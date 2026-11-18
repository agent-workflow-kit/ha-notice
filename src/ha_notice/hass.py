"""The Home Assistant client: trust selection, the request and one attempt (issue #22).

One attempt is: connect (name resolution, TCP, TLS), build the request, write it, read the
answer up to a cap. This module owns the wire shape (URL path, headers, body bytes) and the TLS
trust; it does not classify an answer (TODO(#23)), retry (TODO(#24)) or enforce the whole-send
deadline and the writing gate (TODO(#25)). The gate sits between ``open_connection`` and the
request through the ``before_write`` hook of ``exchange``.

Rules kept here (docs/interface.md, Home Assistant edge):

- Everything outside goes through the gateway: this module imports no ``http``, ``ssl`` or
  ``socket``. No proxy, no redirect handling and no header of the answer is read.
- The token is validated whole before anything else happens (``Target``), is used only in the
  ``Authorization`` header and never appears in a repr, a message or an exception raised here.
- Trust is the compiled OpenSSL locations that are usable, else the first usable fallback file,
  plus ``ca_file``; ``SSL_CERT_FILE`` and ``SSL_CERT_DIR`` are never consulted. Of a bundle only
  the PEM certificate blocks are used; any other text, whatever its encoding, is ignored.
- Exceptions from ``http.client``, ``ssl`` and ``socket`` propagate unchanged (the gateway
  already replaced the ones that could echo input); the caller maps them by class only.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal

from ha_notice import __version__
from ha_notice.config import (
    MAX_CA_FILE_BYTES,
    TOKEN_MAX_CHARS,
    TOKEN_RE,
    BaseUrl,
    Config,
    CredentialError,
)
from ha_notice.gateway import Connection, ConnectSpec, Gateway, SourceError, SSLContext

__all__ = [
    "BODY_CAP",
    "READ_CHUNK",
    "RawResponse",
    "Target",
    "TrustError",
    "exchange",
    "make_target",
    "open_connection",
    "probe_once",
    "request_headers",
    "select_trust",
    "send_once",
]

BODY_CAP = 64 * 1024  # a longer answer is a bad body (interface, Home Assistant edge)
READ_CHUNK = 1024
MAX_DEFAULT_BUNDLE_BYTES = 16 * 1024 * 1024
# A PEM certificate block as the library's ``cadata`` loader reads it (``CERTIFICATE`` and
# ``X509 CERTIFICATE``; a ``TRUSTED CERTIFICATE`` block is not loadable that way and is skipped).
_CERT_BLOCK = re.compile(
    rb"-----BEGIN (CERTIFICATE|X509 CERTIFICATE)-----[A-Za-z0-9+/=\r\n \t]*?-----END \1-----"
)
USER_AGENT = f"ha-notice/{__version__}"
NOTIFY_CONTENT_TYPE = "application/json"


class TrustError(Exception):
    """No TLS trust could be built. ``reason`` is ``no_trust`` (no usable CA certificates were
    found) or ``ca_file`` (the configured file cannot be used). Both are a ``network_error`` with
    ``details.tls`` true, decided by #23. The message is fixed; it never holds a path."""

    def __init__(self, reason: Literal["no_trust", "ca_file"]) -> None:
        super().__init__(
            "no usable CA certificates were found"
            if reason == "no_trust"
            else "ca_file cannot be used as trust"
        )
        self.reason: Literal["no_trust", "ca_file"] = reason


@dataclass(frozen=True)
class RawResponse:
    """What came back, unclassified. ``body`` is at most ``BODY_CAP`` bytes; ``too_large`` is true
    when the answer had more (the rest was not read). Headers are never exposed."""

    status: int
    body: bytes
    too_large: bool


@dataclass(frozen=True)
class Target:
    """Where to send and with what credential. The token is validated on construction and is
    left out of the repr."""

    base: BaseUrl
    token: str = field(repr=False)
    token_env: str
    tls: SSLContext | None
    connect_timeout: float
    io_timeout: float

    def __post_init__(self) -> None:
        token = self.token
        if not (1 <= len(token) <= TOKEN_MAX_CHARS and TOKEN_RE.fullmatch(token)):
            raise CredentialError(self.token_env)
        if self.base.scheme == "https" and self.tls is None:
            raise ValueError("https needs a TLS context")
        if self.base.scheme == "http" and self.tls is not None:
            raise ValueError("http takes no TLS context")


def _certificate_blocks(data: bytes) -> bytes | None:
    """Only the PEM certificate blocks of ``data``, as ASCII, else ``None``. Text between and
    around the blocks (comments in any encoding, a BOM, stray bytes) is dropped, as OpenSSL does
    when it loads a bundle file."""
    blocks = [m.group(0) for m in _CERT_BLOCK.finditer(data)]
    return b"\n".join(blocks) + b"\n" if blocks else None


def _usable_bundle(gateway: Gateway, path: str) -> bytes | None:
    """The certificate blocks of a regular file that loads at least one CA certificate, else
    ``None``."""
    if not path:
        return None
    try:
        data = gateway.read_config(path, MAX_DEFAULT_BUNDLE_BYTES)
    except SourceError:
        return None
    blocks = _certificate_blocks(data) if data else None
    if blocks is None:
        return None
    try:
        context = gateway.new_tls_context([], (), [blocks])
    except Exception:  # GatewayError: the blocks do not parse; the reason is not needed
        return None
    return blocks if context.cert_store_stats().get("x509_ca", 0) > 0 else None


def select_trust(gateway: Gateway, ca_file: str | None) -> SSLContext:
    """The TLS context for an https send.

    Default trust: the compiled ``openssl_cafile`` when it is a usable bundle and the compiled
    ``openssl_capath`` when it is a non-empty directory; when neither is usable, the first usable
    fallback file. ``ca_file`` is added to a non-empty default and is the whole trust otherwise.
    Only the PEM certificate blocks of a file count; other text in it is ignored. Raises
    ``TrustError``: ``ca_file`` when that file has no loadable certificate block, ``no_trust``
    when there is nothing to trust or a default source fails to load.
    """
    candidates = gateway.ca_candidates()
    pems: list[bytes] = []
    dirs: list[str] = []
    bundle = _usable_bundle(gateway, candidates.cafile)
    if bundle is not None:
        pems.append(bundle)
    if candidates.capath and gateway.has_entries(candidates.capath):
        dirs.append(candidates.capath)
    if not pems and not dirs:
        for path in candidates.fallback_files:
            bundle = _usable_bundle(gateway, path)
            if bundle is not None:
                pems.append(bundle)
                break
    if ca_file is not None:
        try:
            raw = gateway.read_config(ca_file, MAX_CA_FILE_BYTES)  # the one read of the file
        except SourceError:
            raw = None
        own = _certificate_blocks(raw) if raw else None
        if own is None:
            raise TrustError("ca_file")
        try:
            gateway.new_tls_context([], (), [own])  # on its own, so only this file is blamed
        except Exception:  # GatewayError, fixed message
            raise TrustError("ca_file") from None
        pems.append(own)
    if not pems and not dirs:
        raise TrustError("no_trust")
    try:
        return gateway.new_tls_context([], dirs, pems)
    except Exception:  # GatewayError, fixed message; ca_file loaded alone above, so a default
        raise TrustError("no_trust") from None  # source is what failed


def make_target(
    gateway: Gateway, config: Config, env: Mapping[str, str], *, io_timeout: float
) -> Target:
    """A ``Target`` from a validated config. The token is read and checked first, so a bad
    credential ends the send before any file is read or socket opened. Raises ``CredentialError``
    or ``TrustError``; ``connect_timeout`` is the configured one (the caller caps it)."""
    config.check_destination()
    base = config.base_url
    if base is None:
        raise ValueError("base_url is not valid")
    if base.scheme == "http" and not config.allow_insecure_http:
        raise ValueError("http needs allow_insecure_http")  # Config.load enforces it too
    token = config.read_token(env)
    tls = select_trust(gateway, config.ca_file) if base.scheme == "https" else None
    return Target(base, token, config.token_env, tls, config.connect_timeout, io_timeout)


def request_headers(target: Target, *, body: bytes | None) -> dict[str, str]:
    """The request headers and no others: ``Content-Type`` and ``Content-Length`` only with a
    body. The values are plain ASCII (the token was validated)."""
    headers = {
        "Host": target.base.authority,
        "Authorization": f"Bearer {target.token}",
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Connection": "close",
        "User-Agent": USER_AGENT,
    }
    if body is not None:
        headers["Content-Type"] = NOTIFY_CONTENT_TYPE
        headers["Content-Length"] = str(len(body))
    return headers


def open_connection(gateway: Gateway, target: Target) -> Connection:
    """Resolve, connect and complete the TLS handshake; no request byte has been written.

    The connection is closed again when connecting fails. TODO(#25): the writing gate is taken
    by the caller after this returns, before ``exchange``.
    """
    scheme: Literal["http", "https"] = "https" if target.base.scheme == "https" else "http"
    spec = ConnectSpec(
        scheme,
        target.base.host,
        target.base.port,
        target.connect_timeout,
        target.io_timeout,
        target.tls,
    )
    conn = gateway.connect(spec)
    try:
        conn.connect()
    except BaseException:
        conn.close()
        raise
    return conn


def _read_capped(conn: Connection) -> RawResponse:
    # TODO(#25): bound the 100-Continue loop with the overall deadline. ``getresponse`` skips
    # interim 1xx answers in a loop that only ``io_timeout`` per read limits, so a peer that
    # sends 1xx lines forever is not stopped here.
    response = conn.getresponse()
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(READ_CHUNK)
        if not chunk:
            return RawResponse(response.status, b"".join(chunks), False)
        total += len(chunk)
        if total > BODY_CAP:
            kept = b"".join(chunks) + chunk
            return RawResponse(response.status, kept[:BODY_CAP], True)
        chunks.append(chunk)


def exchange(
    conn: Connection,
    target: Target,
    method: str,
    path: str,
    body: bytes | None,
    *,
    before_write: Callable[[], None] | None = None,
) -> RawResponse:
    """Write one request on a connected ``conn`` and read the capped answer; always closes.

    ``before_write`` runs after the headers are built and before the first call that can put a
    byte on the socket (TODO(#25): the idle-to-writing gate step; it may raise to refuse).
    Nothing is retried and nothing is classified here (TODO(#23), TODO(#24)). TODO(#25): bound
    the 100-Continue loop with the overall deadline (see ``_read_capped``).
    """
    try:
        headers = request_headers(target, body=body)
        if before_write is not None:
            before_write()
        conn.request(method, path, body, headers)
        return _read_capped(conn)
    finally:
        conn.close()


def send_once(
    gateway: Gateway,
    target: Target,
    service: str,
    body: bytes,
    *,
    before_write: Callable[[], None] | None = None,
) -> RawResponse:
    """One ``POST <prefix>/api/services/notify/<service>`` attempt. ``body`` is the bytes from
    ``render.serialize`` (sent as is). ``service`` must match the validated grammar."""
    path = target.base.request_path(service)
    conn = open_connection(gateway, target)
    return exchange(conn, target, "POST", path, body, before_write=before_write)


def probe_once(
    gateway: Gateway, target: Target, *, before_write: Callable[[], None] | None = None
) -> RawResponse:
    """One ``GET <prefix>/api/`` attempt for ``validate --probe``: no body, no ``Content-Type``."""
    conn = open_connection(gateway, target)
    return exchange(conn, target, "GET", target.base.probe_path, None, before_write=before_write)
