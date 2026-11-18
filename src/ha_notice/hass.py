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
  plus ``ca_file``; ``SSL_CERT_FILE`` and ``SSL_CERT_DIR`` are never consulted.
- Exceptions from ``http.client``, ``ssl`` and ``socket`` propagate unchanged (the gateway
  already replaced the ones that could echo input); the caller maps them by class only.
"""

from __future__ import annotations

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


def _usable_bundle(gateway: Gateway, path: str) -> bytes | None:
    """The bytes of a regular file that loads at least one CA certificate, else ``None``."""
    if not path:
        return None
    try:
        data = gateway.read_config(path, MAX_DEFAULT_BUNDLE_BYTES)
    except SourceError:
        return None
    if not data:
        return None
    try:
        context = gateway.new_tls_context([], (), [data])
    except Exception:  # GatewayError: the file does not parse; the reason is not needed
        return None
    return data if context.cert_store_stats().get("x509_ca", 0) > 0 else None


def select_trust(gateway: Gateway, ca_file: str | None) -> SSLContext:
    """The TLS context for an https send.

    Default trust: the compiled ``openssl_cafile`` when it is a usable bundle and the compiled
    ``openssl_capath`` when it is a non-empty directory; when neither is usable, the first usable
    fallback file. ``ca_file`` is added to a non-empty default and is the whole trust otherwise.
    Raises ``TrustError``.
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
            own = gateway.read_config(ca_file, MAX_CA_FILE_BYTES)  # the one read of the file
        except SourceError:
            own = None
        if own is None:
            raise TrustError("ca_file")
        pems.append(own)
    if not pems and not dirs:
        raise TrustError("no_trust")
    try:
        return gateway.new_tls_context([], dirs, pems)
    except Exception:  # GatewayError, fixed message; the file is the only thing that can fail
        raise TrustError("ca_file" if ca_file is not None else "no_trust") from None


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
    spec = ConnectSpec(
        target.base.scheme,  # pyright: ignore[reportArgumentType]
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
    Nothing is retried and nothing is classified here (TODO(#23), TODO(#24)).
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
