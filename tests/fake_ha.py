"""A fake Home Assistant server for tests (issue #4).

``FakeHA`` is a wire-level HTTP or HTTPS server on 127.0.0.1 (ephemeral port, daemon threads)
that answers the rows of the interface's Home Assistant edge table and misbehaves on demand:
it can delay, trickle a response byte by byte, drop the connection after the request (FIN or
RST), cut a response short, answer with bytes that are not HTTP, redirect, or answer 200 with a
wrong body. It records every request (method, path, headers, body) so a test can assert where
the token went.

Use it with the real gateway as the client::

    with FakeHA(token="HA_FAKE") as ha:
        conn = RealGateway().connect(ConnectSpec("http", "127.0.0.1", ha.port, 3, 3))

A reply is a ``Reply``. ``ha.script`` is a queue consumed one reply per request; when it is
empty the default routes answer like Home Assistant (``GET /api/`` and the notify service).
``EDGE_ROWS`` names one ready-made reply per row of the edge table.

Name resolution cannot be stalled by a server, so ``StallingResolverGateway`` is a real gateway
whose ``resolve`` blocks until the test releases it and then answers with loopback.

The self-signed certificate is made by the ``openssl`` binary through a test-only subprocess
(``make_self_signed_cert``); the tool itself never runs a subprocess, and no dependency is added.
"""

from __future__ import annotations

import http
import json
import re
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import cast

from ha_notice.gateway import AddrInfo, RealGateway

WAIT_CAP_SECONDS = 30.0  # no wait in this module is longer, so a broken test fails, not hangs
MAX_HEAD_BYTES = 65536
MAX_BODY_BYTES = 1 << 20
IO_TIMEOUT_SECONDS = 10.0

API_RUNNING = b'{"message": "API running."}'
NOTIFY_PATH = re.compile(r"/api/services/notify/[a-z0-9_]{1,64}")


def _check_wire_text(what: str, value: str) -> None:
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        raise ValueError(f"{what} is not latin-1") from None
    if "\r" in value or "\n" in value:
        raise ValueError(f"{what} contains CR or LF")


@dataclass(frozen=True)
class Reply:
    """What the server does for one request. The default is a 200 with the body ``[]``.

    ``raw`` replaces the whole response (not HTTP on purpose). ``drop`` sends nothing and closes
    after the request is read. ``reset`` closes with a TCP RST instead of a FIN, whatever else
    the reply does (after ``drop``, after ``truncate_after``, during ``trickle``).
    ``truncate_after`` sends only that many bytes of the response, then closes, or keeps the
    connection open with ``hang``. ``trickle`` is the pause in seconds between single bytes.
    ``declared_length`` overrides the Content-Length header. ``chunked`` frames the body with
    ``Transfer-Encoding: chunked`` and no Content-Length. ``stall_before_read`` accepts the
    connection and then neither reads the request nor answers, until the server closes. The
    stall entry is claimed by the next connection, not the next request.

    Header names, values and the content type must be latin-1 without CR or LF (a ``ValueError``
    otherwise), so a scripted reply cannot break the wire format by accident.
    """

    status: int = 200
    body: bytes = b"[]"
    headers: tuple[tuple[str, str], ...] = ()
    content_type: str | None = "application/json; charset=utf-8"
    delay: float = 0.0
    trickle: float = 0.0
    raw: bytes | None = None
    drop: bool = False
    reset: bool = False
    truncate_after: int | None = None
    hang: bool = False
    declared_length: int | None = None
    chunked: bool = False
    stall_before_read: bool = False

    def __post_init__(self) -> None:
        for name, value in self.headers:
            _check_wire_text("header name", name)
            _check_wire_text("header value", value)
        if self.content_type is not None:
            _check_wire_text("content type", self.content_type)
        if self.chunked and self.declared_length is not None:
            raise ValueError("chunked and declared_length are exclusive")

    def serialize(self) -> bytes:
        if self.raw is not None:
            return self.raw
        reason = http.HTTPStatus(self.status).phrase if self.status in http.HTTPStatus else "Status"
        head = [f"HTTP/1.1 {self.status} {reason}", "Server: Python/3.13 aiohttp/3.11"]
        if self.content_type is not None:
            head.append(f"Content-Type: {self.content_type}")
        if self.chunked:
            head.append("Transfer-Encoding: chunked")
        else:
            length = len(self.body) if self.declared_length is None else self.declared_length
            head.append(f"Content-Length: {length}")
        head.append("Connection: close")
        head.extend(f"{k}: {v}" for k, v in self.headers)
        wire = ("\r\n".join(head) + "\r\n\r\n").encode("latin-1")
        if self.chunked:
            if self.body:
                wire += f"{len(self.body):x}\r\n".encode("ascii") + self.body + b"\r\n"
            return wire + b"0\r\n\r\n"
        return wire + self.body


def _text(status: int, body: str) -> Reply:
    return Reply(status, body.encode(), content_type="text/plain; charset=utf-8")


# One reply per row of the interface's Home Assistant edge table (and the cases inside a row).
EDGE_ROWS: dict[str, Reply] = {
    "200_list": Reply(200, b"[]"),
    "200_list_with_content": Reply(200, b'[{"entity_id": "x"}]', content_type="text/html"),
    "200_object": Reply(200, b"{}"),  # not a list: a wrong body for a send
    "200_not_json": Reply(200, b"<html>login</html>", content_type="text/html"),
    "200_empty": Reply(200, b""),
    "201": Reply(201, b"[]"),
    "204": Reply(204, b"", content_type=None),
    "301": Reply(301, b"", headers=(("Location", "http://127.0.0.1:1/"),), content_type=None),
    "302": Reply(302, b"", headers=(("Location", "http://127.0.0.1:1/"),), content_type=None),
    "307": Reply(307, b"", headers=(("Location", "http://127.0.0.1:1/"),), content_type=None),
    "400": _text(400, "400: Bad Request"),
    "401": _text(401, "401: Unauthorized"),
    "403": _text(403, "403: Forbidden"),
    "404": _text(404, "404: Not Found"),
    "405": _text(405, "405: Method Not Allowed"),
    "429": _text(429, "429: Too Many Requests"),
    "500": _text(500, "500 Internal Server Error"),
    "502": _text(502, "502: Bad Gateway"),
    "503": _text(503, "503: Service Unavailable"),
    "504": _text(504, "504: Gateway Timeout"),
    "418": _text(418, "418: I'm a teapot"),  # any other status
}


def redirect(location: str, status: int = 302) -> Reply:
    return Reply(status, b"", headers=(("Location", location),), content_type=None)


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    tls: bool

    def header_values(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def header(self, name: str) -> str | None:
        values = self.header_values(name)
        return values[0] if values else None


class _BadRequest(Exception):
    pass


def _read_request(conn: socket.socket, tls: bool, buf: bytearray) -> RecordedRequest:
    """Read one request; every byte received is appended to ``buf`` (kept for bad requests too)."""
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEAD_BYTES:
            raise _BadRequest("head too large")
        chunk = conn.recv(4096)
        if not chunk:
            raise _BadRequest("closed before the head ended")
        buf += chunk
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise _BadRequest("bad request line")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            raise _BadRequest("bad header line")
        headers.append((name.strip(), value.strip()))
    if any(name.lower() == "transfer-encoding" for name, _ in headers):
        raise _BadRequest("transfer-encoding is not supported")
    lengths = [value for name, value in headers if name.lower() == "content-length"]
    if len(lengths) > 1:
        raise _BadRequest("duplicate content-length")
    length = 0
    if lengths:
        value = lengths[0]
        if not value.isascii() or not value.isdigit() or int(value) > MAX_BODY_BYTES:
            raise _BadRequest("bad content-length")
        length = int(value)
    while len(rest) < length:
        chunk = conn.recv(4096)
        if not chunk:
            raise _BadRequest("closed before the body ended")
        buf += chunk
        rest += chunk
    if len(rest) > length:
        raise _BadRequest("bytes after the body")
    return RecordedRequest(parts[0], parts[1], tuple(headers), rest, tls)


NOTIFY_FIELDS = frozenset({"title", "message", "data"})
NOTIFY_DATA_FIELDS = frozenset({"url", "clickAction", "tag", "group"})


def _valid_notify_body(body: bytes) -> bool:
    """The body shapes the interface's 400 row names: an object with a non-empty string message."""
    try:
        value = json.loads(body)
    except (ValueError, RecursionError):
        return False
    if not isinstance(value, dict):
        return False
    fields = cast("dict[str, object]", value)
    if not set(fields) <= NOTIFY_FIELDS:
        return False
    message = fields.get("message")
    if not isinstance(message, str) or not message:
        return False
    if "title" in fields and not isinstance(fields["title"], str):
        return False
    if "data" in fields:
        data = fields["data"]
        if not isinstance(data, dict):
            return False
        items = cast("dict[str, object]", data)
        if not set(items) <= NOTIFY_DATA_FIELDS or not all(
            isinstance(v, str) for v in items.values()
        ):
            return False
    return True


class _Server:
    """The sockets, threads and state of a ``FakeHA``.

    It holds no reference to the ``FakeHA`` that owns it, so garbage collection of the facade
    can run ``close`` through a ``weakref.finalize``.
    """

    def __init__(
        self,
        *,
        token: str | None,
        certfile: Path | None,
        keyfile: Path | None,
        prefix: str,
        services: set[str] | None,
        script: list[Reply],
        requests: list[RecordedRequest],
        received: list[bytes],
        handshake_failures: list[str],
        bad_requests: list[str],
        handler_errors: list[str],
    ) -> None:
        self.token = token
        self.base = "/" + prefix.strip("/") if prefix.strip("/") else ""
        self.services = services
        self.script = script
        self.requests = requests
        self.received = received
        self.handshake_failures = handshake_failures
        self.bad_requests = bad_requests
        self.handler_errors = handler_errors
        self.connections = 0
        self.cond = threading.Condition()
        self.stop = threading.Event()
        self.open: set[socket.socket] = set()
        self.threads: list[threading.Thread] = []
        self.ctx: ssl.SSLContext | None = None
        if certfile is not None:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(str(certfile), str(keyfile))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.sock.settimeout(1.0)  # only a safety net: close() wakes the acceptor at once
        self.port: int = self.sock.getsockname()[1]
        self.closed = False
        self.acceptor = threading.Thread(target=self._accept_loop, name="fake-ha-accept")
        self.acceptor.daemon = True
        self.acceptor.start()

    def close(self) -> None:
        with self.cond:
            if self.closed:
                return
            self.closed = True
        self.stop.set()
        try:  # wake the blocked accept with a connection of our own (it is not counted)
            socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
        except OSError:
            pass
        self.acceptor.join(WAIT_CAP_SECONDS)
        with self.cond:
            open_conns = list(self.open)
            threads = list(self.threads)
        for conn in open_conns:  # wake handlers that wait on a client
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for thread in threads:
            thread.join(WAIT_CAP_SECONDS)
        self.sock.close()

    def wait_for_requests(self, count: int, timeout: float) -> list[RecordedRequest]:
        timeout = min(timeout, WAIT_CAP_SECONDS)
        with self.cond:
            if not self.cond.wait_for(lambda: len(self.requests) >= count, timeout):
                raise AssertionError(f"expected {count} requests, saw {len(self.requests)}")
            return list(self.requests)

    # --- server ---------------------------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if self.stop.is_set():
                conn.close()
                return
            with self.cond:
                index = self.connections
                self.connections += 1
                self.received.append(b"")
                thread = threading.Thread(
                    target=self._handle, args=(index, conn), name="fake-ha-conn"
                )
                thread.daemon = True
                self.threads.append(thread)
                self.open.add(conn)
            thread.start()

    def _handle(self, index: int, raw: socket.socket) -> None:
        conn = raw
        buf = bytearray()
        try:
            conn.settimeout(IO_TIMEOUT_SECONDS)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.ctx is not None:
                try:
                    # wrap_socket detaches ``raw``; the wrapped socket is the one close() must
                    # shut down, so track it before the handshake can block.
                    conn = self.ctx.wrap_socket(
                        raw, server_side=True, do_handshake_on_connect=False
                    )
                    with self.cond:
                        self.open.discard(raw)
                        self.open.add(conn)
                    if self.stop.is_set():
                        return
                    conn.do_handshake()
                except (ssl.SSLError, OSError) as exc:
                    self._note(self.handshake_failures, type(exc).__name__)
                    return
            with self.cond:
                stalled = bool(self.script) and self.script[0].stall_before_read
                if stalled:
                    self.script.pop(0)
            if stalled:
                self.stop.wait(WAIT_CAP_SECONDS)
                return
            try:
                request = _read_request(conn, self.ctx is not None, buf)
            except (_BadRequest, OSError, UnicodeDecodeError) as exc:
                self._note(self.bad_requests, type(exc).__name__)
                return
            with self.cond:
                self.requests.append(request)
                self.cond.notify_all()
                reply = self.script.pop(0) if self.script else self._route(request)
            self._perform(conn, reply)
        except OSError:
            pass  # the client went away; nothing to report
        except Exception as exc:  # a bug in a scripted reply must not escape the thread
            self._note(self.handler_errors, f"{type(exc).__name__}: {exc}")
        finally:
            with self.cond:
                self.received[index] = bytes(buf)
                self.open.discard(raw)
                self.open.discard(conn)
            try:
                conn.close()
            except OSError:
                pass
            raw.close()

    def _note(self, sink: list[str], name: str) -> None:
        with self.cond:
            sink.append(name)

    def _route(self, request: RecordedRequest) -> Reply:
        """Default answers, like Home Assistant: route first, then auth on known routes only.

        Called with the lock held. 403, 429 and 5xx are never produced here (script them).
        """
        target = request.path.split("?", 1)[0]
        if not target.startswith(self.base + "/"):
            return EDGE_ROWS["404"]
        path = target[len(self.base) :]
        notify = NOTIFY_PATH.fullmatch(path)
        if path != "/api/" and not notify:
            return EDGE_ROWS["404"]
        if self.token is not None and request.header("Authorization") != f"Bearer {self.token}":
            return EDGE_ROWS["401"]
        if path == "/api/":
            return Reply(200, API_RUNNING) if request.method == "GET" else EDGE_ROWS["405"]
        if request.method != "POST":
            return EDGE_ROWS["405"]
        service = path.rsplit("/", 1)[1]
        if self.services is not None and service not in self.services:
            return EDGE_ROWS["400"]
        if not _valid_notify_body(request.body):
            return EDGE_ROWS["400"]
        return Reply(200, b"[]")

    def _perform(self, conn: socket.socket, reply: Reply) -> None:
        if reply.reset:
            # Closing with a zero linger time sends RST instead of FIN.
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        if reply.delay and self.stop.wait(min(reply.delay, WAIT_CAP_SECONDS)):
            return
        if reply.drop:
            return
        data = reply.serialize()
        if reply.truncate_after is not None:
            data = data[: reply.truncate_after]
        if reply.trickle:
            for i in range(len(data)):
                conn.sendall(data[i : i + 1])
                if self.stop.wait(min(reply.trickle, WAIT_CAP_SECONDS)):
                    return
        else:
            conn.sendall(data)
        if reply.hang:
            self.stop.wait(WAIT_CAP_SECONDS)


@dataclass
class FakeHA:
    """A fake Home Assistant on 127.0.0.1.

    ``certfile`` and ``keyfile`` make it an HTTPS server. ``token`` makes the default routes
    answer 401 unless ``Authorization: Bearer <token>`` is sent (a scripted reply is not
    checked). ``prefix`` serves the default routes under ``/<prefix>/api/...`` (the unprefixed
    paths are then 404). ``services`` is the set of known notify service names (``None``: any);
    an unknown one answers 400. The default notify route answers 400 for a body that is not a
    JSON object, has no non-empty string ``message``, or has a field other than ``title``,
    ``message`` and ``data`` (``data`` keys: ``url``, ``clickAction``, ``tag``, ``group``).
    403, 429 and 5xx are only ever produced by a script. Always use it as a context manager (or
    call ``close``); ``close`` stops only the threads and sockets this object started, and a
    garbage-collected object stops them too.

    ``received[i]`` is the raw bytes read on connection ``i`` (in accept order; ``b""`` for a
    connection that sent nothing), kept even for requests that were rejected. A request with a
    ``Transfer-Encoding`` header, a duplicate ``Content-Length`` or bytes beyond its body is
    rejected (``bad_requests``) rather than normalised.
    """

    token: str | None = None
    certfile: Path | None = None
    keyfile: Path | None = None
    prefix: str = ""
    services: set[str] | None = None
    script: list[Reply] = field(default_factory=lambda: [])
    requests: list[RecordedRequest] = field(default_factory=lambda: [])
    received: list[bytes] = field(default_factory=lambda: [])
    # Class names of failed TLS handshakes and unparsable requests (no request was recorded),
    # and of unexpected errors in a connection handler.
    handshake_failures: list[str] = field(default_factory=lambda: [])
    bad_requests: list[str] = field(default_factory=lambda: [])
    handler_errors: list[str] = field(default_factory=lambda: [])

    # Fields the running server reads; assigning one after construction updates the server.
    _LIVE = frozenset({"token", "prefix", "services", "script", "requests", "received"})

    def __setattr__(self, name: str, value: object) -> None:
        object.__setattr__(self, name, value)
        server = self.__dict__.get("_server")
        if server is not None and name in self._LIVE:
            setattr(server, name, value)

    def __post_init__(self) -> None:
        self._server = _Server(
            token=self.token,
            certfile=self.certfile,
            keyfile=self.keyfile,
            prefix=self.prefix,
            services=self.services,
            script=self.script,
            requests=self.requests,
            received=self.received,
            handshake_failures=self.handshake_failures,
            bad_requests=self.bad_requests,
            handler_errors=self.handler_errors,
        )
        self.port: int = self._server.port
        weakref.finalize(self, self._server.close)  # the server holds no reference to self

    @property
    def connections(self) -> int:
        return self._server.connections

    @property
    def scheme(self) -> str:
        return "https" if self._server.ctx is not None else "http"

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}"

    def __enter__(self) -> FakeHA:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def wait_for_requests(self, count: int, timeout: float = 10.0) -> list[RecordedRequest]:
        """Block until ``count`` requests are recorded (fails the test after ``timeout``)."""
        return self._server.wait_for_requests(count, timeout)

    def close(self) -> None:
        self._server.close()


class StallingResolverGateway(RealGateway):
    """A real gateway whose name resolution blocks until ``release`` is set.

    After the release it answers with loopback and ``port``, whatever name was asked for, so
    a test never touches DNS. ``resolving`` is set once a caller is inside ``resolve``.
    """

    def __init__(self, release: threading.Event | None = None) -> None:
        self.release = release or threading.Event()
        self.resolving = threading.Event()
        self.calls: list[tuple[str, int]] = []

    def resolve(self, host: str, port: int) -> list[AddrInfo]:
        self.calls.append((host, port))
        self.resolving.set()
        self.release.wait(WAIT_CAP_SECONDS)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]


# --- self-signed certificate ----------------------------------------------------------------

OPENSSL_CONFIG = """[req]
distinguished_name = dn
prompt = no
x509_extensions = ext
[dn]
CN = fake-ha
[ext]
basicConstraints = critical,CA:TRUE
subjectKeyIdentifier = hash
"""

# Only used for an expired certificate: ``openssl ca -selfsign`` can back-date it, ``req`` cannot.
OPENSSL_CA_CONFIG = """[ca]
default_ca = selfsign
[selfsign]
database = index.txt
new_certs_dir = .
serial = serial
default_md = sha256
policy = any
unique_subject = no
x509_extensions = ext
[any]
commonName = supplied
"""

# Not set anywhere: ``build_tls_context`` does not turn on ``VERIFY_X509_STRICT``, so a leaf
# without ``CA:TRUE`` (the usual shape of a Home Assistant certificate) verifies as a trust anchor.


def make_self_signed_cert(
    directory: Path,
    *,
    sans: tuple[str, ...] = ("IP:127.0.0.1", "DNS:localhost"),
    name: str = "ha",
    rsa: bool = False,
    is_ca: bool = True,
    expired: bool = False,
) -> tuple[Path, Path]:
    """Write a throwaway self-signed certificate and key; return ``(cert, key)``.

    Test-only: it runs the ``openssl`` binary with a private HOME, no inherited configuration and
    a two-day lifetime. ``sans`` are subjectAltName entries such as ``IP:127.0.0.1``; an empty
    tuple leaves the extension out. ``rsa`` makes an RSA key instead of an EC one, ``is_ca``
    false marks the certificate ``CA:FALSE`` and ``expired`` back-dates it to the year 2020.
    """
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("the openssl binary is required to make the test certificate")
    directory.mkdir(parents=True, exist_ok=True)
    config = directory / f"{name}.cnf"
    cert = directory / f"{name}.crt"
    key = directory / f"{name}.key"
    text = OPENSSL_CONFIG if is_ca else OPENSSL_CONFIG.replace("CA:TRUE", "CA:FALSE")
    if sans:
        text += "subjectAltName = " + ",".join(sans) + "\n"
    if expired:
        text += OPENSSL_CA_CONFIG
    config.write_text(text)
    home = directory / f"{name}-home"
    home.mkdir(exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "XDG_CONFIG_HOME": str(home)}
    keyspec = ["rsa", "-pkeyopt", "rsa_keygen_bits:2048"] if rsa else [
        "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"
    ]  # fmt: skip
    if not expired:
        argv = [
            openssl, "req", "-x509", "-newkey", *keyspec, "-nodes", "-days", "2",
            "-config", str(config), "-keyout", str(key), "-out", str(cert),
        ]  # fmt: skip
        _run(argv, env, directory)
        return cert, key
    work = directory / f"{name}-ca"
    work.mkdir(exist_ok=True)
    (work / "index.txt").write_text("")
    (work / "serial").write_text("01\n")
    request = work / "req.csr"
    _run(
        [
            openssl, "req", "-new", "-newkey", *keyspec, "-nodes", "-config", str(config),
            "-keyout", str(key), "-out", str(request),
        ],
        env,
        directory,
    )  # fmt: skip
    _run(
        [
            openssl, "ca", "-batch", "-selfsign", "-config", str(config), "-keyfile", str(key),
            "-in", str(request), "-out", str(cert), "-notext",
            "-startdate", "20200101000000Z", "-enddate", "20200102000000Z",
        ],
        env,
        work,
    )  # fmt: skip
    return cert, key


def _run(argv: list[str], env: dict[str, str], cwd: Path) -> None:
    done = subprocess.run(
        argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, timeout=60,
        check=False,
    )  # fmt: skip
    if done.returncode != 0:
        raise RuntimeError(f"openssl failed: {done.stderr.decode(errors='replace')}")


def json_body(request: RecordedRequest) -> object:
    return json.loads(request.body)
