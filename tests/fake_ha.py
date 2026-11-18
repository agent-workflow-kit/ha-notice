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
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

from ha_notice.gateway import AddrInfo, RealGateway

WAIT_CAP_SECONDS = 30.0  # no wait in this module is longer, so a broken test fails, not hangs
MAX_HEAD_BYTES = 65536
MAX_BODY_BYTES = 1 << 20
IO_TIMEOUT_SECONDS = 10.0

API_RUNNING = b'{"message": "API running."}'
NOTIFY_PATH = re.compile(r"/api/services/notify/[a-z0-9_]{1,64}")


@dataclass(frozen=True)
class Reply:
    """What the server does for one request. The default is a 200 with the body ``[]``.

    ``raw`` replaces the whole response (not HTTP on purpose). ``drop`` sends nothing and closes
    after the request is read (``reset``: closes with a TCP RST). ``truncate_after`` sends only
    that many bytes of the response, then closes, or keeps the connection open with ``hang``.
    ``trickle`` is the pause in seconds between single bytes. ``declared_length`` overrides the
    Content-Length header.
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

    def serialize(self) -> bytes:
        if self.raw is not None:
            return self.raw
        reason = http.HTTPStatus(self.status).phrase if self.status in http.HTTPStatus else "Status"
        head = [f"HTTP/1.1 {self.status} {reason}", "Server: Python/3.13 aiohttp/3.11"]
        if self.content_type is not None:
            head.append(f"Content-Type: {self.content_type}")
        length = len(self.body) if self.declared_length is None else self.declared_length
        head.append(f"Content-Length: {length}")
        head.append("Connection: close")
        head.extend(f"{k}: {v}" for k, v in self.headers)
        return ("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + self.body


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


def _read_request(conn: socket.socket, tls: bool) -> RecordedRequest:
    data = b""
    while b"\r\n\r\n" not in data:
        if len(data) > MAX_HEAD_BYTES:
            raise _BadRequest("head too large")
        chunk = conn.recv(4096)
        if not chunk:
            raise _BadRequest("closed before the head ended")
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
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
    length = 0
    for name, value in headers:
        if name.lower() == "content-length":
            if not value.isascii() or not value.isdigit() or int(value) > MAX_BODY_BYTES:
                raise _BadRequest("bad content-length")
            length = int(value)
    while len(rest) < length:
        chunk = conn.recv(4096)
        if not chunk:
            raise _BadRequest("closed before the body ended")
        rest += chunk
    return RecordedRequest(parts[0], parts[1], tuple(headers), rest[:length], tls)


@dataclass
class FakeHA:
    """A fake Home Assistant on 127.0.0.1.

    ``certfile`` and ``keyfile`` make it an HTTPS server. ``token`` makes the default routes
    answer 401 unless ``Authorization: Bearer <token>`` is sent (a scripted reply is not
    checked). Always use it as a context manager (or call ``close``); ``close`` stops only the
    threads and sockets this object started.
    """

    token: str | None = None
    certfile: Path | None = None
    keyfile: Path | None = None
    script: list[Reply] = field(default_factory=lambda: [])
    requests: list[RecordedRequest] = field(default_factory=lambda: [])
    # Class names of failed TLS handshakes and unparsable requests (no request was recorded).
    handshake_failures: list[str] = field(default_factory=lambda: [])
    bad_requests: list[str] = field(default_factory=lambda: [])
    connections: int = 0

    def __post_init__(self) -> None:
        self._cond = threading.Condition()
        self._stop = threading.Event()
        self._open: set[socket.socket] = set()
        self._threads: list[threading.Thread] = []
        self._ctx: ssl.SSLContext | None = None
        if self.certfile is not None:
            self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ctx.load_cert_chain(str(self.certfile), str(self.keyfile))
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(64)
        self._sock.settimeout(0.1)
        self.port: int = self._sock.getsockname()[1]
        self._acceptor = threading.Thread(target=self._accept_loop, name="fake-ha-accept")
        self._acceptor.daemon = True
        self._acceptor.start()

    # --- public ---------------------------------------------------------------------------

    @property
    def scheme(self) -> str:
        return "https" if self._ctx is not None else "http"

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
        timeout = min(timeout, WAIT_CAP_SECONDS)
        with self._cond:
            if not self._cond.wait_for(lambda: len(self.requests) >= count, timeout):
                raise AssertionError(f"expected {count} requests, saw {len(self.requests)}")
            return list(self.requests)

    def close(self) -> None:
        self._stop.set()
        self._acceptor.join(WAIT_CAP_SECONDS)
        with self._cond:
            open_conns = list(self._open)
            threads = list(self._threads)
        for conn in open_conns:  # wake handlers that wait on a client
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for thread in threads:
            thread.join(WAIT_CAP_SECONDS)
        self._sock.close()

    # --- server ---------------------------------------------------------------------------

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self._handle, args=(conn,), name="fake-ha-conn")
            thread.daemon = True
            with self._cond:
                self.connections += 1
                self._threads.append(thread)
                self._open.add(conn)
            thread.start()

    def _handle(self, conn: socket.socket) -> None:
        raw = conn
        try:
            conn.settimeout(IO_TIMEOUT_SECONDS)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self._ctx is not None:
                try:
                    conn = self._ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError) as exc:
                    self._note(self.handshake_failures, type(exc).__name__)
                    return
            try:
                request = _read_request(conn, self._ctx is not None)
            except (_BadRequest, OSError, UnicodeDecodeError) as exc:
                self._note(self.bad_requests, type(exc).__name__)
                return
            with self._cond:
                self.requests.append(request)
                self._cond.notify_all()
                reply = self.script.pop(0) if self.script else self._route(request)
            self._perform(conn, reply)
        except OSError:
            pass  # the client went away; nothing to report
        finally:
            try:
                conn.close()
            except OSError:
                pass
            raw.close()
            with self._cond:
                self._open.discard(raw)

    def _note(self, sink: list[str], name: str) -> None:
        with self._cond:
            sink.append(name)

    def _route(self, request: RecordedRequest) -> Reply:
        """Default answers, like Home Assistant. Called with the lock held."""
        path = request.path
        if self.token is not None and request.header("Authorization") != f"Bearer {self.token}":
            return EDGE_ROWS["401"]
        if path == "/api/":
            return Reply(200, API_RUNNING) if request.method == "GET" else EDGE_ROWS["405"]
        if NOTIFY_PATH.fullmatch(path):
            return Reply(200, b"[]") if request.method == "POST" else EDGE_ROWS["405"]
        return EDGE_ROWS["404"]

    def _perform(self, conn: socket.socket, reply: Reply) -> None:
        if reply.delay and self._stop.wait(min(reply.delay, WAIT_CAP_SECONDS)):
            return
        if reply.drop:
            if reply.reset:
                # Closing with a zero linger time sends RST instead of FIN.
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return
        data = reply.serialize()
        if reply.truncate_after is not None:
            data = data[: reply.truncate_after]
        if reply.trickle:
            for i in range(len(data)):
                conn.sendall(data[i : i + 1])
                if self._stop.wait(min(reply.trickle, WAIT_CAP_SECONDS)):
                    return
        else:
            conn.sendall(data)
        if reply.hang:
            self._stop.wait(WAIT_CAP_SECONDS)


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


def make_self_signed_cert(
    directory: Path, *, sans: tuple[str, ...] = ("IP:127.0.0.1", "DNS:localhost"), name: str = "ha"
) -> tuple[Path, Path]:
    """Write a throwaway self-signed certificate and key; return ``(cert, key)``.

    Test-only: it runs the ``openssl`` binary with a private HOME, no inherited configuration and
    a two-day lifetime. ``sans`` are subjectAltName entries such as ``IP:127.0.0.1``.
    """
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError("the openssl binary is required to make the test certificate")
    directory.mkdir(parents=True, exist_ok=True)
    config = directory / f"{name}.cnf"
    cert = directory / f"{name}.crt"
    key = directory / f"{name}.key"
    config.write_text(OPENSSL_CONFIG)
    home = directory / f"{name}-home"
    home.mkdir(exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "XDG_CONFIG_HOME": str(home)}
    argv = [
        openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-days", "2", "-config", str(config), "-keyout", str(key), "-out", str(cert),
        "-addext", "subjectAltName=" + ",".join(sans),
    ]  # fmt: skip
    done = subprocess.run(
        argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60, check=False
    )
    if done.returncode != 0:
        raise RuntimeError(f"openssl failed: {done.stderr.decode(errors='replace')}")
    return cert, key


def json_body(request: RecordedRequest) -> object:
    return json.loads(request.body)
