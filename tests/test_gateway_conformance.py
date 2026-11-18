"""The fake gateway is faithful to the real one (issue #3).

Part 1 compares signatures. Part 2 runs the same connection scenarios against the real gateway
(on a loopback server this test starts and stops itself) and the fake, and requires the same
outcome, including the same exception classes.
"""

from __future__ import annotations

import contextlib
import http.client
import inspect
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from ha_notice import gateway as gw
from ha_notice.gateway import ConnectSpec, Gateway, RealGateway
from tests.fake_gateway import ConnectionScript, FakeGateway
from tests.timing import LOAD_SLACK_S

# --- signatures -----------------------------------------------------------------------------


def _public_methods(cls: type) -> dict[str, Any]:
    return {n: m for n, m in inspect.getmembers(cls, inspect.isfunction) if not n.startswith("_")}


def _shape(fn: Any) -> list[tuple[str, Any, Any]]:
    params = list(inspect.signature(fn).parameters.values())[1:]  # drop self
    return [(p.name, p.kind, p.default) for p in params]


def _protocol_methods(proto: type) -> dict[str, Any]:
    return {n: m for n, m in vars(proto).items() if inspect.isfunction(m) and not n.startswith("_")}


@pytest.mark.parametrize(
    ("proto", "real", "fake_name"),
    [
        (gw.Gateway, gw.RealGateway, "FakeGateway"),
        (gw.Connection, gw._RealConnection, "FakeConnection"),  # pyright: ignore[reportPrivateUsage]
        (gw.Response, gw._RealResponse, "FakeResponse"),  # pyright: ignore[reportPrivateUsage]
    ],
)
def test_real_and_fake_have_the_protocol_methods_with_the_same_signatures(
    proto: type, real: type, fake_name: str
) -> None:
    import tests.fake_gateway as fg

    fake = getattr(fg, fake_name)
    wanted = _protocol_methods(proto)
    assert wanted, "the protocol declares no methods"
    real_methods = _public_methods(real)
    fake_methods = _public_methods(fake)
    for name, method in wanted.items():
        assert name in real_methods, f"real lacks {name}"
        assert name in fake_methods, f"fake lacks {name}"
        assert _shape(real_methods[name]) == _shape(method), f"real {name} differs from protocol"
        assert _shape(fake_methods[name]) == _shape(method), f"fake {name} differs from protocol"


def test_response_protocol_exposes_no_headers() -> None:
    # A Location header is never read (interface: Home Assistant edge).
    assert set(_protocol_methods(gw.Response)) == {"read"}
    assert {"status"} <= set(gw.Response.__annotations__)


def test_the_fake_is_a_gateway() -> None:
    g: Gateway = FakeGateway()
    h: Gateway = RealGateway()
    assert g and h


# --- shared scenarios -----------------------------------------------------------------------

OK_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]"


@dataclass
class Backend:
    gateway: Gateway
    spec: ConnectSpec
    received: list[bytes]


class LoopbackServer:
    """One-shot loopback server. Records the handle it opened and closes only that."""

    def __init__(self, reply: bytes | None) -> None:
        self.reply = reply
        self.received: list[bytes] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.sock.settimeout(0.1)
        self.stop = threading.Event()
        self.port: int = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        conn = None
        for _ in range(200):  # at most about 20 s; close() sets stop
            if self.stop.is_set():
                return
            try:
                conn, _ = self.sock.accept()
                break
            except TimeoutError:
                continue
            except OSError:
                return
        if conn is None:
            return
        with conn:
            conn.settimeout(10)
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                # Read the declared body too.
                head, _, rest = data.partition(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    k, _, v = line.partition(b":")
                    if k.strip().lower() == b"content-length":
                        length = int(v.strip())
                while len(rest) < length:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    rest += chunk
                data = head + b"\r\n\r\n" + rest
            except OSError:
                pass
            self.received.append(data)
            if self.reply is not None:
                conn.sendall(self.reply)

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=10)
        self.sock.close()


@contextlib.contextmanager
def closed_port() -> Iterator[int]:
    """A loopback port that refuses connections, with no race: it stays bound, never listens."""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        yield s.getsockname()[1]
    finally:
        s.close()


SCENARIOS = ["ok", "refused", "drop_after_request", "not_http", "short_body", "long_body"]
SHORT_BODY = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nabcd"
LONG_BODY = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcdef"


@pytest.fixture(params=["real", "fake"])
def make_backend(request: pytest.FixtureRequest) -> Iterator[Any]:
    servers: list[LoopbackServer] = []
    stack = contextlib.ExitStack()

    def make(scenario: str) -> Backend:
        if request.param == "real":
            reply = {
                "ok": OK_RESPONSE,
                "drop_after_request": None,
                "not_http": b"garbage\r\n\r\n",
                "short_body": SHORT_BODY,
                "long_body": LONG_BODY,
            }
            if scenario == "refused":
                port, received = stack.enter_context(closed_port()), []
            else:
                server = LoopbackServer(reply[scenario])
                servers.append(server)
                port, received = server.port, server.received
            return Backend(RealGateway(), _spec(port), received)
        script = {
            "ok": ConnectionScript(),
            "refused": ConnectionScript(connect_error=ConnectionRefusedError(111, "refused")),
            "drop_after_request": ConnectionScript(
                response_error=http.client.RemoteDisconnected("closed")
            ),
            "not_http": ConnectionScript(response_error=http.client.BadStatusLine("garbage")),
            "short_body": ConnectionScript(body=b"abcd", declared_length=100),
            "long_body": ConnectionScript(body=b"abcdef", declared_length=4),
        }[scenario]
        fake = FakeGateway()
        fake.scripts.append(script)
        return Backend(fake, _spec(8123), [])

    try:
        yield make
    finally:
        for s in servers:
            s.close()
        stack.close()


def _spec(port: int) -> ConnectSpec:
    return ConnectSpec("http", "127.0.0.1", port, connect_timeout=5.0, io_timeout=5.0)


def run_scenario(b: Backend) -> tuple[str, Any]:
    """Drive connect, request, getresponse, read the same way hass.py will."""
    conn = b.gateway.connect(b.spec)
    step = "connect"
    try:
        conn.connect()
        step = "request"
        conn.request("POST", "/api/services/notify/x", b'{"message":"m"}', {"X-A": "b"})
        step = "response"
        resp = conn.getresponse()
        body = b""
        while chunk := resp.read(1024):
            body += chunk
        return ("ok", (resp.status, body))
    except BaseException as exc:  # noqa: BLE001 - compare the class, whatever it is
        return (f"{step}:{type(exc).__name__}", None)
    finally:
        conn.close()


EXPECTED = {
    "ok": ("ok", (200, b"[]")),
    "refused": ("connect:ConnectionRefusedError", None),
    "drop_after_request": ("response:RemoteDisconnected", None),
    "not_http": ("response:BadStatusLine", None),
    "short_body": ("response:IncompleteRead", None),
    "long_body": ("ok", (200, b"abcd")),
}


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_same_outcome_on_real_and_fake(make_backend: Any, scenario: str) -> None:
    assert run_scenario(make_backend(scenario)) == EXPECTED[scenario]


def test_real_gateway_sends_the_documented_request(make_backend: Any, request: Any) -> None:
    if "real" not in request.node.callspec.id:
        pytest.skip("real gateway only")
    b = make_backend("ok")
    conn = b.gateway.connect(b.spec)
    try:
        conn.connect()
        conn.request(
            "POST",
            "/api/services/notify/svc",
            b'{"message":"m"}',
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Connection": "close",
                "User-Agent": "ha-notice/test",
                "Authorization": "Bearer fake-token",
            },
        )
        conn.getresponse().read(10)
    finally:
        conn.close()
    sent = b.received[0]
    head, _, body = sent.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    assert lines[0] == "POST /api/services/notify/svc HTTP/1.1"
    headers = {k.lower(): v.strip() for k, _, v in (x.partition(":") for x in lines[1:])}
    assert headers["host"] == f"127.0.0.1:{b.spec.port}"
    assert headers["accept-encoding"] == "identity"
    assert headers["connection"] == "close"
    assert headers["content-length"] == "15"
    assert headers["authorization"] == "Bearer fake-token"
    assert body == b'{"message":"m"}'


def test_real_gateway_resolves_through_its_own_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    server = LoopbackServer(OK_RESPONSE)
    seen: list[tuple[str, int]] = []
    real = RealGateway()
    original = real.resolve

    def spy(host: str, port: int) -> list[gw.AddrInfo]:
        seen.append((host, port))
        return original(host, port)

    monkeypatch.setattr(real, "resolve", spy)
    try:
        conn = real.connect(ConnectSpec("http", "localhost", server.port, 5.0, 5.0))
        try:
            conn.connect()
        finally:
            conn.close()
    finally:
        server.close()
    assert seen == [("localhost", server.port)]


def test_real_gateway_ignores_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = LoopbackServer(OK_RESPONSE)
    target = LoopbackServer(OK_RESPONSE)
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(var, f"http://127.0.0.1:{proxy.port}")
    try:
        b = Backend(RealGateway(), _spec(target.port), target.received)
        assert run_scenario(b) == EXPECTED["ok"]
    finally:
        proxy.close()
        target.close()
    assert proxy.received == []
    assert len(target.received) == 1


def test_real_gateway_does_not_follow_redirects() -> None:
    target = LoopbackServer(OK_RESPONSE)
    redirect = (
        f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target.port}/x\r\n"
        "Content-Length: 0\r\nConnection: close\r\n\r\n"
    ).encode()
    first = LoopbackServer(redirect)
    try:
        conn = RealGateway().connect(_spec(first.port))
        try:
            conn.connect()
            conn.request("GET", "/api/", None, {})
            assert conn.getresponse().status == 302
        finally:
            conn.close()
    finally:
        first.close()
        target.close()
    assert target.received == []


def test_real_connection_refused_is_prompt() -> None:
    gw_ = RealGateway()
    with closed_port() as port:
        conn = gw_.connect(_spec(port))
        try:
            with pytest.raises(ConnectionRefusedError):
                conn.connect()
        finally:
            conn.close()


def test_real_unresolvable_name_raises_gaierror() -> None:
    with pytest.raises(socket.gaierror):
        RealGateway().resolve("", 80)


def test_fake_unresolvable_name_raises_the_same_class() -> None:
    fake = FakeGateway()
    fake.resolve_errors["nope.example"] = socket.gaierror(-2, "Name or service not known")
    with pytest.raises(socket.gaierror):
        fake.resolve("nope.example", 80)


def test_https_to_a_plain_server_is_a_tls_error_on_both(request: Any) -> None:
    """The real gateway fails the TLS handshake with an ssl.SSLError (or a reset)."""
    import ssl

    server = LoopbackServer(None)
    real = RealGateway()
    spec = ConnectSpec("https", "127.0.0.1", server.port, 5.0, 5.0, tls=real.new_tls_context([]))
    conn = real.connect(spec)
    try:
        with pytest.raises((ssl.SSLError, OSError)):
            conn.connect()
    finally:
        conn.close()
        server.close()


# --- review round 1: the same scenarios on both ----------------------------------------------


@pytest.fixture(params=["real", "fake"])
def any_gateway(request: pytest.FixtureRequest) -> Gateway:
    return RealGateway() if request.param == "real" else FakeGateway()


def test_https_without_a_tls_context_is_a_value_error(any_gateway: Gateway) -> None:
    with pytest.raises(ValueError):
        any_gateway.connect(ConnectSpec("https", "127.0.0.1", 8123, 1.0, 1.0))


def test_bracketed_ipv6_literal_is_resolved_without_brackets() -> None:
    seen: list[tuple[str, int]] = []

    class Spy(RealGateway):
        def resolve(self, host: str, port: int) -> list[gw.AddrInfo]:
            seen.append((host, port))
            raise socket.gaierror(-2, "stop here")

    real_conn = Spy().connect(ConnectSpec("http", "[::1]", 8123, 1.0, 1.0))
    with pytest.raises(socket.gaierror):
        real_conn.connect()
    real_conn.close()

    fake = FakeGateway()
    fake.resolve_errors["::1"] = socket.gaierror(-2, "stop here")
    fake_conn = fake.connect(ConnectSpec("http", "[::1]", 8123, 1.0, 1.0))
    with pytest.raises(socket.gaierror):
        fake_conn.connect()
    assert seen == fake.resolve_calls == [("::1", 8123)]


def _connect_and(b: Backend, action: Any) -> Any:
    conn = b.gateway.connect(b.spec)
    try:
        conn.connect()
        return action(conn)
    finally:
        conn.close()


def _request_error(b: Backend, path: str, headers: dict[str, str]) -> BaseException:
    def act(conn: Any) -> BaseException:
        try:
            conn.request("POST", path, b"{}", headers)
        except BaseException as exc:  # noqa: BLE001 - the class is the result
            return exc
        raise AssertionError("request() did not raise")

    return _connect_and(b, act)


TOKEN = "SECRET-TOKEN-VALUE"
BAD_REQUESTS = [
    ("/a b", {}, http.client.InvalidURL),
    ("/a\x00b", {}, http.client.InvalidURL),
    ("/ok", {"Authorization": f"Bearer {TOKEN}\r\nX-Evil: 1"}, ValueError),
    ("/ok", {"Authorization": f"Bearer {TOKEN}\u2603"}, UnicodeEncodeError),
    ("/ok", {"Bad:Name": TOKEN}, ValueError),
    ("/ok", {"X\n": TOKEN}, ValueError),
]


@pytest.mark.parametrize(("path", "headers", "expected"), BAD_REQUESTS)
def test_request_validation_is_the_same_and_never_echoes_input(
    make_backend: Any, path: str, headers: dict[str, str], expected: type[BaseException]
) -> None:
    exc = _request_error(make_backend("ok"), path, headers)
    assert type(exc) is expected
    shown = f"{exc!s} {exc!r} {exc.args!r}"
    assert TOKEN not in shown and "/a b" not in shown and "\x00" not in shown
    assert exc.__context__ is None and exc.__cause__ is None


def test_a_second_request_before_the_response_is_cannot_send(make_backend: Any) -> None:
    def act(conn: Any) -> None:
        conn.request("GET", "/api/", None, {})
        with pytest.raises(http.client.CannotSendRequest):
            conn.request("GET", "/api/", None, {})

    _connect_and(make_backend("ok"), act)


def test_a_second_getresponse_is_response_not_ready(make_backend: Any) -> None:
    def act(conn: Any) -> None:
        conn.request("GET", "/api/", None, {})
        conn.getresponse()
        with pytest.raises(http.client.ResponseNotReady):
            conn.getresponse()

    _connect_and(make_backend("ok"), act)


def test_read_of_minus_one_reads_to_the_end(make_backend: Any) -> None:
    def act(conn: Any) -> bytes:
        conn.request("GET", "/api/", None, {})
        return conn.getresponse().read(-1)

    assert _connect_and(make_backend("ok"), act) == b"[]"


def test_read_of_minus_one_on_a_short_body_is_incomplete_read(make_backend: Any) -> None:
    def act(conn: Any) -> None:
        conn.request("GET", "/api/", None, {})
        with pytest.raises(http.client.IncompleteRead):
            conn.getresponse().read(-1)

    _connect_and(make_backend("short_body"), act)


def test_read_of_minus_one_stops_at_the_declared_length(make_backend: Any) -> None:
    def act(conn: Any) -> bytes:
        conn.request("GET", "/api/", None, {})
        return conn.getresponse().read(-1)

    assert _connect_and(make_backend("long_body"), act) == b"abcd"


# --- trust loading and directory checks, on both gateways ----------------------------------


def test_new_tls_context_loads_pem_bytes_on_both(
    any_gateway: Gateway, self_signed_cert: tuple[Path, Path]
) -> None:
    pem = self_signed_cert[0].read_bytes()
    ctx = any_gateway.new_tls_context([], (), [pem])
    assert ctx.cert_store_stats()["x509_ca"] == 1
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    for bad in (b"", b"junk", "é".encode()):
        with pytest.raises(gw.GatewayError):
            any_gateway.new_tls_context([], (), [bad])


def test_new_tls_context_loads_files_and_directories_on_both(
    any_gateway: Gateway, self_signed_cert: tuple[Path, Path], tmp_path: Path
) -> None:
    cert = self_signed_cert[0]
    assert any_gateway.new_tls_context([str(cert)]).cert_store_stats()["x509_ca"] == 1
    directory = tmp_path / "certs"
    directory.mkdir()
    any_gateway.new_tls_context([], [str(directory)])  # a directory loads lazily: no error
    # OpenSSL looks into a capath lazily, so even a missing directory is no load error.
    any_gateway.new_tls_context([], [str(tmp_path / "missing")])
    with pytest.raises(gw.GatewayError):
        any_gateway.new_tls_context([str(tmp_path / "missing.pem")])
    both = any_gateway.new_tls_context([str(cert)], [str(directory)], [cert.read_bytes()])
    assert both.cert_store_stats()["x509_ca"] == 1  # the same certificate twice is stored once


def test_has_entries_is_the_same_on_both(any_gateway: Gateway, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    full = tmp_path / "full"
    full.mkdir()
    (full / ".hidden").write_text("")
    plain = tmp_path / "plain"
    plain.write_text("x")
    assert not any_gateway.has_entries(str(empty))
    assert any_gateway.has_entries(str(full))
    assert not any_gateway.has_entries(str(plain))
    assert not any_gateway.has_entries(str(tmp_path / "missing"))
    assert not any_gateway.has_entries("")


# --- connect deadline (one monotonic deadline for resolve, every address and TLS) -------------


class _Clock:
    def __init__(self) -> None:
        self.now = 100.0


def _patched_real(
    monkeypatch: pytest.MonkeyPatch, addresses: list[float | None]
) -> tuple[RealGateway, _Clock, list[Any]]:
    """A real gateway on a fake clock whose addresses either refuse after a delay or blackhole."""
    clock = _Clock()
    socks: list[Any] = []

    class FakeSock:
        def __init__(self, *_a: Any) -> None:
            self.timeout: float | None = None
            self.closed = False
            socks.append(self)

        def settimeout(self, t: float | None) -> None:
            self.timeout = t

        def connect(self, sockaddr: Any) -> None:
            assert self.timeout is not None
            delay = sockaddr[1]
            if delay is None or delay >= self.timeout:
                clock.now += self.timeout
                raise TimeoutError("timed out")
            clock.now += delay
            raise ConnectionRefusedError(111, "refused")

        def close(self) -> None:
            self.closed = True

    class Clocked(RealGateway):
        def monotonic(self) -> float:
            return clock.now

        def resolve(self, host: str, port: int) -> list[gw.AddrInfo]:
            return [(2, 1, 6, "", ("a", d)) for d in addresses]

    import types

    monkeypatch.setattr(gw, "socket", types.SimpleNamespace(socket=FakeSock))
    return Clocked(), clock, socks


@pytest.mark.parametrize("addresses", [[None, None, None], [0.4, None, None], [0.2, 0.3, None]])
def test_connect_timeout_covers_all_addresses_on_real_and_fake(
    monkeypatch: pytest.MonkeyPatch, addresses: list[float | None]
) -> None:
    spec = ConnectSpec("http", "multi.example", 8123, 1.0, 1.0)
    real, clock, socks = _patched_real(monkeypatch, addresses)
    start = clock.now
    conn = real.connect(spec)
    with pytest.raises(TimeoutError):
        conn.connect()
    assert clock.now - start == pytest.approx(1.0)
    assert all(s.closed for s in socks)

    fake = FakeGateway()
    fake.scripts.append(ConnectionScript(address_delays=tuple(addresses)))
    t0 = fake.monotonic()
    fconn = fake.connect(spec)
    with pytest.raises(TimeoutError):
        fconn.connect()
    assert fake.monotonic() - t0 == pytest.approx(1.0)


def test_all_addresses_refusing_quickly_is_the_last_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = ConnectSpec("http", "multi.example", 8123, 1.0, 1.0)
    real, _clock, _socks = _patched_real(monkeypatch, [0.1, 0.1])
    with pytest.raises(ConnectionRefusedError):
        real.connect(spec).connect()
    fake = FakeGateway()
    fake.scripts.append(ConnectionScript(address_delays=(0.1, 0.1)))
    with pytest.raises(ConnectionRefusedError):
        fake.connect(spec).connect()


def test_a_slow_resolution_eats_the_connect_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    spec = ConnectSpec("http", "slow.example", 8123, 1.0, 1.0)
    real, clock, _socks = _patched_real(monkeypatch, [0.1])
    inner = real.resolve

    def slow_resolve(host: str, port: int) -> list[gw.AddrInfo]:
        clock.now += 1.5
        return inner(host, port)

    monkeypatch.setattr(real, "resolve", slow_resolve)
    with pytest.raises(TimeoutError):
        real.connect(spec).connect()

    fake = FakeGateway()
    fake.resolve_delay = 1.5
    with pytest.raises(TimeoutError):
        fake.connect(spec).connect()


def test_connect_delay_beyond_the_timeout_is_a_timeout_on_the_fake() -> None:
    fake = FakeGateway()
    fake.scripts.append(ConnectionScript(connect_delay=5.0))
    t0 = fake.monotonic()
    with pytest.raises(TimeoutError):
        fake.connect(ConnectSpec("http", "x.example", 80, 2.0, 2.0)).connect()
    assert fake.monotonic() - t0 == pytest.approx(2.0)


def test_a_tls_handshake_stall_is_bounded_by_the_connect_timeout() -> None:
    server = LoopbackServer(None)  # accepts, reads the ClientHello, answers nothing
    real = RealGateway()
    spec = ConnectSpec("https", "127.0.0.1", server.port, 0.5, 5.0, tls=real.new_tls_context([]))
    conn = real.connect(spec)
    t0 = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            conn.connect()
    finally:
        conn.close()
        server.close()
    assert time.monotonic() - t0 < 1.0


def test_a_slow_tcp_connect_shortens_the_handshake_time(monkeypatch: pytest.MonkeyPatch) -> None:
    real_socket = socket.socket

    class SlowConnect(real_socket):  # type: ignore[misc, valid-type]
        def connect(self, address: Any) -> None:
            time.sleep(0.4)
            super().connect(address)

    monkeypatch.setattr(gw.socket, "socket", SlowConnect)
    server = LoopbackServer(None)
    real = RealGateway()
    spec = ConnectSpec("https", "127.0.0.1", server.port, 0.5, 5.0, tls=real.new_tls_context([]))
    conn = real.connect(spec)
    t0 = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            conn.connect()
    finally:
        elapsed = time.monotonic() - t0
        conn.close()
        server.close()
    assert elapsed < 0.75  # one deadline, not 0.4 s plus a fresh 0.5 s for the handshake


def test_a_drip_feeding_tls_handshake_is_bounded_by_the_connect_timeout() -> None:
    # One byte every 0.3 s keeps every single recv under the 0.5 s timeout, so only an overall
    # deadline over the handshake (not a per-recv timer) can stop it.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    stop = threading.Event()

    def drip() -> None:
        try:
            peer, _ = listener.accept()
        except OSError:
            return
        with peer:
            try:
                for _ in range(40):
                    if stop.wait(0.3):
                        return
                    peer.sendall(b"\x16")
            except OSError:
                return

    thread = threading.Thread(target=drip, daemon=True)
    thread.start()
    real = RealGateway()
    port: int = listener.getsockname()[1]
    spec = ConnectSpec("https", "127.0.0.1", port, 0.5, 60.0, tls=real.new_tls_context([]))
    conn = real.connect(spec)
    t0 = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            conn.connect()
    finally:
        elapsed = time.monotonic() - t0
        conn.close()
        stop.set()
        listener.close()
        thread.join(2)
    assert elapsed < 1.0 + LOAD_SLACK_S  # the drip would run 12 s


# --- internals of the real connection ---------------------------------------------------------


def test_the_http_client_seam_must_exist(monkeypatch: pytest.MonkeyPatch) -> None:
    class Renamed:
        def __init__(self, *_a: Any, **_k: Any) -> None:
            pass

    monkeypatch.setattr(gw.http.client, "HTTPConnection", Renamed)
    with pytest.raises(gw.GatewayError):
        RealGateway().connect(ConnectSpec("http", "127.0.0.1", 80, 1.0, 1.0))


def test_the_http_client_seam_is_ours() -> None:
    conn = RealGateway().connect(ConnectSpec("http", "127.0.0.1", 80, 1.0, 1.0))
    inner: Any = conn._conn  # pyright: ignore[reportPrivateUsage]
    assert inner._create_connection == conn._open_socket  # pyright: ignore[reportPrivateUsage]
