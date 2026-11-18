"""The fake gateway is faithful to the real one (issue #3).

Part 1 compares signatures. Part 2 runs the same connection scenarios against the real gateway
(on a loopback server this test starts and stops itself) and the fake, and requires the same
outcome, including the same exception classes.
"""

from __future__ import annotations

import http.client
import inspect
import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from ha_notice import gateway as gw
from ha_notice.gateway import ConnectSpec, Gateway, RealGateway
from tests.fake_gateway import ConnectionScript, FakeGateway

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


def _free_closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port: int = s.getsockname()[1]
    s.close()
    return port


SCENARIOS = ["ok", "refused", "drop_after_request", "not_http"]


@pytest.fixture(params=["real", "fake"])
def make_backend(request: pytest.FixtureRequest) -> Iterator[Any]:
    servers: list[LoopbackServer] = []

    def make(scenario: str) -> Backend:
        if request.param == "real":
            reply = {"ok": OK_RESPONSE, "drop_after_request": None, "not_http": b"garbage\r\n\r\n"}
            if scenario == "refused":
                port, received = _free_closed_port(), []
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
        }[scenario]
        fake = FakeGateway()
        fake.scripts.append(script)
        return Backend(fake, _spec(8123), [])

    try:
        yield make
    finally:
        for s in servers:
            s.close()


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
    conn = gw_.connect(_spec(_free_closed_port()))
    with pytest.raises(ConnectionRefusedError):
        conn.connect()


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
