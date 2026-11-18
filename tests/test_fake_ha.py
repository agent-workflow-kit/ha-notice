"""Contract tests of the fake Home Assistant server (issue #4).

The client is the real gateway from issue #3 wherever it can show the behavior; the response
headers are not part of the gateway's surface, so those checks use ``http.client`` directly.
The response mapping, retries and deadline belong to later issues; the TODOs name them.
"""

from __future__ import annotations

import gc
import http.client
import json
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from ha_notice.gateway import ConnectSpec, Gateway, RealGateway
from tests.fake_ha import (
    API_RUNNING,
    EDGE_ROWS,
    FakeHA,
    RecordedRequest,
    Reply,
    StallingResolverGateway,
    json_body,
    redirect,
)

TOKEN = "HA_fake-token-0123456789"
NOTIFY = "/api/services/notify/mobile_app_test"
POST_BODY = json.dumps({"message": "hello"}).encode()
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Connection": "close",
}


def spec(ha: FakeHA, *, io_timeout: float = 5.0, tls: ssl.SSLContext | None = None) -> ConnectSpec:
    return ConnectSpec(
        "https" if ha.scheme == "https" else "http",
        "127.0.0.1",
        ha.port,
        connect_timeout=5.0,
        io_timeout=io_timeout,
        tls=tls,
    )


def exchange(
    ha: FakeHA,
    method: str = "POST",
    path: str = NOTIFY,
    *,
    body: bytes | None = POST_BODY,
    headers: dict[str, str] | None = None,
    io_timeout: float = 5.0,
    tls: ssl.SSLContext | None = None,
    gateway: Gateway | None = None,
) -> tuple[int, bytes]:
    """One request through the real gateway; returns (status, whole body)."""
    gw = gateway or RealGateway()
    conn = gw.connect(spec(ha, io_timeout=io_timeout, tls=tls))
    try:
        conn.connect()
        sent = dict(headers or HEADERS)
        if method == "GET":  # the probe sends no Content-Type
            sent.pop("Content-Type", None)
        conn.request(method, path, body if method != "GET" else None, sent)
        response = conn.getresponse()
        data = b""
        while True:
            chunk = response.read(1024)
            if not chunk:
                return response.status, data
            data += chunk
    finally:
        conn.close()


def raw_exchange(ha: FakeHA, method: str, path: str) -> http.client.HTTPResponse:
    """The same through ``http.client``, for the headers the gateway does not expose."""
    conn = http.client.HTTPConnection("127.0.0.1", ha.port, timeout=5)
    conn.request(method, path, body=POST_BODY if method == "POST" else None, headers=HEADERS)
    response = conn.getresponse()
    response.read()
    conn.close()
    return response


def trust(cert: Path) -> ssl.SSLContext:
    return RealGateway().new_tls_context([str(cert)])


@pytest.fixture
def ha() -> Iterator[FakeHA]:
    with FakeHA(token=TOKEN) as server:
        yield server


@pytest.fixture
def tls_ha(self_signed_cert: tuple[Path, Path]) -> Iterator[FakeHA]:
    cert, key = self_signed_cert
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key) as server:
        yield server


# --- default routes -------------------------------------------------------------------------


def test_get_api_answers_with_a_json_object(ha: FakeHA) -> None:
    status, body = exchange(ha, "GET", "/api/")
    assert status == 200
    assert body == API_RUNNING
    assert isinstance(json.loads(body), dict)


def test_notify_post_answers_with_an_empty_list(ha: FakeHA) -> None:
    status, body = exchange(ha)
    assert (status, json.loads(body)) == (200, [])


def test_requests_are_recorded_with_method_path_headers_and_body(ha: FakeHA) -> None:
    exchange(ha)
    exchange(ha, "GET", "/api/")
    first, second = ha.wait_for_requests(2)
    assert (first.method, first.path, first.body) == ("POST", NOTIFY, POST_BODY)
    assert first.header("authorization") == f"Bearer {TOKEN}"
    assert first.header("Content-Type") == "application/json"
    assert json_body(first) == {"message": "hello"}
    assert (second.method, second.path, second.body) == ("GET", "/api/", b"")
    assert second.header("Content-Type") is None
    assert not first.tls


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("GET", "/api/services/notify/x", 405),  # wrong method on the service
        ("POST", "/api/", 405),
        ("POST", "/api//services/notify/x", 404),  # a double slash is a 404 on the host
        ("POST", "/api/services/notify/x/", 404),  # so is a trailing slash
        ("POST", "/prefix/api/services/notify/x", 404),
        ("GET", "/", 404),
    ],
)
def test_default_routes_answer_404_and_405_like_home_assistant(
    ha: FakeHA, method: str, path: str, expected: int
) -> None:
    assert exchange(ha, method, path)[0] == expected


@pytest.mark.parametrize("auth", [None, "Bearer wrong", f"bearer {TOKEN}", TOKEN, "Bearer "])
def test_missing_or_wrong_token_is_401(ha: FakeHA, auth: str | None) -> None:
    headers = {k: v for k, v in HEADERS.items() if k != "Authorization"}
    if auth is not None:
        headers["Authorization"] = auth
    assert exchange(ha, headers=headers)[0] == 401


def test_no_token_configured_checks_nothing() -> None:
    with FakeHA() as server:
        headers = {k: v for k, v in HEADERS.items() if k != "Authorization"}
        assert exchange(server, headers=headers)[0] == 200


# --- the edge table -------------------------------------------------------------------------


@pytest.mark.parametrize("row", sorted(EDGE_ROWS))
def test_each_edge_row_is_reproduced_on_the_wire(ha: FakeHA, row: str) -> None:
    expected = EDGE_ROWS[row]
    ha.script.append(expected)
    status, body = exchange(ha)
    assert (status, body) == (expected.status, expected.body)


def test_edge_rows_cover_every_status_class_of_the_table() -> None:
    statuses = {r.status for r in EDGE_ROWS.values()}
    # 200, other 2xx, 3xx, 400, 401/403, 404/405, 429, 5xx and "any other status".
    assert {200, 201, 204, 301, 302, 400, 401, 403, 404, 405, 429, 500, 503, 418} <= statuses


def test_the_wrong_body_rows_are_200_but_not_a_json_list() -> None:
    for name in ("200_object", "200_not_json", "200_empty"):
        reply = EDGE_ROWS[name]
        assert reply.status == 200
        try:
            assert not isinstance(json.loads(reply.body), list)
        except ValueError:
            pass  # not JSON at all is also a wrong body
    assert isinstance(json.loads(EDGE_ROWS["200_list_with_content"].body), list)


@pytest.mark.parametrize("value", ["nan", "-5", "1e999", "Wed, 21 Oct 2026 07:28:00 GMT", "5", "0"])
def test_a_429_carries_any_retry_after_header_unchanged(ha: FakeHA, value: str) -> None:
    ha.script.append(
        Reply(429, b"429: Too Many Requests", headers=(("Retry-After", value),), content_type=None)
    )
    response = raw_exchange(ha, "POST", NOTIFY)
    assert response.status == 429
    assert response.getheader("Retry-After") == value


def test_a_script_is_consumed_one_reply_per_request_then_defaults_return(ha: FakeHA) -> None:
    ha.script.extend([EDGE_ROWS["429"], EDGE_ROWS["429"], EDGE_ROWS["503"]])
    assert [exchange(ha)[0] for _ in range(4)] == [429, 429, 503, 200]
    assert ha.script == []


def test_wrong_body_is_served_with_the_declared_length(ha: FakeHA) -> None:
    ha.script.append(EDGE_ROWS["200_object"])
    response = raw_exchange(ha, "POST", NOTIFY)
    assert response.getheader("Content-Length") == "2"
    assert response.getheader("Content-Type") == "application/json; charset=utf-8"


# --- misbehavior ----------------------------------------------------------------------------


def test_a_delay_longer_than_the_io_timeout_times_out_after_the_request_is_recorded(
    ha: FakeHA,
) -> None:
    ha.script.append(Reply(delay=3.0))
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        exchange(ha, io_timeout=0.3)
    assert time.monotonic() - started < 2.5
    assert len(ha.wait_for_requests(1)) == 1  # the host saw the whole request


def test_a_delay_shorter_than_the_io_timeout_still_answers(ha: FakeHA) -> None:
    ha.script.append(Reply(delay=0.2))
    assert exchange(ha, io_timeout=3.0)[0] == 200


def test_a_trickled_response_outlasts_the_io_timeout_but_never_stalls_one_read(ha: FakeHA) -> None:
    # Per-operation timeouts are why the gateway's deadline lives in the caller's worker.
    reply = Reply(trickle=0.01)
    total = len(reply.serialize())
    ha.script.append(reply)
    started = time.monotonic()
    status, body = exchange(ha, io_timeout=0.4)
    elapsed = time.monotonic() - started
    assert (status, body) == (200, b"[]")
    assert elapsed > 0.01 * (total - 1) * 0.8
    assert elapsed > 0.4  # longer than one io_timeout, yet no single read timed out
    # TODO(#25): the send deadline ends a trickle that outlasts `timeout`.


def test_a_trickle_with_a_gap_longer_than_the_io_timeout_times_out(ha: FakeHA) -> None:
    ha.script.append(Reply(trickle=1.0))
    with pytest.raises(TimeoutError):
        exchange(ha, io_timeout=0.2)


def test_drop_after_the_request_is_remote_disconnected(ha: FakeHA) -> None:
    ha.script.append(Reply(drop=True))
    with pytest.raises(http.client.RemoteDisconnected):
        exchange(ha)
    assert len(ha.wait_for_requests(1)) == 1
    # TODO(#24): a drop once the gate is writing is outcome_unknown and is never retried.


def test_a_reset_after_the_request_is_a_connection_reset_not_a_clean_close(ha: FakeHA) -> None:
    ha.script.append(Reply(drop=True, reset=True))
    with pytest.raises(ConnectionResetError) as info:
        exchange(ha)
    # RemoteDisconnected is a ConnectionResetError too, and is what a FIN (no SO_LINGER) gives.
    assert not isinstance(info.value, http.client.RemoteDisconnected)
    assert len(ha.wait_for_requests(1)) == 1


def test_a_reset_after_a_partial_response_is_a_connection_reset(ha: FakeHA) -> None:
    head_length = len(Reply(body=b"").serialize())
    ha.script.append(
        Reply(body=b"abcd", declared_length=100, truncate_after=head_length + 2, reset=True)
    )
    with pytest.raises(ConnectionResetError) as info:
        exchange(ha)
    assert not isinstance(info.value, http.client.RemoteDisconnected)


def test_a_reset_during_a_trickle_is_a_connection_reset(ha: FakeHA) -> None:
    ha.script.append(Reply(trickle=0.005, truncate_after=60, reset=True))
    with pytest.raises(ConnectionResetError) as info:
        exchange(ha)
    assert not isinstance(info.value, http.client.RemoteDisconnected)


def test_a_response_cut_short_is_an_incomplete_read(ha: FakeHA) -> None:
    ha.script.append(Reply(body=b"abcd", declared_length=100))
    with pytest.raises(http.client.IncompleteRead):
        exchange(ha)


def test_a_response_cut_inside_the_status_line_is_a_bad_status_line(ha: FakeHA) -> None:
    ha.script.append(Reply(truncate_after=10))
    with pytest.raises(http.client.BadStatusLine) as info:
        exchange(ha)
    assert not isinstance(info.value, http.client.RemoteDisconnected)


def test_a_hang_after_the_head_times_out_on_the_body(ha: FakeHA) -> None:
    head_length = len(Reply(body=b"").serialize())
    ha.script.append(Reply(body=b"abcd", declared_length=4, truncate_after=head_length, hang=True))
    with pytest.raises(TimeoutError):
        exchange(ha, io_timeout=0.3)


def test_bytes_that_are_not_http_are_a_bad_status_line(ha: FakeHA) -> None:
    ha.script.append(Reply(raw=b"garbage\r\n\r\n"))
    with pytest.raises(http.client.BadStatusLine):
        exchange(ha)


def test_a_redirect_is_served_but_the_second_server_sees_nothing() -> None:
    with FakeHA(token=TOKEN) as other, FakeHA(token=TOKEN) as ha:
        # Positive control: the counters are live, so the unchanged values below mean something.
        assert exchange(other)[0] == 200
        assert (other.connections, len(other.requests)) == (1, 1)
        target = other.base_url + NOTIFY
        ha.script.extend([redirect(target, 307), redirect(target)])
        status, _ = exchange(ha)
        response = raw_exchange(ha, "POST", NOTIFY)
        assert status == 307
        assert (response.status, response.getheader("Location")) == (302, target)
        assert (other.connections, len(other.requests)) == (1, 1)  # neither client followed it
    # TODO(#23): a 3xx maps to wrong_host_response and nothing reads the Location.


def test_the_token_reaches_only_the_server_it_was_sent_to() -> None:
    with FakeHA(token=TOKEN) as base, FakeHA(token=TOKEN) as elsewhere:
        # Positive control: a request to the other server is counted and carries the token.
        assert exchange(elsewhere)[0] == 200
        assert (elsewhere.connections, len(elsewhere.requests)) == (1, 1)
        assert elsewhere.requests[0].header("Authorization") == f"Bearer {TOKEN}"
        exchange(base)
        exchange(base, "GET", "/api/")
        sent = [r for r in base.requests if r.header("Authorization")]
        assert len(sent) == 2
        assert (elsewhere.connections, len(elsewhere.requests)) == (1, 1)


# --- stalled name resolution ----------------------------------------------------------------


def test_a_stalled_resolver_holds_the_connect_and_no_request_reaches_the_server(ha: FakeHA) -> None:
    gw = StallingResolverGateway()
    result: list[object] = []

    def run() -> None:
        try:
            result.append(exchange(ha, gateway=gw))
        except BaseException as exc:  # reported by the assertions below
            result.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert gw.resolving.wait(5)
    time.sleep(0.3)
    assert result == []
    assert ha.connections == 0 and ha.requests == []  # nothing was sent while resolving
    gw.release.set()
    thread.join(10)
    assert result == [(200, b"[]")]
    assert gw.calls == [("127.0.0.1", ha.port)]
    # TODO(#25): the deadline ends a send whose name resolution never returns.


# --- TLS ------------------------------------------------------------------------------------


def test_https_with_the_certificate_as_trust_anchor_works(
    tls_ha: FakeHA, self_signed_cert: tuple[Path, Path]
) -> None:
    status, body = exchange(tls_ha, tls=trust(self_signed_cert[0]))
    assert (status, body) == (200, b"[]")
    assert tls_ha.requests[0].tls
    assert tls_ha.base_url.startswith("https://127.0.0.1:")


def test_https_without_trusting_the_certificate_fails_verification(tls_ha: FakeHA) -> None:
    empty_trust = RealGateway().new_tls_context([])
    with pytest.raises(ssl.SSLCertVerificationError):
        exchange(tls_ha, tls=empty_trust)
    assert tls_ha.requests == []  # the token is never sent after a failed handshake
    # TODO(#22): trust selection decides which files are in the context; ca_file adds this one.


def test_a_certificate_for_another_name_fails_verification(
    other_cert: tuple[Path, Path],
) -> None:
    cert, key = other_cert
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key) as ha:
        with pytest.raises(ssl.SSLCertVerificationError):
            exchange(ha, tls=trust(cert))  # trusted, but the name 127.0.0.1 does not match
        assert ha.requests == []


def test_a_context_trusting_a_different_ca_does_not_verify_the_fake(
    tls_ha: FakeHA, other_cert: tuple[Path, Path]
) -> None:
    with pytest.raises(ssl.SSLCertVerificationError):
        exchange(tls_ha, tls=trust(other_cert[0]))  # a different CA


def test_a_plain_client_against_the_https_server_fails_and_records_no_request(
    tls_ha: FakeHA,
) -> None:
    with pytest.raises((http.client.HTTPException, ConnectionError)):
        raw_exchange(tls_ha, "POST", NOTIFY)
    deadline = time.monotonic() + 5
    while not tls_ha.handshake_failures and time.monotonic() < deadline:
        time.sleep(0.01)
    assert tls_ha.handshake_failures
    assert tls_ha.requests == []


def test_a_tls_client_against_the_plain_server_fails(
    ha: FakeHA, self_signed_cert: tuple[Path, Path]
) -> None:
    conn = RealGateway().connect(
        ConnectSpec("https", "127.0.0.1", ha.port, 1.0, 1.0, trust(self_signed_cert[0]))
    )
    with pytest.raises((ssl.SSLError, ConnectionError, TimeoutError)):
        conn.connect()
    conn.close()
    assert ha.requests == []


# --- robustness and shutdown ----------------------------------------------------------------


@pytest.mark.parametrize(
    "garbage",
    [
        b"\x00\x01\x02\r\n\r\n",
        b"POST /x HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
        b"POST /x HTTP/1.1\r\nno-colon-here\r\n\r\n",
        b"GET / HTTP/1.1\r\n" + b"X: " + b"a" * 100_000,
        b"POST /x HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n",
        b"",
    ],
)
def test_a_malformed_request_is_dropped_and_the_server_keeps_serving(
    ha: FakeHA, garbage: bytes
) -> None:
    with socket.create_connection(("127.0.0.1", ha.port), timeout=5) as s:
        try:
            s.sendall(garbage)
            s.shutdown(socket.SHUT_WR)
            s.settimeout(5)
            while s.recv(4096):
                pass
        except OSError:
            pass
    assert exchange(ha)[0] == 200
    assert all(r.path == NOTIFY for r in ha.requests)  # the malformed one was not recorded


def test_parallel_requests_are_all_recorded() -> None:
    with FakeHA(token=TOKEN) as ha:
        results: list[int] = []
        lock = threading.Lock()

        def one() -> None:
            status, _ = exchange(ha)
            with lock:
                results.append(status)

        threads = [threading.Thread(target=one) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert results == [200] * 8
        assert len(ha.wait_for_requests(8)) == 8


def test_close_stops_the_listener_and_all_threads_even_with_a_hung_connection() -> None:
    ha = FakeHA(token=TOKEN)
    ha.script.append(Reply(hang=True, truncate_after=0))
    port = ha.port
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"GET /api/ HTTP/1.1\r\nHost: x\r\n\r\n")
    ha.wait_for_requests(1)
    started = time.monotonic()
    ha.close()
    assert time.monotonic() - started < 5
    s.close()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
    assert not [t for t in threading.enumerate() if t.name.startswith("fake-ha")]


def test_the_server_binds_loopback_only() -> None:
    with FakeHA() as ha:
        assert ha._server.sock.getsockname()[0] == "127.0.0.1"  # pyright: ignore[reportPrivateUsage]
        assert ha.port > 0


def test_two_servers_get_different_ports() -> None:
    with FakeHA() as a, FakeHA() as b:
        assert a.port != b.port


def test_recorded_request_header_lookup_is_case_insensitive_and_keeps_duplicates() -> None:
    req = RecordedRequest("GET", "/", (("X-A", "1"), ("x-a", "2")), b"", False)
    assert req.header_values("X-a") == ["1", "2"]
    assert req.header("missing") is None


# --- review round 1 -------------------------------------------------------------------------


def wait_until(condition: Callable[[], bool], timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.01)
    return condition()


def send_raw(ha: FakeHA, data: bytes) -> None:
    """Send bytes on one connection, half-close, and wait for the server to finish with it."""
    with socket.create_connection(("127.0.0.1", ha.port), timeout=5) as s:
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        s.settimeout(5)
        try:
            while s.recv(4096):
                pass
        except OSError:
            pass


def fake_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name.startswith("fake-ha")]


def test_the_raw_bytes_of_a_good_request_are_recorded_per_connection(ha: FakeHA) -> None:
    exchange(ha)
    ha.wait_for_requests(1)
    assert wait_until(lambda: len(ha.received) == 1 and ha.received[0] != b"")
    assert ha.received[0].startswith(b"POST " + NOTIFY.encode())
    assert ha.received[0].endswith(POST_BODY)


def test_a_connection_that_sends_nothing_records_empty_bytes(ha: FakeHA) -> None:
    send_raw(ha, b"")
    assert wait_until(lambda: len(ha.bad_requests) == 1)
    assert wait_until(lambda: ha.received == [b""])


@pytest.mark.parametrize(
    "data",
    [
        b"POST /x HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc",  # partial body
        b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        b"POST /x HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
        b"POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcEXTRA",  # trailing bytes
        b"GET /api/ HTTP/1.1\r\n\r\nGET /api/ HTTP/1.1\r\n\r\n",  # pipelined
    ],
    ids=["partial_body", "chunked", "duplicate_length", "trailing_bytes", "pipelined"],
)
def test_a_bad_request_is_rejected_but_its_raw_bytes_are_kept(ha: FakeHA, data: bytes) -> None:
    send_raw(ha, data)
    assert wait_until(lambda: len(ha.bad_requests) == 1)
    assert wait_until(lambda: ha.received == [data])
    assert ha.requests == []


# 1
def test_close_wakes_an_idle_handshaken_tls_connection_quickly(
    tls_ha: FakeHA, self_signed_cert: tuple[Path, Path]
) -> None:
    ctx = trust(self_signed_cert[0])
    with socket.create_connection(("127.0.0.1", tls_ha.port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname="127.0.0.1"):
            started = time.monotonic()
            tls_ha.close()
            assert time.monotonic() - started < 2
    assert not fake_threads()


def test_close_wakes_a_tls_connection_that_never_handshakes_quickly(tls_ha: FakeHA) -> None:
    with socket.create_connection(("127.0.0.1", tls_ha.port), timeout=5):
        assert wait_until(lambda: tls_ha.connections == 1)
        time.sleep(0.2)  # let the handler block in the handshake
        started = time.monotonic()
        tls_ha.close()
        assert time.monotonic() - started < 2
    assert not fake_threads()


# 5
@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"\xff\xfe",
        b"[]",
        b'"message"',
        b"{}",
        b'{"message": ""}',
        b'{"message": 5}',
        b'{"message": null}',
        b'{"message": "x", "extra": 1}',
        b'{"message": "x", "title": 3}',
        b'{"message": "x", "data": []}',
        b'{"message": "x", "data": {"nope": "y"}}',
        b'{"message": "x", "data": {"tag": 1}}',
    ],
)
def test_the_default_notify_route_answers_400_for_an_invalid_body(ha: FakeHA, body: bytes) -> None:
    assert exchange(ha, body=body)[0] == 400


def test_the_default_notify_route_accepts_every_field_the_interface_names(ha: FakeHA) -> None:
    body = json.dumps(
        {
            "title": "t",
            "message": "m",
            "data": {"url": "u", "clickAction": "c", "tag": "g", "group": "x"},
        }
    ).encode()
    assert exchange(ha, body=body)[0] == 200


def test_an_unknown_service_is_400_when_services_are_given() -> None:
    with FakeHA(token=TOKEN, services={"mobile_app_test"}) as server:
        assert exchange(server)[0] == 200
        assert exchange(server, path="/api/services/notify/other")[0] == 400


# 8
@pytest.mark.parametrize(
    "kwargs",
    [
        {"headers": (("X-A", "a\r\nInjected: 1"),)},
        {"headers": (("X\nA", "a"),)},
        {"headers": (("X-A", "café€"),)},
        {"headers": (("X-€", "a"),)},
        {"content_type": "text/plain\r\nX: y"},
        {"chunked": True, "declared_length": 3},
    ],
)
def test_a_reply_that_cannot_be_put_on_the_wire_is_rejected_at_construction(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        Reply(**kwargs)  # type: ignore[arg-type]


def test_an_unexpected_error_in_a_handler_is_recorded_and_no_thread_exception_escapes(
    ha: FakeHA,
) -> None:
    escaped: list[object] = []
    previous = threading.excepthook
    threading.excepthook = escaped.append
    try:
        bad = Reply()
        object.__setattr__(bad, "headers", (("X-A", "€"),))  # bypasses the construction check
        ha.script.append(bad)
        with pytest.raises((http.client.HTTPException, ConnectionError)):
            exchange(ha)
        assert wait_until(lambda: len(ha.handler_errors) == 1)
    finally:
        threading.excepthook = previous
    assert escaped == []


# 9
def test_close_of_an_idle_server_does_not_wait_for_an_accept_poll() -> None:
    durations: list[float] = []
    for _ in range(5):
        server = FakeHA()
        started = time.monotonic()
        server.close()
        durations.append(time.monotonic() - started)
    assert sum(durations) / len(durations) < 0.5
    assert max(durations) < 1.0  # the accept timeout is only a safety net
    assert not fake_threads()


# 10
def test_a_server_that_is_garbage_collected_unclosed_stops_its_threads_and_socket() -> None:
    server = FakeHA()
    port = server.port
    del server
    gc.collect()
    assert wait_until(lambda: not fake_threads())
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


# 12
@pytest.mark.parametrize("auth", [None, "Bearer wrong"])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_an_unknown_path_is_404_before_the_token_is_checked(
    ha: FakeHA, auth: str | None, method: str
) -> None:
    headers = {k: v for k, v in HEADERS.items() if k != "Authorization"}
    if auth is not None:
        headers["Authorization"] = auth
    assert exchange(ha, method, "/api/nothing", headers=headers)[0] == 404
    assert exchange(ha, method, "/", headers=headers)[0] == 404


# 13
def test_the_query_string_is_ignored_for_routing_but_kept_in_the_record(ha: FakeHA) -> None:
    assert exchange(ha, path="/api/services/notify/x?foo=1")[0] == 200
    assert exchange(ha, "GET", "/api/?a=b")[0] == 200
    first, second = ha.wait_for_requests(2)
    assert first.path == "/api/services/notify/x?foo=1"
    assert second.path == "/api/?a=b"


# 15
def test_a_complete_chunked_response_reads_fine(ha: FakeHA) -> None:
    ha.script.append(Reply(body=b"[1, 2, 3]", chunked=True))
    assert exchange(ha) == (200, b"[1, 2, 3]")
    response = raw_exchange_after(ha, Reply(chunked=True))
    assert response.getheader("Transfer-Encoding") == "chunked"
    assert response.getheader("Content-Length") is None


def raw_exchange_after(ha: FakeHA, reply: Reply) -> http.client.HTTPResponse:
    ha.script.append(reply)
    return raw_exchange(ha, "POST", NOTIFY)


def test_a_chunked_response_cut_mid_body_is_an_incomplete_read(ha: FakeHA) -> None:
    head_length = len(Reply(chunked=True, body=b"").serialize()) - len(b"0\r\n\r\n")
    ha.script.append(Reply(chunked=True, body=b"a" * 100, truncate_after=head_length + 10))
    with pytest.raises(http.client.IncompleteRead):
        exchange(ha)


def test_a_chunked_body_over_the_cap_reads_like_a_content_length_one(ha: FakeHA) -> None:
    # The gateway has no cap of its own: the caller reads 1 KiB slices and stops at 64 KiB.
    big = b"x" * 70000
    ha.script.extend([Reply(body=big), Reply(body=big, chunked=True)])
    assert exchange(ha) == (200, big)
    assert exchange(ha) == (200, big)

    def first_slices(reply: Reply) -> list[int]:
        ha.script.append(reply)
        conn = RealGateway().connect(spec(ha))
        try:
            conn.connect()
            conn.request("POST", NOTIFY, POST_BODY, HEADERS)
            response = conn.getresponse()
            return [len(response.read(1024)) for _ in range(66)]
        finally:
            conn.close()

    assert first_slices(Reply(body=big)) == first_slices(Reply(body=big, chunked=True))


# 16
def test_stall_before_read_never_reads_or_answers_and_close_wakes_it() -> None:
    ha = FakeHA(token=TOKEN)
    ha.script.append(Reply(stall_before_read=True))
    with pytest.raises(TimeoutError):
        exchange(ha, io_timeout=0.3)
    assert ha.requests == [] and ha.connections == 1
    assert ha.script == []
    started = time.monotonic()
    ha.close()
    assert time.monotonic() - started < 2
    assert not fake_threads()


# 17
def test_a_prefix_moves_the_default_routes() -> None:
    with FakeHA(token=TOKEN, prefix="ha") as server:
        assert exchange(server, path="/ha" + NOTIFY)[0] == 200
        assert exchange(server, "GET", "/ha/api/")[0] == 200
        assert exchange(server)[0] == 404
        assert exchange(server, "GET", "/api/")[0] == 404
        assert exchange(server, "GET", "/hax/api/")[0] == 404
