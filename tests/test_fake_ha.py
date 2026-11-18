"""Contract tests of the fake Home Assistant server (issue #4).

The client is the real gateway from issue #3 wherever it can show the behavior; the response
headers are not part of the gateway's surface, so those checks use ``http.client`` directly.
The response mapping, retries and deadline belong to later issues; the TODOs name them.
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import threading
import time
from collections.abc import Iterator
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


def test_a_reset_after_the_request_is_a_connection_error(ha: FakeHA) -> None:
    ha.script.append(Reply(drop=True, reset=True))
    with pytest.raises(ConnectionError):
        exchange(ha)
    assert len(ha.wait_for_requests(1)) == 1


def test_a_response_cut_short_is_an_incomplete_read(ha: FakeHA) -> None:
    ha.script.append(Reply(body=b"abcd", declared_length=100))
    with pytest.raises(http.client.IncompleteRead):
        exchange(ha)


def test_a_response_cut_inside_the_status_line_is_a_bad_response(ha: FakeHA) -> None:
    ha.script.append(Reply(truncate_after=10))
    with pytest.raises((http.client.HTTPException, ConnectionError)):
        exchange(ha)


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
        target = other.base_url + NOTIFY
        ha.script.extend([redirect(target, 307), redirect(target)])
        status, _ = exchange(ha)
        response = raw_exchange(ha, "POST", NOTIFY)
        assert status == 307
        assert (response.status, response.getheader("Location")) == (302, target)
        assert other.requests == []  # neither client followed it
        assert other.connections == 0
    # TODO(#23): a 3xx maps to wrong_host_response and nothing reads the Location.


def test_the_token_reaches_only_the_server_it_was_sent_to() -> None:
    with FakeHA(token=TOKEN) as base, FakeHA(token=TOKEN) as elsewhere:
        exchange(base)
        exchange(base, "GET", "/api/")
        sent = [r for r in base.requests if r.header("Authorization")]
        assert len(sent) == 2
        assert elsewhere.requests == []
        assert elsewhere.connections == 0


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
    other_cert: tuple[Path, Path], self_signed_cert: tuple[Path, Path]
) -> None:
    cert, key = other_cert
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key) as ha:
        with pytest.raises(ssl.SSLCertVerificationError):
            exchange(ha, tls=trust(cert))  # trusted, but the name 127.0.0.1 does not match
        assert ha.requests == []


def test_a_system_trust_only_context_does_not_verify_the_fake(
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
        assert ha._sock.getsockname()[0] == "127.0.0.1"  # pyright: ignore[reportPrivateUsage]
        assert ha.port > 0


def test_two_servers_get_different_ports() -> None:
    with FakeHA() as a, FakeHA() as b:
        assert a.port != b.port


def test_recorded_request_header_lookup_is_case_insensitive_and_keeps_duplicates() -> None:
    req = RecordedRequest("GET", "/", (("X-A", "1"), ("x-a", "2")), b"", False)
    assert req.header_values("X-a") == ["1", "2"]
    assert req.header("missing") is None
