"""The fake gateway can block connect, stall after the first byte and fail resolution (issue #3)."""

from __future__ import annotations

import http.client
import os
import socket
import threading
from pathlib import Path
from typing import Any

import pytest

from ha_notice.cli import main
from ha_notice.gateway import ConnectSpec, HomeLookupError, SourceError, build_tls_context
from tests.fake_gateway import ConnectionScript, FakeExit, FakeGateway, StallingSource

SPEC = ConnectSpec(
    "https", "ha.example", 8123, connect_timeout=3.0, io_timeout=10.0, tls=build_tls_context([])
)


def test_clock_is_scripted_and_sleep_advances_it() -> None:
    g = FakeGateway()
    t0 = g.monotonic()
    g.sleep(2.0)
    g.sleep(4.0)
    assert g.monotonic() == t0 + 6.0
    assert g.sleeps == [2.0, 4.0]
    assert g.wall_time() > 1_000_000_000


def test_resolution_failure_on_demand() -> None:
    g = FakeGateway()
    g.resolve_errors["ha.example"] = socket.gaierror(-2, "Name or service not known")
    conn = g.connect(SPEC)
    with pytest.raises(socket.gaierror):
        conn.connect()
    assert g.resolve_calls == [("ha.example", 8123)]


def test_blocked_connect_proceeds_only_when_released() -> None:
    g = FakeGateway()
    gate = threading.Event()
    g.scripts.append(ConnectionScript(connect_block=gate))
    conn = g.connect(SPEC)
    done = threading.Event()

    def worker() -> None:
        conn.connect()
        done.set()

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    assert not done.wait(0.2)
    assert conn.bytes_written == 0
    gate.set()
    t.join(timeout=5)
    assert done.is_set()


def test_stall_after_the_first_byte() -> None:
    g = FakeGateway()
    release = threading.Event()
    g.scripts.append(ConnectionScript(body=b"[]", stall_after_first_byte=release))
    conn = g.connect(SPEC)
    conn.connect()
    conn.request("GET", "/api/", None, {})
    resp = conn.getresponse()
    assert resp.read(1024) == b"["
    got: list[bytes] = []
    t = threading.Thread(target=lambda: got.append(resp.read(1024)), daemon=True)
    t.start()
    t.join(0.2)
    assert t.is_alive() and got == []
    release.set()
    t.join(5)
    assert got == [b"]"]


def test_request_error_records_partial_bytes() -> None:
    g = FakeGateway()
    g.scripts.append(
        ConnectionScript(request_error=BrokenPipeError(32, "pipe"), request_bytes_before_error=5)
    )
    conn = g.connect(SPEC)
    conn.connect()
    with pytest.raises(BrokenPipeError):
        conn.request("POST", "/x", b"body", {})
    assert conn.bytes_written == 5


def test_response_before_request_is_an_error_like_http_client() -> None:
    conn = FakeGateway().connect(SPEC)
    conn.connect()
    with pytest.raises(http.client.ResponseNotReady):
        conn.getresponse()


def test_scripts_are_consumed_in_order_then_default() -> None:
    g = FakeGateway()
    g.scripts.append(ConnectionScript(status=429))
    g.scripts.append(ConnectionScript(status=500))
    statuses = []
    for _ in range(3):
        c = g.connect(SPEC)
        c.connect()
        c.request("GET", "/", None, {})
        statuses.append(c.getresponse().status)
    assert statuses == [429, 500, 200]
    assert len(g.connections) == 3


def test_connect_delay_advances_the_clock() -> None:
    g = FakeGateway()
    g.scripts.append(ConnectionScript(connect_delay=2.5))
    t0 = g.monotonic()
    g.connect(SPEC).connect()
    assert g.monotonic() == t0 + 2.5


def test_home_and_uid_are_scripted() -> None:
    g = FakeGateway(home="/h", user_id=7, login="u")
    assert (g.home_dir(), g.uid(), g.login_name()) == ("/h", 7, "u")
    g.home = HomeLookupError("lookup failed")
    with pytest.raises(HomeLookupError):
        g.home_dir()


def test_read_source_scripts_match_the_real_semantics() -> None:
    g = FakeGateway()
    g.sources[0] = b"abc"
    g.sources["big"] = b"x" * 11
    g.sources["gone"] = SourceError("unusable")
    g.sources["stall"] = StallingSource(b"1234567890")
    assert g.read_source(0, 10, lambda: 5.0).data == b"abc"
    r = g.read_source("big", 10, lambda: 5.0)
    assert (len(r.data), r.status) == (10, "too_large")
    with pytest.raises(SourceError):
        g.read_source("gone", 10, lambda: 5.0)
    deadline = g.monotonic() + 1.0
    r = g.read_source("stall", 100, lambda: deadline - g.monotonic())
    assert (r.data, r.status) == (b"1234567890", "timeout")
    assert g.monotonic() >= deadline


def test_exit_process_raises_instead_of_exiting() -> None:
    g = FakeGateway()
    with pytest.raises(FakeExit) as exc:
        g.exit_process(12)
    assert exc.value.code == 12 and g.exits == [12]


def test_the_default_uid_is_the_real_one(monkeypatch: pytest.MonkeyPatch) -> None:
    assert FakeGateway().uid() == os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: 4242)
    assert FakeGateway().uid() == 4242


def test_state_dir_works_on_a_private_home(tmp_path: Path) -> None:
    g = FakeGateway()
    fd = g.open_state_dir(str(tmp_path))
    g.close_fd(fd)
    assert (tmp_path / ".local" / "state" / "ha-notice").is_dir()


class _Tripwire:
    """A gateway that fails on any use (``main`` must not touch it for a usage error)."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the gateway was touched: {name}")


def test_main_usage_error_touches_no_gateway_method() -> None:
    # The tripwire also covers every usage error in tests/test_cli.py; env and gateway reach the
    # handlers through cli.Invocation (test_env_and_gateway_reach_the_handler).
    assert main(["--json"], {}, _Tripwire()) == 2  # type: ignore[arg-type]
    assert main([], {}, _Tripwire()) == 2  # type: ignore[arg-type]


def test_the_tripwire_does_trip() -> None:
    with pytest.raises(AssertionError):
        _Tripwire().resolve("x", 1)


def test_main_accepts_the_old_call_shape() -> None:
    assert main(["--json"]) == 2


def test_response_read_error_is_scripted_after_some_bytes() -> None:
    g = FakeGateway()
    g.scripts.append(
        ConnectionScript(body=b"abcdef", read_error=TimeoutError("timed out"), read_error_after=3)
    )
    conn = g.connect(SPEC)
    conn.connect()
    conn.request("GET", "/", None, {})
    resp = conn.getresponse()
    assert resp.read(2) == b"ab"
    assert resp.read(10) == b"c"
    with pytest.raises(TimeoutError):
        resp.read(10)


def test_short_body_raises_incomplete_read() -> None:
    g = FakeGateway()
    g.scripts.append(ConnectionScript(body=b"abcd", declared_length=100))
    conn = g.connect(SPEC)
    conn.connect()
    conn.request("GET", "/", None, {})
    resp = conn.getresponse()
    assert resp.read(10) == b"abcd"
    with pytest.raises(http.client.IncompleteRead):
        resp.read(10)


def test_read_minus_one_reads_to_eof() -> None:
    g = FakeGateway()
    g.scripts.append(ConnectionScript(body=b"abcdef"))
    conn = g.connect(SPEC)
    conn.connect()
    conn.request("GET", "/", None, {})
    assert conn.getresponse().read(-1) == b"abcdef"


def test_state_file_truncate_matches_the_real_gateway(tmp_path: Path) -> None:
    g = FakeGateway(home=str(tmp_path))
    dir_fd = g.open_state_dir(str(tmp_path))
    fd = g.open_state_file(dir_fd, "log.jsonl", append=True)
    try:
        g.write_fd(fd, b"abcdef")
        g.state_file_truncate(fd, 3)
        assert g.state_file_size(fd) == 3
    finally:
        g.close_fd(fd)
        g.close_fd(dir_fd)
