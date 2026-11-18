"""Log records, the outcome rule, the lock and rotation (issue #21).

Everything runs on a private tmp home passed through the gateway; ``HOME`` and ``XDG_STATE_HOME``
point at a trap directory that must stay empty. Tests that start processes record the Popen
objects and kill only those.
"""

from __future__ import annotations

import dataclasses
import io
import json
import os
import signal
import stat
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from ha_notice import log as logmod
from ha_notice.gateway import RealGateway, StateDirError
from ha_notice.log import (
    LOCK_NAME,
    LOG_NAME,
    RunFacts,
    build_record,
    format_ts,
    outcome_for,
    serialize_record,
    write_log_record,
)
from ha_notice.render import dedupe_key_sha256, message_sha256
from ha_notice.state import STATE_WARNING, StateWarner
from tests.fake_gateway import FakeGateway
from tests.harness import Golden, load_schema, schema_errors

STATE_REL = Path(".local") / "state" / "ha-notice"
MIB = 1024 * 1024
ERROR_CODES: list[str] = load_schema("defs")["$defs"]["error_code"]["enum"]
REASONS: list[str] = load_schema("defs")["$defs"]["refusal_reason"]["enum"]


@pytest.fixture(autouse=True)
def _alarm(request: pytest.FixtureRequest) -> Iterator[None]:
    def boom(*_: Any) -> None:
        raise AssertionError("blocked")

    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(90 if request.node.get_closest_marker("long_alarm") else 20)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


@pytest.fixture
def trap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    t = tmp_path / "trap"
    t.mkdir()
    monkeypatch.setenv("HOME", str(t))
    monkeypatch.setenv("XDG_STATE_HOME", str(t))
    return t


@pytest.fixture
def home(tmp_path: Path, trap: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir(mode=0o700)
    return h


@pytest.fixture
def sdir(home: Path) -> Path:
    d = home / STATE_REL
    d.mkdir(parents=True, mode=0o700)
    return d


def facts(**kw: Any) -> RunFacts:
    base: dict[str, Any] = {
        "exit_code": 0,
        "unknown_outcome": False,
        "code": None,
        "reason": None,
        "level": "info",
        "bytes": 42,
        "truncated": False,
        "duration_ms": 120,
        "http_status": 200,
        "message_sha256": "0123456789abcdef",
        "dedupe_key_sha256": None,
        "tag_set": False,
        "actor": "auto:cron",
        "actor_source": "default",
    }
    base.update(kw)
    return RunFacts(**base)


def run(gateway: FakeGateway, f: RunFacts | None = None) -> str:
    """Write one record; return what the warner printed."""
    buf = io.StringIO()
    write_log_record(gateway, f or facts(), StateWarner(buf), version="0.1.0")
    return buf.getvalue()


def lines(path: Path) -> list[dict[str, Any]]:
    data = path.read_bytes()
    assert data == b"" or data.endswith(b"\n")
    return [json.loads(x) for x in data.splitlines()]


def fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


def mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


# --- the outcome rule ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "exit_code,unknown,expected",
    [
        (0, False, "sent"),
        (20, False, "refused"),
        (12, False, "failed"),
        (12, True, "outcome_unknown"),
        (1, True, "outcome_unknown"),
        (1, False, None),
        (2, False, None),
        (2, True, None),
        (22, False, None),
        (130, False, None),
        (143, True, None),
        (255, True, None),
        (3, False, None),
        (-1, False, None),
    ],
)
def test_outcome_rule(exit_code: int, unknown: bool, expected: str | None) -> None:
    assert outcome_for(exit_code, unknown) == expected


@pytest.mark.parametrize("code", ERROR_CODES)
def test_unavailable_is_failed_and_unknown_outcome_wins(code: str) -> None:
    # any exit 12 code: unknown_outcome decides, the code never does
    assert outcome_for(12, False) == "failed"
    assert outcome_for(12, True) == "outcome_unknown"


# --- the record ----------------------------------------------------------------------------


def valid(record: dict[str, Any]) -> None:
    assert schema_errors("log", record) == []


def test_sent_record_matches_the_schema() -> None:
    rec = build_record(facts(), ts="2023-11-14T22:13:20.123Z", version="0.1.0")
    assert rec is not None
    valid(rec)
    assert rec["outcome"] == "sent" and rec["exit"] == 0 and rec["code"] is None


def test_refused_record_has_code_refused_and_the_reason() -> None:
    f = facts(exit_code=20, reason="empty_message", code="refused", http_status=None)
    rec = build_record(f, ts="2023-11-14T22:13:20.123Z", version="0.1.0")
    assert rec is not None
    valid(rec)
    assert (rec["outcome"], rec["code"], rec["reason"]) == ("refused", "refused", "empty_message")


@pytest.mark.parametrize("reason", REASONS)
def test_every_refusal_reason_validates(reason: str) -> None:
    rec = build_record(facts(exit_code=20, reason=reason), ts="2023-11-14T22:13:20.123Z")
    assert rec is not None
    valid(rec)
    assert rec["code"] == "refused"


@pytest.mark.parametrize(
    "code",
    [
        "host_rejected",
        "auth_required",
        "credential_invalid",
        "rate_limited",
        "network_error",
        "unavailable",
        "wrong_host_response",
    ],
)
def test_failed_records_validate(code: str) -> None:
    rec = build_record(facts(exit_code=12, code=code), ts="2023-11-14T22:13:20.123Z")
    assert rec is not None
    valid(rec)
    assert rec["outcome"] == "failed" and rec["code"] == code


@pytest.mark.parametrize("code", ["outcome_unknown", "upstream_error", "wrong_host_response"])
def test_outcome_unknown_records_validate(code: str) -> None:
    f = facts(exit_code=12, code=code, unknown_outcome=True)
    rec = build_record(f, ts="2023-11-14T22:13:20.123Z")
    assert rec is not None
    valid(rec)
    assert rec["outcome"] == "outcome_unknown" and rec["code"] == code


def test_exit_1_after_writing_is_logged_as_internal() -> None:
    f = facts(exit_code=1, code="internal", unknown_outcome=True, http_status=None)
    rec = build_record(f, ts="2023-11-14T22:13:20.123Z")
    assert rec is not None
    valid(rec)
    assert (rec["outcome"], rec["exit"], rec["code"]) == ("outcome_unknown", 1, "internal")


def test_exit_1_code_is_internal_whatever_the_caller_passed() -> None:
    f = facts(exit_code=1, code=None, unknown_outcome=True)
    rec = build_record(f, ts="2023-11-14T22:13:20.123Z")
    assert rec is not None
    assert rec["code"] == "internal"
    valid(rec)


@pytest.mark.parametrize("exit_code", [1, 2, 22, 130, 143])
def test_unlogged_exits_build_no_record(exit_code: int) -> None:
    assert build_record(facts(exit_code=exit_code), ts="2023-11-14T22:13:20.123Z") is None


def test_reason_is_null_unless_exit_20() -> None:
    rec = build_record(facts(exit_code=12, code="network_error", reason="empty_message"), ts="x")
    assert rec is not None and rec["reason"] is None


def test_field_order_and_set_match_the_schema() -> None:
    rec = build_record(facts(), ts="2023-11-14T22:13:20.123Z", version="0.1.0")
    assert rec is not None
    assert list(rec) == list(load_schema("log")["properties"])


def test_unknown_outcome_on_a_success_is_still_sent() -> None:
    rec = build_record(facts(unknown_outcome=True), ts="2023-11-14T22:13:20.123Z")
    assert rec is not None and rec["outcome"] == "sent"
    valid(rec)


# --- ts ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "t,expected",
    [
        (0.0, "1970-01-01T00:00:00.000Z"),
        (1_700_000_000.123, "2023-11-14T22:13:20.123Z"),
        (1_700_000_000.9996, "2023-11-14T22:13:21.000Z"),  # rounds across the second
        (1_700_000_000.0004, "2023-11-14T22:13:20.000Z"),
        (1_700_000_000.001, "2023-11-14T22:13:20.001Z"),
        (951_782_400.5, "2000-02-29T00:00:00.500Z"),
        (253_402_300_799.0, "9999-12-31T23:59:59.000Z"),
    ],
)
def test_ts_is_utc_with_milliseconds(t: float, expected: str) -> None:
    assert format_ts(t) == expected


@pytest.mark.parametrize("t", [-1.0, float("nan"), float("inf"), 1e18, 253_402_300_800.0])
def test_ts_out_of_range_is_a_value_error(t: float) -> None:
    with pytest.raises(ValueError):
        format_ts(t)


def test_ts_ignores_the_local_timezone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TZ", "Asia/Tokyo")
    time.tzset()
    try:
        assert format_ts(1_700_000_000.0) == "2023-11-14T22:13:20.000Z"
    finally:
        monkeypatch.delenv("TZ")
        time.tzset()


def test_ts_comes_from_the_wall_clock_not_the_monotonic_one(home: Path, sdir: Path) -> None:
    g = FakeGateway(home=str(home), now=5.0, wall=1_700_000_000.123)
    # wall_time = wall + (now - 1000) in the fake; the record uses wall_time only
    run(g)
    (rec,) = lines(sdir / LOG_NAME)
    assert rec["ts"] == format_ts(g.wall_time())
    assert rec["ts"].endswith("Z")


# --- serialization and hostile values ------------------------------------------------------


def test_line_is_compact_ascii_json_with_one_final_lf() -> None:
    rec = build_record(facts(), ts="2023-11-14T22:13:20.123Z", version="0.1.0")
    assert rec is not None
    data = serialize_record(rec)
    assert data.endswith(b"\n") and data.count(b"\n") == 1
    assert b": " not in data and b", " not in data
    assert all(0x20 <= b < 0x7F for b in data[:-1])


@pytest.mark.parametrize(
    "actor", ["auto:x\ny", "auto:x\ry", "auto: x", "auto:\x00", "auto:é", "auto:\x1b[31m"]
)
def test_hostile_values_never_add_a_raw_control_character_or_line(actor: str) -> None:
    rec = build_record(facts(actor=actor), ts="2023-11-14T22:13:20.123Z", version="0.1.0")
    assert rec is not None
    data = serialize_record(rec)
    assert data.count(b"\n") == 1 and data[-1:] == b"\n"
    assert not any(b < 0x20 or b > 0x7E for b in data[:-1])
    assert json.loads(data)["actor"] == actor  # the value round-trips; escaping did the work


def test_a_huge_record_is_not_written(home: Path, sdir: Path) -> None:
    out = run(FakeGateway(home=str(home)), facts(actor="auto:" + "a" * 5000))
    assert out == STATE_WARNING + "\n"
    assert not (sdir / LOG_NAME).exists() or (sdir / LOG_NAME).stat().st_size == 0


def test_every_record_is_under_one_kib_at_the_schema_maximum() -> None:
    f = facts(
        exit_code=12,
        code="wrong_host_response",
        unknown_outcome=True,
        actor="auto:" + "a" * 64,
        http_status=599,
        bytes=10**9,
        duration_ms=10**12,
        level="action",
    )
    rec = build_record(f, ts="2023-11-14T22:13:20.123Z", version="v" * 64)
    assert rec is not None
    valid(rec)
    assert len(serialize_record(rec)) < 1024


def test_version_is_cut_to_the_schema_limit() -> None:
    rec = build_record(facts(), ts="2023-11-14T22:13:20.123Z", version="v" * 100)
    assert rec is not None
    assert len(rec["version"]) == 64
    valid(rec)


# --- writing -------------------------------------------------------------------------------


def test_a_record_is_appended_as_one_line_with_mode_0600(home: Path, sdir: Path) -> None:
    g = FakeGateway(home=str(home), wall=1_700_000_000.123)
    assert run(g) == ""
    assert run(g, facts(exit_code=20, reason="invalid_payload")) == ""
    recs = lines(sdir / LOG_NAME)
    assert [r["outcome"] for r in recs] == ["sent", "refused"]
    for r in recs:
        valid(r)
    assert mode(sdir / LOG_NAME) == 0o600
    assert mode(sdir / LOCK_NAME) == 0o600


def test_the_state_directory_is_created_when_missing(home: Path, trap: Path) -> None:
    assert run(FakeGateway(home=str(home))) == ""
    assert len(lines(home / STATE_REL / LOG_NAME)) == 1
    assert list(trap.iterdir()) == []  # HOME and XDG_STATE_HOME are not read


def test_an_unlogged_exit_touches_nothing(home: Path) -> None:
    assert run(FakeGateway(home=str(home)), facts(exit_code=2)) == ""
    assert not (home / ".local").exists()


def test_descriptors_do_not_leak_on_success_or_failure(home: Path, sdir: Path) -> None:
    g = FakeGateway(home=str(home))
    before = fd_count()
    for _ in range(5):
        run(g)
    (sdir / LOCK_NAME).unlink()
    os.mkfifo(sdir / LOCK_NAME)
    for _ in range(5):
        assert run(g) == STATE_WARNING + "\n"
    assert fd_count() == before


@pytest.mark.parametrize(
    "name,kind,facts_kw",
    [
        ("sent", "ok", {}),
        ("refused", "ok", {"exit_code": 20, "reason": "empty_message", "http_status": None}),
        (
            "failed",
            "ok",
            {"exit_code": 12, "code": "network_error", "http_status": None, "bytes": 193},
        ),
        (
            "outcome-unknown",
            "ok",
            {
                "exit_code": 12,
                "code": "upstream_error",
                "unknown_outcome": True,
                "http_status": 502,
            },
        ),
        (
            "internal-after-writing",
            "ok",
            {"exit_code": 1, "code": "internal", "unknown_outcome": True, "http_status": None},
        ),
    ],
)
def test_log_goldens(
    golden: Golden, home: Path, sdir: Path, name: str, kind: str, facts_kw: dict[str, Any]
) -> None:
    g = FakeGateway(home=str(home), wall=1_700_000_000.123)
    run(g, facts(**facts_kw))
    golden.check("log", f"{name}.jsonl", (sdir / LOG_NAME).read_text(), schema="log")


def test_the_golden_with_hashes_is_the_real_hash_of_known_input(
    golden: Golden, home: Path, sdir: Path
) -> None:
    f = facts(
        message_sha256=message_sha256("Backup", "Nightly backup finished"),
        dedupe_key_sha256=dedupe_key_sha256("backup-nightly"),
        tag_set=True,
        level="warn",
        actor="human:alice",
        actor_source="flag",
    )
    run(FakeGateway(home=str(home), wall=1_700_000_000.123), f)
    golden.check("log", "hashes.jsonl", (sdir / LOG_NAME).read_text(), schema="log")


def test_the_log_never_contains_text_url_service_or_token(home: Path, sdir: Path) -> None:
    secret = "SECRET-7f3a-recognizable"
    title = f"title {secret}"
    message = f"message {secret} https://ha.example/{secret}"
    key = f"key-{secret}"
    f = facts(
        message_sha256=message_sha256(title, message),
        dedupe_key_sha256=dedupe_key_sha256(key),
        tag_set=True,
    )
    run(FakeGateway(home=str(home)), f)
    raw = (sdir / LOG_NAME).read_bytes()
    for needle in (secret, "ha.example", "https://", "notify.", "Bearer", title, message, key):
        assert needle.encode() not in raw
    # the record has exactly the schema's fields; nothing else can carry text
    assert set(json.loads(raw)) == set(load_schema("log")["properties"])


def test_runfacts_has_no_free_text_field() -> None:
    names = {f.name for f in dataclasses.fields(RunFacts)}
    assert names.isdisjoint({"title", "message", "link", "url", "base_url", "service", "token"})


# --- the unusable state ---------------------------------------------------------------------


def test_an_unusable_state_directory_warns_once_and_writes_nothing(home: Path) -> None:
    g = FakeGateway(home=str(home), state_error=StateDirError("x"))
    buf = io.StringIO()
    w = StateWarner(buf)
    write_log_record(g, facts(), w)
    write_log_record(g, facts(), w)  # a second failure in the same run stays silent
    assert buf.getvalue() == STATE_WARNING + "\n"
    assert not (home / ".local").exists()


@pytest.mark.parametrize("name", [LOG_NAME, LOCK_NAME])
def test_a_fifo_returns_at_once_with_one_warning(home: Path, sdir: Path, name: str) -> None:
    os.mkfifo(sdir / name)
    started = time.monotonic()
    out = run(FakeGateway(home=str(home)))
    assert time.monotonic() - started < 2
    assert out == STATE_WARNING + "\n"


@pytest.mark.parametrize("name", [LOG_NAME, LOCK_NAME])
def test_a_symlinked_entry_is_not_followed(
    home: Path, sdir: Path, tmp_path: Path, name: str
) -> None:
    target = tmp_path / "target"
    target.write_text("keep")
    (sdir / name).symlink_to(target)
    assert run(FakeGateway(home=str(home))) == STATE_WARNING + "\n"
    assert target.read_text() == "keep"


@pytest.mark.parametrize("name", [LOG_NAME, LOCK_NAME])
def test_a_directory_in_place_of_an_entry_warns(home: Path, sdir: Path, name: str) -> None:
    (sdir / name).mkdir()
    assert run(FakeGateway(home=str(home))) == STATE_WARNING + "\n"


@dataclass
class FailingWrites(FakeGateway):
    errno_text: str = "full"
    short: bool = False

    def write_fd(self, fd: int, data: bytes) -> int:
        if self.short:
            return super().write_fd(fd, data[: len(data) // 2])
        raise StateDirError(self.errno_text)


def test_a_write_failure_warns_once_and_releases_the_lock(home: Path, sdir: Path) -> None:
    g = FailingWrites(home=str(home))
    buf = io.StringIO()
    w = StateWarner(buf)
    before = fd_count()
    write_log_record(g, facts(), w)
    write_log_record(g, facts(), w)
    assert buf.getvalue() == STATE_WARNING + "\n"
    assert fd_count() == before
    # the lock is free again: a healthy gateway writes
    assert run(FakeGateway(home=str(home))) == ""
    assert len(lines(sdir / LOG_NAME)) == 1


def test_a_short_write_is_a_failure(home: Path, sdir: Path) -> None:
    out = run(FailingWrites(home=str(home), short=True))
    assert out == STATE_WARNING + "\n"


@dataclass
class BusyLock(FakeGateway):
    free_after: int = 10**9  # try_lock fails this many times, then succeeds
    attempts: int = 0

    def try_lock(self, fd: int) -> bool:
        self.attempts += 1
        if self.attempts <= self.free_after:
            return False
        return super().try_lock(fd)


def test_a_busy_lock_is_polled_every_20_ms_for_about_one_second(home: Path, sdir: Path) -> None:
    g = BusyLock(home=str(home))
    start = g.monotonic()
    out = run(g)
    elapsed = g.monotonic() - start
    assert out == STATE_WARNING + "\n"
    assert 1.0 <= elapsed <= 1.05
    assert set(g.sleeps) == {0.02}
    assert 49 <= g.attempts <= 52
    assert not (sdir / LOG_NAME).exists() or (sdir / LOG_NAME).stat().st_size == 0


def test_a_lock_freed_in_time_is_taken(home: Path, sdir: Path) -> None:
    g = BusyLock(home=str(home), free_after=5)
    assert run(g) == ""
    assert g.attempts == 6 and len(g.sleeps) == 5
    assert len(lines(sdir / LOG_NAME)) == 1


def test_a_lock_freed_on_the_last_attempt_is_taken(home: Path, sdir: Path) -> None:
    g = BusyLock(home=str(home), free_after=49)
    assert run(g) == ""
    assert len(lines(sdir / LOG_NAME)) == 1


_HOLDER = textwrap.dedent(
    """
    import fcntl, os, sys
    fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    print("held", flush=True)
    sys.stdin.readline()
    """
)


class RealClock(FakeGateway):
    """The fake gateway with a real monotonic clock and a real sleep."""

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def _private_env(tmp_path: Path) -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path / "trap")}


@pytest.mark.long_alarm
def test_a_flock_held_by_another_process_skips_the_record_after_about_one_second(
    home: Path, sdir: Path, tmp_path: Path
) -> None:
    holder = subprocess.Popen(
        [sys.executable, "-I", "-c", _HOLDER, str(sdir / LOCK_NAME)],
        env=_private_env(tmp_path),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "held"
        started = time.monotonic()
        out = run(RealClock(home=str(home)))
        elapsed = time.monotonic() - started
        assert out == STATE_WARNING + "\n"
        assert 0.95 <= elapsed < 3.0
        assert not (sdir / LOG_NAME).exists() or (sdir / LOG_NAME).stat().st_size == 0
        # the holder releases: the next record is written
        assert holder.stdin is not None
        holder.stdin.write("\n")
        holder.stdin.flush()
        holder.wait(timeout=10)
        assert run(RealClock(home=str(home))) == ""
        assert len(lines(sdir / LOG_NAME)) == 1
    finally:
        if holder.poll() is None:
            holder.kill()  # only the PID this test started
            holder.wait()


@pytest.mark.long_alarm
def test_a_flock_released_within_the_budget_lets_the_record_through(
    home: Path, sdir: Path, tmp_path: Path
) -> None:
    holder = subprocess.Popen(
        [sys.executable, "-I", "-c", _HOLDER, str(sdir / LOCK_NAME)],
        env=_private_env(tmp_path),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "held"
        assert holder.stdin is not None
        import threading

        def release() -> None:
            time.sleep(0.3)
            holder.stdin.write("\n")  # type: ignore[union-attr]
            holder.stdin.flush()  # type: ignore[union-attr]

        t = threading.Thread(target=release)
        t.start()
        out = run(RealClock(home=str(home)))
        t.join(timeout=10)
        holder.wait(timeout=10)
        assert out == ""
        assert len(lines(sdir / LOG_NAME)) == 1
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait()


# --- rotation ------------------------------------------------------------------------------


def fill(path: Path, size: int, marker: bytes) -> None:
    """A file of exactly ``size`` bytes: whole lines of the marker, then a sparse hole."""
    line = marker + b"\n"
    with path.open("wb") as fh:
        fh.write(line)
        fh.truncate(size)
    path.chmod(0o600)


def test_a_log_just_under_the_limit_is_appended_to(home: Path, sdir: Path) -> None:
    fill(sdir / LOG_NAME, MIB - 1, b"old")
    run(FakeGateway(home=str(home)))
    assert not (sdir / "log.jsonl.1").exists()
    assert (sdir / LOG_NAME).stat().st_size > MIB - 1


def test_a_log_of_exactly_the_limit_is_rotated(home: Path, sdir: Path) -> None:
    fill(sdir / LOG_NAME, MIB, b"old")
    run(FakeGateway(home=str(home)))
    assert (sdir / "log.jsonl.1").stat().st_size == MIB
    assert (sdir / "log.jsonl.1").read_bytes().startswith(b"old\n")
    assert len(lines(sdir / LOG_NAME)) == 1  # the record is in the NEW log.jsonl, not in .1
    assert mode(sdir / LOG_NAME) == 0o600 and mode(sdir / "log.jsonl.1") == 0o600


def test_the_first_rotation_creates_no_other_files(home: Path, sdir: Path) -> None:
    fill(sdir / LOG_NAME, MIB + 5, b"old")
    run(FakeGateway(home=str(home)))
    assert sorted(p.name for p in sdir.iterdir()) == [
        "log.jsonl",
        "log.jsonl.1",
        "log.lock",
    ]


def test_rotation_shifts_the_whole_chain_and_drops_the_oldest(home: Path, sdir: Path) -> None:
    fill(sdir / LOG_NAME, MIB, b"cur")
    for n in (1, 2, 3):
        (sdir / f"log.jsonl.{n}").write_bytes(f"gen{n}\n".encode())
        (sdir / f"log.jsonl.{n}").chmod(0o600)
    run(FakeGateway(home=str(home)))
    assert (sdir / "log.jsonl.1").read_bytes().startswith(b"cur\n")
    assert (sdir / "log.jsonl.2").read_bytes() == b"gen1\n"
    assert (sdir / "log.jsonl.3").read_bytes() == b"gen2\n"  # gen3 is gone
    assert not (sdir / "log.jsonl.4").exists()
    for n in (1, 2, 3):
        assert mode(sdir / f"log.jsonl.{n}") == 0o600


def test_rotation_with_gaps_in_the_chain(home: Path, sdir: Path) -> None:
    fill(sdir / LOG_NAME, MIB, b"cur")
    (sdir / "log.jsonl.2").write_bytes(b"gen2\n")
    run(FakeGateway(home=str(home)))
    assert (sdir / "log.jsonl.1").read_bytes().startswith(b"cur\n")
    assert not (sdir / "log.jsonl.2").exists()
    assert (sdir / "log.jsonl.3").read_bytes() == b"gen2\n"


def test_a_huge_log_is_rotated_without_being_read(home: Path, sdir: Path) -> None:
    fill(sdir / LOG_NAME, 4 * 1024 * MIB, b"old")  # 4 GiB, sparse
    started = time.monotonic()
    run(FakeGateway(home=str(home)))
    assert time.monotonic() - started < 2
    assert (sdir / "log.jsonl.1").stat().st_size == 4 * 1024 * MIB


def test_a_rotation_failure_warns_once_and_skips_the_record(home: Path, sdir: Path) -> None:
    fill(sdir / LOG_NAME, MIB, b"old")
    (sdir / "log.jsonl.3").mkdir()  # a non-empty directory cannot be replaced by .2
    (sdir / "log.jsonl.3" / "child").write_text("x")
    (sdir / "log.jsonl.2").write_bytes(b"two\n")
    out = run(FakeGateway(home=str(home)))
    assert out == STATE_WARNING + "\n"
    assert (sdir / LOG_NAME).stat().st_size == MIB  # untouched


def test_rotation_leaves_the_lock_file_alone(home: Path, sdir: Path) -> None:
    fill(sdir / LOG_NAME, MIB, b"old")
    run(FakeGateway(home=str(home)))
    run(FakeGateway(home=str(home)))
    assert (sdir / LOCK_NAME).stat().st_size == 0
    assert not (sdir / "log.lock.1").exists()


def test_the_limits_are_those_of_the_interface() -> None:
    assert logmod.ROTATE_AT == 1024 * 1024
    assert logmod.KEPT == 3
    assert logmod.LOCK_BUDGET == 1.0 and logmod.LOCK_POLL == 0.02
    assert logmod.MAX_RECORD == 1024


_WORKER = textwrap.dedent(
    """
    import io, sys
    from ha_notice import log
    from ha_notice.gateway import RealGateway
    from ha_notice.state import StateWarner

    class G(RealGateway):
        def home_dir(self):
            return sys.argv[1]

    log.ROTATE_AT = int(sys.argv[3])
    worker, count = int(sys.argv[2]), int(sys.argv[4])
    sys.stdin.readline()  # the start signal
    warn = io.StringIO()
    g = G()
    for i in range(count):
        f = log.RunFacts(
            exit_code=0, unknown_outcome=False, code=None, reason=None, level="info",
            bytes=1, truncated=False, duration_ms=worker * 100000 + i, http_status=200,
            message_sha256=None, dedupe_key_sha256=None, tag_set=False,
            actor="auto:w", actor_source="default",
        )
        log.write_log_record(g, f, StateWarner(warn), version="0.1.0")
    sys.stdout.write(str(warn.getvalue().count("warning")))
    """
)


@pytest.mark.long_alarm
def test_concurrent_writers_rotating_lose_no_record_and_never_double_rotate(
    home: Path, sdir: Path, tmp_path: Path
) -> None:
    workers, per_worker, limit = 4, 60, 30_000
    procs = [
        subprocess.Popen(
            [sys.executable, "-I", "-c", _WORKER, str(home), str(w), str(limit), str(per_worker)],
            env=_private_env(tmp_path),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for w in range(workers)
    ]
    try:
        for p in procs:
            assert p.stdin is not None
            p.stdin.write("go\n")
            p.stdin.flush()
        results = [(p.communicate(timeout=60), p.returncode) for p in procs]
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()  # only the PIDs this test started
                p.wait()
    assert [r[1] for r in results] == [0] * workers, results
    assert [r[0][0] for r in results] == ["0"] * workers  # no skipped record, no warning
    names = ["log.jsonl", "log.jsonl.1", "log.jsonl.2", "log.jsonl.3"]
    seen: list[int] = []
    for n in names:
        p = sdir / n
        if not p.exists():
            continue
        data = p.read_bytes()
        assert data.endswith(b"\n")
        assert len(data) <= limit + 1024  # rotated as soon as a file reached the limit
        for rec in lines(p):
            valid(rec)
            seen.append(rec["duration_ms"])
    expected = {w * 100000 + i for w in range(workers) for i in range(per_worker)}
    assert len(seen) == len(set(seen))  # no duplicates
    assert set(seen) == expected  # none lost
    assert (sdir / "log.jsonl.1").exists()  # rotation really happened
    # a double rotation would leave a nearly empty rotated file
    for n in names[1:]:
        if (sdir / n).exists():
            assert (sdir / n).stat().st_size >= limit
    assert not (sdir / "log.jsonl.4").exists()
    assert mode(sdir / "log.jsonl.1") == 0o600


def test_home_and_xdg_state_home_are_ignored(home: Path, trap: Path) -> None:
    run(FakeGateway(home=str(home)))
    assert list(trap.iterdir()) == []


def test_real_gateway_home_comes_from_the_password_database(
    home: Path, trap: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class G(RealGateway):
        def home_dir(self) -> str:
            return str(home)

    buf = io.StringIO()
    write_log_record(G(), facts(), StateWarner(buf), version="0.1.0")
    assert buf.getvalue() == ""
    assert len(lines(home / STATE_REL / LOG_NAME)) == 1
    assert list(trap.iterdir()) == []
