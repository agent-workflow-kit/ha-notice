"""Log records, the outcome rule, the lock and rotation (docs/interface.md, Log).

``RunFacts`` is what the run knows when its result is fixed; it has no free-text field, so a
record cannot carry a title, message, link, URL, service or token (only the two 16-hex hashes
and the schema's enums and integers). ``write_log_record`` is the log step: it runs after the
result is printed and flushed, outside the deadline, and bounded by the lock budget.

The lock is a non-blocking ``flock`` on ``log.lock`` polled every 20 ms for at most 1 s, taken
before ``log.jsonl`` is opened, so the size check, the rotation and the append are one critical
section across processes and the file opened is the one that exists after any other process's
rotation. Any state problem prints the fixed warning once and never raises.

A record whose facts break the schema's rules (an enum, the outcome/code/reason matrix, a hash
or actor grammar, a range) is never written: ``build_record`` raises ``ValueError`` and the step
warns once. A short or failed write is cut back (best effort) to the size before it, so no
partial line is left for the next record to be glued to.

TODO(#27): call ``write_log_record`` from ``send.deliver`` after the result is printed (and skip
it when config ``log`` is false); the signal exits (128+N) are never logged (#26). The criteria
that need ``send.py`` are deferred to #27 with it: the result is printed and flushed before the
log step; the log step stays within timeout + 3 s with the lock held by another process;
``log: false`` and dry runs touch nothing; and the send-level checks (a FIFO or symlinked log
entry costs one warning, never a hang or a changed exit code).
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ha_notice import __version__
from ha_notice.gateway import Gateway
from ha_notice.state import StateUnusable, StateWarner, open_state

__all__ = [
    "KEPT",
    "LOCK_BUDGET",
    "LOCK_NAME",
    "LOCK_POLL",
    "LOG_NAME",
    "MAX_RECORD",
    "ROTATE_AT",
    "RunFacts",
    "build_record",
    "format_ts",
    "outcome_for",
    "serialize_record",
    "write_log_record",
]

LOG_NAME = "log.jsonl"
LOCK_NAME = "log.lock"
ROTATE_AT = 1024 * 1024  # a log this size or larger is rotated (module value: tests lower it)
KEPT = 3  # log.jsonl.1 .. log.jsonl.3
LOCK_POLL = 0.02
LOCK_BUDGET = 1.0
MAX_RECORD = 1024  # a record is written only when it is shorter than this
_VERSION_MAX = 64
_MAX_TS = 253_402_300_799  # 9999-12-31T23:59:59Z

# The schema's rules (schemas/defs.json, schemas/log.json); tests pin these to the schema files.
LEVELS = ("info", "warn", "action", "error")
ACTOR_SOURCES = ("flag", "tty", "default")
REASONS = ("invalid_payload", "empty_message", "command_keyword", "link_invalid", "link_scheme")
FAILED_CODES = (
    "host_rejected",
    "auth_required",
    "credential_invalid",
    "rate_limited",
    "network_error",
    "wrong_host_response",
    "unavailable",
)
UNKNOWN_CODES = ("outcome_unknown", "upstream_error", "wrong_host_response")
_SHA16 = re.compile(r"[0-9a-f]{16}\Z")
_ACTOR = re.compile(r"(human|auto):[A-Za-z0-9._@/-]{1,64}\Z")


@dataclass(frozen=True)
class RunFacts:
    """The facts of one finished run; ``exit_code`` is the code the process will return."""

    exit_code: int
    unknown_outcome: bool
    code: str | None
    reason: str | None
    level: str | None
    bytes: int | None
    truncated: bool | None
    duration_ms: int
    http_status: int | None
    message_sha256: str | None
    dedupe_key_sha256: str | None
    tag_set: bool | None
    actor: str
    actor_source: str


def outcome_for(exit_code: int, unknown_outcome: bool) -> str | None:
    """The log outcome of an exit, or None when the run is not logged.

    ``unknown_outcome`` decides every exit 12 and exit 1; exit 1 without it (the request was
    never started), exit 2, 22 and signal exits are not logged.
    """
    if exit_code == 0:
        return "sent"
    if exit_code == 20:
        return "refused"
    if exit_code == 12:
        return "outcome_unknown" if unknown_outcome else "failed"
    if exit_code == 1 and unknown_outcome:
        return "outcome_unknown"
    return None


def format_ts(wall_time: float) -> str:
    """``YYYY-MM-DDTHH:MM:SS.mmmZ`` in UTC to the millisecond; ValueError when out of range."""
    if not math.isfinite(wall_time):
        raise ValueError("wall time is not finite")
    total_ms = round(wall_time * 1000)
    seconds, ms = divmod(total_ms, 1000)
    if not 0 <= seconds <= _MAX_TS:
        raise ValueError("wall time is out of range")
    return datetime.fromtimestamp(seconds, UTC).strftime("%Y-%m-%dT%H:%M:%S") + f".{ms:03d}Z"


def build_record(facts: RunFacts, *, ts: str, version: str = __version__) -> dict[str, Any] | None:
    """The record for a run (keys in schema order), or None when the run is not logged.

    Raises ``ValueError`` when the facts would make a record that breaks the schema.
    """
    outcome = outcome_for(facts.exit_code, facts.unknown_outcome)
    if outcome is None:
        return None
    if facts.exit_code == 20:
        code: str | None = "refused"
        reason = facts.reason
    elif facts.exit_code == 1:
        code, reason = "internal", None
    elif facts.exit_code == 12:
        code, reason = facts.code, None
    else:
        code, reason = None, None
    _check_facts(facts, outcome, code, reason)
    return {
        "ts": ts,
        "tool": "ha-notice",
        "version": version[:_VERSION_MAX],
        "outcome": outcome,
        "exit": facts.exit_code,
        "code": code,
        "reason": reason,
        "level": facts.level,
        "bytes": facts.bytes,
        "truncated": facts.truncated,
        "duration_ms": facts.duration_ms,
        "http_status": facts.http_status,
        "message_sha256": facts.message_sha256,
        "dedupe_key_sha256": facts.dedupe_key_sha256,
        "tag_set": facts.tag_set,
        "actor": facts.actor,
        "actor_source": facts.actor_source,
    }


def _is_int(value: object, low: int, high: int | None = None) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= low
        and (high is None or value <= high)
    )


def _check_facts(facts: RunFacts, outcome: str, code: object, reason: object) -> None:
    """Raise ValueError unless the record would satisfy schemas/log.json."""
    if outcome == "failed":
        ok = code in FAILED_CODES
    elif outcome == "outcome_unknown":
        ok = code == "internal" if facts.exit_code == 1 else code in UNKNOWN_CODES
    elif outcome == "refused":
        ok = code == "refused" and reason in REASONS
    else:
        ok = code is None
    if not ok:
        raise ValueError("code and reason do not fit the outcome")
    checks = (
        facts.level is None or facts.level in LEVELS,
        facts.bytes is None or _is_int(facts.bytes, 0),
        facts.truncated is None or isinstance(facts.truncated, bool),
        _is_int(facts.duration_ms, 0),
        facts.http_status is None or _is_int(facts.http_status, 100, 599),
        facts.message_sha256 is None
        or (isinstance(facts.message_sha256, str) and _SHA16.match(facts.message_sha256)),
        facts.dedupe_key_sha256 is None
        or (isinstance(facts.dedupe_key_sha256, str) and _SHA16.match(facts.dedupe_key_sha256)),
        facts.tag_set is None or isinstance(facts.tag_set, bool),
        isinstance(facts.actor, str) and _ACTOR.match(facts.actor),
        facts.actor_source in ACTOR_SOURCES,
    )
    if not all(checks):
        raise ValueError("a fact breaks the log schema")


def serialize_record(record: dict[str, Any]) -> bytes:
    """One compact, pure-ASCII JSON line ending in LF (control characters are escaped)."""
    return json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def write_log_record(
    gateway: Gateway, facts: RunFacts, warner: StateWarner, *, version: str = __version__
) -> None:
    """Append the run's record to ``log.jsonl``; never raises, never changes an exit code.

    Any ``Exception`` (not ``BaseException``: an interrupt still propagates, with the
    descriptors closed) becomes the one fixed warning.

    A run that is not logged touches nothing. An unusable state, a lock busy after the budget,
    a failed rotation or write, an over-long record or an impossible clock each print the fixed
    warning (once per run) and write nothing.
    """
    try:
        record = build_record(facts, ts=format_ts(gateway.wall_time()), version=version)
        if record is None:
            return
        line = serialize_record(record)
        if len(line) >= MAX_RECORD:
            raise StateUnusable
        _append(gateway, line)
    except Exception:
        warner.warn()


def _append(gateway: Gateway, line: bytes) -> None:
    state = open_state(gateway)
    lock_fd = log_fd = -1
    try:
        lock_fd = state.open_file(LOCK_NAME)
        deadline = gateway.monotonic() + LOCK_BUDGET
        while not state.try_lock(lock_fd):
            if gateway.monotonic() >= deadline:
                raise StateUnusable
            gateway.sleep(LOCK_POLL)
        log_fd = state.open_file(LOG_NAME, append=True)
        if state.size(log_fd) >= ROTATE_AT:
            state.close_file(log_fd)
            log_fd = -1
            _rotate(state)
            log_fd = state.open_file(LOG_NAME, append=True)  # the record goes to the new file
        _append_line(state, log_fd, line)
    finally:
        if log_fd >= 0:
            state.close_file(log_fd)
        if lock_fd >= 0:
            state.close_file(lock_fd)  # closing releases the flock
        state.close()


def _append_line(state: Any, log_fd: int, line: bytes) -> None:
    """One write; on a short write or an error, cut the file back to its size before it."""
    before = state.size(log_fd)
    try:
        if state.write(log_fd, line) != len(line):
            raise StateUnusable
    except BaseException:
        try:
            state.truncate(log_fd, before)  # the lock is held and the file is O_APPEND
        except Exception:
            pass  # best effort; the warning is still printed once
        raise


def _rotate(state: Any) -> None:
    """``.2`` to ``.3`` (the old ``.3`` is replaced), ``.1`` to ``.2``, ``log.jsonl`` to ``.1``."""
    for n in range(KEPT - 1, 0, -1):
        state.rename(f"{LOG_NAME}.{n}", f"{LOG_NAME}.{n + 1}", missing_ok=True)
    state.rename(LOG_NAME, f"{LOG_NAME}.1")
