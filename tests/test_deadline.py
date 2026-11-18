"""The whole-send deadline (issue #25): the gate, the worker thread and the decision.

Gate tests are deterministic (no threads). Worker tests use scripted attempts on a gateway with a
real monotonic clock whose ``sleep`` can be cut short by the test, so nothing waits longer than
the deadline of about one second. Real-socket tests use the wire-level fake server. Every test
releases what blocks its own worker threads in a fixture.
"""

from __future__ import annotations

import dataclasses
import json
import threading
import time
from collections.abc import Callable, Iterator

import pytest

from ha_notice import deadline as dl
from ha_notice.config import parse_base_url
from ha_notice.deadline import GateRefused, Kind, WritingGate, finish, run_with_deadline
from ha_notice.hass import RawResponse, Target, send_once
from ha_notice.response import ErrorSpec, Gate, Op, Success
from ha_notice.retry import AttemptFacts, AttemptGate, Outcome
from tests.fake_gateway import FakeExit, FakeGateway
from tests.fake_ha import FakeHA, Reply, StallingResolverGateway

TOKEN = "HA_deadline-0123456789"
BODY = json.dumps({"message": "hi"}).encode()
FACTS = AttemptFacts(1, 0, 0, ())
DEADLINE_S = 1.0
SLACK_S = 3.0  # the documented bound beyond the deadline


def ok_outcome() -> Outcome:
    return Outcome(Success(200), FACTS)


def resp(status: int = 200, body: bytes = b"[]") -> RawResponse:
    return RawResponse(status, body, False)


# --- the gate -------------------------------------------------------------------------------


def test_the_gate_implements_the_loop_protocol() -> None:
    gate: AttemptGate = WritingGate()
    assert gate.state() is Gate.IDLE
    assert not gate.abandoned()


def test_idle_to_writing_and_back_after_a_429() -> None:
    gate = WritingGate()
    gate.enter_writing()
    assert gate.state() is Gate.WRITING
    gate.return_to_idle()
    assert gate.state() is Gate.IDLE
    gate.return_to_idle()  # a no-op when idle
    assert gate.state() is Gate.IDLE


def test_an_abandoned_gate_refuses_every_attempt_and_stays_abandoned() -> None:
    gate = WritingGate()
    assert gate.settle().result == ErrorSpec("network_error", {"tls": False, "timeout": True})
    assert gate.abandoned()
    for _ in range(3):
        with pytest.raises(GateRefused):
            gate.enter_writing()
        gate.return_to_idle()
        assert gate.abandoned()
        assert gate.state() is Gate.IDLE


def test_the_refusal_carries_no_text_and_is_a_connect_phase_failure() -> None:
    exc = GateRefused()
    assert isinstance(exc, OSError)
    assert str(exc) == ""


def test_the_deadline_while_idle_is_a_retryable_network_error_not_sent() -> None:
    verdict = WritingGate().settle()
    assert verdict.kind is Kind.DEADLINE and verdict.gate is Gate.IDLE
    assert verdict.worker_may_run
    error = verdict.error(tag_sent=False)
    assert error.exit_code == 12
    body = error.envelope["error"]
    assert body["code"] == "network_error"
    assert body["retryable"] is True and body["unknown_outcome"] is False
    assert body["details"]["timeout"] is True
    assert body["retry_after_s"] is None


def test_the_deadline_while_writing_is_outcome_unknown() -> None:
    gate = WritingGate()
    gate.enter_writing()
    verdict = gate.settle()
    assert verdict.gate is Gate.WRITING
    error = verdict.error(tag_sent=False)
    assert error.exit_code == 12
    body = error.envelope["error"]
    assert body["code"] == "outcome_unknown" and body["unknown_outcome"] is True
    assert body["retryable"] is False
    assert verdict.error(tag_sent=True).envelope["error"]["retryable"] is True


def test_a_writing_gate_is_closed_by_the_decision() -> None:
    gate = WritingGate()
    gate.enter_writing()
    gate.settle()
    gate.return_to_idle()  # a late 429 cannot reopen the gate
    assert gate.state() is Gate.WRITING
    assert gate.abandoned()
    with pytest.raises(GateRefused):
        gate.enter_writing()


def test_a_published_result_wins_over_the_deadline() -> None:
    gate = WritingGate()
    gate.enter_writing()
    assert gate.publish(ok_outcome())
    verdict = gate.settle()
    assert verdict.kind is Kind.COMPLETED
    assert verdict.result == Success(200)
    assert not verdict.worker_may_run


def test_a_result_after_the_decision_is_dropped_and_the_decision_is_final() -> None:
    gate = WritingGate()
    first = gate.settle()
    assert not gate.publish(ok_outcome())
    assert not gate.publish_crash()
    assert gate.settle() is first


def test_only_the_first_result_counts() -> None:
    gate = WritingGate()
    assert gate.publish(ok_outcome())
    assert not gate.publish(Outcome(ErrorSpec("auth_required", {"http_status": 401}), FACTS))
    assert gate.settle().result == Success(200)


def test_a_crash_is_internal_and_unknown_only_after_writing() -> None:
    idle = WritingGate()
    assert idle.publish_crash()
    verdict = idle.settle()
    assert verdict.kind is Kind.CRASH and not verdict.worker_may_run
    error = verdict.error(tag_sent=False)
    assert error.exit_code == 1
    assert error.envelope["error"]["code"] == "internal"
    assert error.envelope["error"]["message"] == "internal error"
    assert error.envelope["error"]["unknown_outcome"] is False

    writing = WritingGate()
    writing.enter_writing()
    writing.publish_crash()
    assert writing.settle().error(tag_sent=False).envelope["error"]["unknown_outcome"] is True


def test_a_probe_verdict_has_no_unknown_outcome() -> None:
    gate = WritingGate()
    gate.enter_writing()
    spec = gate.settle(probe=True).result
    assert isinstance(spec, ErrorSpec) and spec.probe and not spec.unknown_outcome


def test_the_gate_is_exactly_once_under_contention() -> None:
    for _ in range(200):
        gate = WritingGate()
        gate.enter_writing()
        start = threading.Barrier(3)
        results: list[Kind] = []

        def publisher(gate: WritingGate = gate, start: threading.Barrier = start) -> None:
            start.wait()
            gate.publish(ok_outcome())

        def settler(
            gate: WritingGate = gate,
            start: threading.Barrier = start,
            results: list[Kind] = results,
        ) -> None:
            start.wait()
            results.append(gate.settle().kind)

        threads = [threading.Thread(target=publisher), threading.Thread(target=settler)]
        for t in threads:
            t.start()
        start.wait()
        for t in threads:
            t.join(5)
        kind = gate.settle().kind
        assert kind in (Kind.COMPLETED, Kind.DEADLINE)
        assert results == [kind]  # what the settling thread saw is what stays


# --- the worker -----------------------------------------------------------------------------


@dataclasses.dataclass
class ClockGateway(FakeGateway):
    """A fake gateway with a real monotonic clock and a sleep the test can cut short."""

    wake: threading.Event = dataclasses.field(default_factory=threading.Event)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.wake.wait(seconds)


SCALE = 10.0


@dataclasses.dataclass
class ScaledGateway(ClockGateway):
    """A clock running SCALE times faster than real time whose sleep oversleeps (twice as long),
    so a deadline can fall inside a wait that fitted when it started."""

    def monotonic(self) -> float:
        return time.monotonic() * SCALE

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.wake.wait(2 * seconds / SCALE)


@pytest.fixture
def clock() -> Iterator[ScaledGateway]:
    gateway = ScaledGateway()
    try:
        yield gateway
    finally:
        gateway.wake.set()


@pytest.fixture
def release() -> Iterator[threading.Event]:
    event = threading.Event()
    try:
        yield event
    finally:
        event.set()


def run(
    gateway: ClockGateway,
    attempt: Callable[[Callable[[], None]], RawResponse],
    *,
    op: Op = Op.SEND,
    seconds: float = DEADLINE_S,
    gate: WritingGate | None = None,
) -> tuple[dl.Verdict, float]:
    started = time.monotonic()
    verdict = run_with_deadline(
        gateway, attempt, op=op, deadline=gateway.monotonic() + seconds, gate=gate
    )
    return verdict, time.monotonic() - started


def test_a_response_is_returned_at_once() -> None:
    gateway = ClockGateway()
    verdict, took = run(gateway, lambda before_write: (before_write(), resp())[1])
    assert verdict.kind is Kind.COMPLETED and verdict.result == Success(200)
    assert verdict.facts is not None and verdict.facts.requests == 1
    assert took < 0.5
    assert not verdict.worker_may_run


def test_the_worker_is_a_daemon_thread(release: threading.Event) -> None:
    seen: list[threading.Thread] = []

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        seen.append(threading.current_thread())
        before_write()
        return resp()

    run(ClockGateway(), attempt)
    assert len(seen) == 1
    assert seen[0] is not threading.main_thread()
    assert seen[0].daemon is True
    assert seen[0].name == dl.WORKER_NAME


def test_connect_blocked_past_the_deadline_reports_network_error_and_writes_nothing(
    release: threading.Event,
) -> None:
    gate = WritingGate()
    written: list[str] = []
    refused: list[bool] = []
    done = threading.Event()

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        release.wait(10)  # name resolution or connect that outlasts the deadline
        try:
            before_write()
        except GateRefused:
            refused.append(True)
            raise
        finally:
            done.set()
        written.append("bytes")
        return resp()

    verdict, took = run(ClockGateway(), attempt, gate=gate)
    assert verdict.kind is Kind.DEADLINE and verdict.gate is Gate.IDLE
    assert verdict.error(tag_sent=False).exit_code == 12
    body = verdict.error(tag_sent=False).envelope["error"]
    assert body["code"] == "network_error"
    assert body["retryable"] is True and body["unknown_outcome"] is False
    assert DEADLINE_S <= took < DEADLINE_S + SLACK_S
    release.set()  # the connect now proceeds
    assert done.wait(5)
    assert refused == [True] and written == []
    assert gate.settle() is verdict  # the late work changed nothing


def test_a_block_after_the_first_byte_reports_outcome_unknown(release: threading.Event) -> None:
    def attempt(before_write: Callable[[], None]) -> RawResponse:
        before_write()
        release.wait(10)
        return resp()

    verdict, took = run(ClockGateway(), attempt)
    assert verdict.gate is Gate.WRITING
    assert verdict.error(tag_sent=False).envelope["error"]["code"] == "outcome_unknown"
    assert took < DEADLINE_S + SLACK_S


def test_a_late_response_after_a_writing_deadline_does_not_change_the_result(
    release: threading.Event,
) -> None:
    gate = WritingGate()
    finished = threading.Event()

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        before_write()
        release.wait(10)
        finished.set()
        return resp()

    verdict, _ = run(ClockGateway(), attempt, gate=gate)
    release.set()
    assert finished.wait(5)
    time.sleep(0.05)
    assert gate.settle() is verdict
    assert verdict.error(tag_sent=False).envelope["error"]["code"] == "outcome_unknown"


def test_a_429_then_a_deadline_during_the_wait_is_network_error_not_rate_limited(
    clock: ScaledGateway,
) -> None:
    calls: list[int] = []

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        calls.append(1)
        before_write()
        return resp(429, b"")

    # The 2 s wait fits the 2.5 s deadline; it takes 4 s of the scaled clock.
    verdict, took = run(clock, attempt, seconds=2.5)
    assert calls == [1]
    assert clock.sleeps == [2]
    assert verdict.gate is Gate.IDLE
    body = verdict.error(tag_sent=False).envelope["error"]
    assert body["code"] == "network_error"
    assert body["retryable"] is True and body["unknown_outcome"] is False
    assert body["retry_after_s"] is None
    assert took < 1.0  # real seconds


def test_no_attempt_starts_after_the_deadline_in_a_wait(clock: ScaledGateway) -> None:
    gate = WritingGate()
    calls: list[int] = []

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        calls.append(1)
        before_write()
        return resp(429, b"")

    verdict, _ = run(clock, attempt, gate=gate, seconds=2.5)
    clock.wake.set()  # the worker's wait ends after the deadline
    time.sleep(0.2)
    assert calls == [1]
    assert verdict.kind is Kind.DEADLINE


def test_a_429_then_a_deadline_during_the_retry_connect_is_network_error(
    release: threading.Event, clock: ScaledGateway
) -> None:
    gate = WritingGate()
    calls: list[int] = []
    wrote_second = threading.Event()

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        calls.append(1)
        if len(calls) == 1:
            before_write()
            return resp(429, b"")
        release.wait(10)  # the retry connect is stuck
        try:
            before_write()
        except GateRefused:
            raise
        wrote_second.set()
        return resp()

    clock.wake.set()  # the 2 s wait returns at once
    verdict, took = run(clock, attempt, gate=gate, seconds=3.0)
    assert len(calls) == 2
    body = verdict.error(tag_sent=False).envelope["error"]
    assert body["code"] == "network_error" and body["unknown_outcome"] is False
    release.set()
    time.sleep(0.2)
    assert not wrote_second.is_set()
    assert took < DEADLINE_S + SLACK_S


def test_the_gate_lock_is_never_held_across_the_attempt(release: threading.Event) -> None:
    gate = WritingGate()
    observed: list[bool] = []

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        observed.append(gate._lock.locked())  # connect phase
        before_write()
        observed.append(gate._lock.locked())  # the socket write and read
        return resp()

    verdict, _ = run(ClockGateway(), attempt, gate=gate)
    assert verdict.kind is Kind.COMPLETED
    assert observed == [False, False]


def test_the_main_thread_can_decide_while_the_worker_is_blocked(release: threading.Event) -> None:
    gate = WritingGate()

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        before_write()
        release.wait(10)  # blocked in a "syscall" with the gate in writing
        return resp()

    verdict, took = run(ClockGateway(), attempt, gate=gate)
    assert verdict.kind is Kind.DEADLINE and took < DEADLINE_S + 1.0
    assert not gate._lock.locked()


@pytest.mark.parametrize("exc", [SystemExit(3), KeyboardInterrupt(), GeneratorExit()])
def test_an_uncaught_worker_exception_is_internal_and_prints_nothing(
    exc: BaseException, capfd: pytest.CaptureFixture[str]
) -> None:
    def attempt(before_write: Callable[[], None]) -> RawResponse:
        raise exc

    verdict, _ = run(ClockGateway(), attempt)
    assert verdict.kind is Kind.CRASH
    error = verdict.error(tag_sent=False)
    assert error.exit_code == 1
    assert error.envelope["error"]["message"] == "internal error"
    out, err = capfd.readouterr()
    assert out == "" and err == ""


def test_an_exception_from_the_attempt_is_internal_with_no_text(
    capfd: pytest.CaptureFixture[str],
) -> None:
    def attempt(before_write: Callable[[], None]) -> RawResponse:
        raise ValueError("secret-text")

    verdict, _ = run(ClockGateway(), attempt)
    error = verdict.error(tag_sent=False)
    assert error.exit_code == 1 and "secret-text" not in json.dumps(error.envelope)
    assert capfd.readouterr() == ("", "")


def test_a_crash_after_writing_has_unknown_outcome() -> None:
    def attempt(before_write: Callable[[], None]) -> RawResponse:
        before_write()
        raise RuntimeError("boom")

    verdict, _ = run(ClockGateway(), attempt)
    # RuntimeError while writing is classified by the loop as ``internal``, a result, not a crash.
    assert verdict.error(tag_sent=False).envelope["error"]["unknown_outcome"] is True


def test_a_crash_in_the_loop_itself_is_internal(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    def broken(*args: object, **kwargs: object) -> Outcome:
        raise MemoryError("x")

    monkeypatch.setattr(dl, "run_attempts", broken)
    verdict, _ = run(ClockGateway(), lambda before_write: resp())
    assert verdict.kind is Kind.CRASH
    assert capfd.readouterr() == ("", "")


def test_the_stop_callable_is_decided_like_the_deadline(release: threading.Event) -> None:
    def attempt(before_write: Callable[[], None]) -> RawResponse:
        release.wait(10)
        return resp()

    gateway = ClockGateway()
    started = time.monotonic()
    verdict = run_with_deadline(
        gateway, attempt, op=Op.SEND, deadline=gateway.monotonic() + 60, stop=lambda: True
    )
    assert verdict.kind is Kind.DEADLINE and verdict.gate is Gate.IDLE
    assert time.monotonic() - started < 1.0


def test_a_past_deadline_still_prefers_a_published_result() -> None:
    gate = WritingGate()
    gate.publish(ok_outcome())
    gateway = ClockGateway()
    verdict = run_with_deadline(
        gateway, lambda bw: resp(), op=Op.SEND, deadline=gateway.monotonic() - 5, gate=gate
    )
    assert verdict.kind is Kind.COMPLETED


def test_finish_ends_the_process_only_when_the_worker_may_run() -> None:
    fake = FakeGateway()
    with pytest.raises(FakeExit) as info:
        finish(fake, WritingGate().settle(), 12)
    assert info.value.code == 12 and fake.exits == [12]
    gate = WritingGate()
    gate.publish(ok_outcome())
    assert finish(fake, gate.settle(), 0) == 0
    assert fake.exits == [12]


# --- real sockets ---------------------------------------------------------------------------


class RealClock(StallingResolverGateway):
    """The stalling resolver on a real clock, with a sleep the test can cut short."""

    def __init__(self) -> None:
        super().__init__()
        self.wake = threading.Event()

    def sleep(self, seconds: float) -> None:
        self.wake.wait(seconds)


@pytest.fixture
def real() -> Iterator[RealClock]:
    gateway = RealClock()
    try:
        yield gateway
    finally:
        gateway.release.set()
        gateway.wake.set()


def target_for(ha: FakeHA, *, io_timeout: float = 5.0) -> Target:
    parsed = parse_base_url(f"{ha.scheme}://127.0.0.1:{ha.port}")
    assert parsed is not None
    return Target(parsed, TOKEN, "HA_TOKEN", None, 5.0, io_timeout)


def real_run(
    gateway: RealClock, ha: FakeHA, *, op: Op = Op.SEND
) -> tuple[dl.Verdict, float, WritingGate]:
    target = target_for(ha)
    gate = WritingGate()

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        return send_once(gateway, target, "mobile_app_test", BODY, before_write=before_write)

    started = time.monotonic()
    verdict = run_with_deadline(
        gateway, attempt, op=op, deadline=gateway.monotonic() + DEADLINE_S, gate=gate
    )
    return verdict, time.monotonic() - started, gate


def test_a_real_send_succeeds_through_the_worker(real: RealClock) -> None:
    real.release.set()
    with FakeHA() as ha:
        verdict, took, _ = real_run(real, ha)
        assert verdict.kind is Kind.COMPLETED and verdict.result == Success(200)
        assert len(ha.requests) == 1 and took < 1.0


def test_a_stalled_name_resolution_is_bounded_and_writes_nothing(real: RealClock) -> None:
    with FakeHA() as ha:
        verdict, took, gate = real_run(real, ha)
        assert real.resolving.is_set()
        assert verdict.gate is Gate.IDLE
        assert verdict.error(tag_sent=False).envelope["error"]["code"] == "network_error"
        assert took < DEADLINE_S + SLACK_S
        real.release.set()  # the resolution proceeds; the worker must refuse to write
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not ha.connections:
            time.sleep(0.01)
        time.sleep(0.2)
        assert ha.requests == []
        assert all(chunk == b"" for chunk in ha.received)


def test_a_server_that_never_reads_is_outcome_unknown_in_time(real: RealClock) -> None:
    real.release.set()
    with FakeHA(script=[Reply(stall_before_read=True)]) as ha:
        verdict, took, _ = real_run(real, ha)
        assert verdict.gate is Gate.WRITING
        assert verdict.error(tag_sent=False).envelope["error"]["code"] == "outcome_unknown"
        assert took < DEADLINE_S + SLACK_S


def test_a_server_that_hangs_after_the_request_is_outcome_unknown_in_time(
    real: RealClock,
) -> None:
    real.release.set()
    with FakeHA(script=[Reply(truncate_after=10, hang=True)]) as ha:
        verdict, took, _ = real_run(real, ha)
        assert verdict.error(tag_sent=False).envelope["error"]["code"] == "outcome_unknown"
        assert took < DEADLINE_S + SLACK_S


def test_a_byte_by_byte_response_is_bounded_by_the_deadline(real: RealClock) -> None:
    real.release.set()
    with FakeHA(script=[Reply(trickle=0.2, body=b"[" + b" " * 200 + b"]")]) as ha:
        verdict, took, _ = real_run(real, ha)  # every recv succeeds within io_timeout
        assert verdict.kind is Kind.DEADLINE and verdict.gate is Gate.WRITING
        assert verdict.error(tag_sent=False).envelope["error"]["code"] == "outcome_unknown"
        assert DEADLINE_S <= took < DEADLINE_S + SLACK_S


def test_a_429_whose_wait_does_not_fit_ends_at_once_with_rate_limited(
    real: RealClock,
) -> None:
    real.release.set()
    with FakeHA(script=[Reply(status=429)]) as ha:
        verdict, took, _ = real_run(real, ha)  # the 2 s wait outlasts the 1 s deadline
        assert len(ha.requests) == 1
        assert verdict.kind is Kind.COMPLETED
        error = verdict.error(tag_sent=False)
        assert error.exit_code == 12 and error.envelope["error"]["retry_after_s"] == 2
        assert took < 1.0


def test_a_probe_deadline_is_not_an_unknown_outcome(real: RealClock) -> None:
    real.release.set()
    with FakeHA(script=[Reply(truncate_after=10, hang=True)]) as ha:
        verdict, _, _ = real_run(real, ha, op=Op.PROBE)
        spec = verdict.result
        assert isinstance(spec, ErrorSpec) and spec.probe and not spec.unknown_outcome
