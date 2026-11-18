"""The retry loop (issue #24): 429 and connect-phase retries, waits, counters and the deadline.

Scripted attempts cover the decision table; a few tests run ``send_once`` on the real gateway
against the wire-level fake server. No test sleeps: waits go through ``FakeGateway.sleep``, which
advances a fake clock.
"""

from __future__ import annotations

import dataclasses
import http.client
import json
import socket
import ssl
from collections.abc import Callable

import pytest

from ha_notice import retry as retry_module
from ha_notice.config import parse_base_url
from ha_notice.gateway import RealGateway
from ha_notice.hass import RawResponse, Target, send_once
from ha_notice.response import ErrorSpec, Gate, Op, Retry, Success
from ha_notice.retry import (
    CONNECTION_WAIT_S,
    RATE_LIMIT_WAITS_S,
    AttemptGate,
    LocalGate,
    run_attempts,
)
from tests.fake_gateway import FakeGateway
from tests.fake_ha import FakeHA, Reply

TOKEN = "HA_retry-0123456789"
BODY = json.dumps({"message": "hi"}).encode()


def resp(status: int = 200, body: bytes = b"[]") -> RawResponse:
    return RawResponse(status, body, False)


class ConnectFail:
    """The attempt fails before the gate is entered (name resolution, connect, handshake)."""

    def __init__(self, exc: BaseException | None = None) -> None:
        self.exc = exc or ConnectionRefusedError(111, "refused")


class WriteFail:
    """The attempt enters the gate, then fails with no complete answer."""

    def __init__(self, exc: BaseException | None = None) -> None:
        self.exc = exc or ConnectionResetError(104, "reset")


Step = RawResponse | ConnectFail | WriteFail


class Script:
    """Scripted attempts; records what each attempt saw of the gate."""

    def __init__(self, *steps: Step) -> None:
        self.steps = list(steps)
        self.requests = 0
        self.states_at_start: list[Gate] = []
        self.gate: AttemptGate | None = None

    def __call__(self, before_write: Callable[[], None]) -> RawResponse:
        assert self.steps, "more attempts than scripted"
        step = self.steps.pop(0)
        self.requests += 1
        if self.gate is not None:
            self.states_at_start.append(self.gate.state())
        if isinstance(step, ConnectFail):
            raise step.exc
        before_write()
        if isinstance(step, WriteFail):
            raise step.exc
        return step


def run(
    *steps: Step,
    op: Op = Op.SEND,
    remaining: Callable[[], float] | None = None,
    gate: AttemptGate | None = None,
    gateway: FakeGateway | None = None,
):
    gateway = gateway or FakeGateway()
    gate = gate or LocalGate()
    script = Script(*steps)
    script.gate = gate
    outcome = run_attempts(script, op=op, gate=gate, sleep=gateway.sleep, remaining=remaining)
    return outcome, script, gateway


def code(outcome) -> str:
    assert isinstance(outcome.result, ErrorSpec)
    return outcome.result.code


# --- the happy path and the constants


def test_a_200_is_one_request_and_no_wait() -> None:
    outcome, script, gateway = run(resp())
    assert outcome.result == Success(200)
    assert (script.requests, gateway.sleeps, outcome.facts.waited_s) == (1, [], 0)
    assert outcome.retry_after_s is None


def test_the_waits_are_fixed() -> None:
    assert (RATE_LIMIT_WAITS_S, CONNECTION_WAIT_S) == ((2, 4), 2)


# --- 429


def test_429_then_200_waits_two_seconds() -> None:
    outcome, script, gateway = run(resp(429), resp())
    assert outcome.result == Success(200)
    assert (script.requests, gateway.sleeps) == (2, [2])
    assert (outcome.facts.rate_limit_retries, outcome.facts.connection_retries) == (1, 0)


def test_three_429s_wait_two_then_four_and_end_rate_limited() -> None:
    outcome, script, gateway = run(resp(429), resp(429), resp(429))
    assert (script.requests, gateway.sleeps) == (3, [2, 4])
    assert (code(outcome), outcome.retry_after_s) == ("rate_limited", 4)
    assert outcome.facts.waits_s == (2, 4)
    result = outcome.error(tag_sent=False)
    error = result.envelope["error"]
    assert (result.exit_code, error["retry_after_s"], error["retryable"]) == (12, 4, True)
    assert error["unknown_outcome"] is False


def test_a_fourth_429_is_never_requested() -> None:
    outcome, script, _ = run(resp(429), resp(429), resp(429))
    assert script.steps == [] and script.requests == 3


def test_each_attempt_enters_the_gate_and_a_429_returns_it_to_idle() -> None:
    outcome, script, _ = run(resp(429), resp(429), resp())
    assert script.states_at_start == [Gate.IDLE, Gate.IDLE, Gate.IDLE]
    assert outcome.result == Success(200)


# --- connect-phase failures


def test_connection_refused_is_retried_once_after_two_seconds() -> None:
    outcome, script, gateway = run(ConnectFail(), resp())
    assert outcome.result == Success(200)
    assert (script.requests, gateway.sleeps) == (2, [2])
    assert (outcome.facts.rate_limit_retries, outcome.facts.connection_retries) == (0, 1)


def test_two_refusals_end_as_network_error_after_two_requests() -> None:
    outcome, script, gateway = run(ConnectFail(), ConnectFail())
    assert (code(outcome), script.requests, gateway.sleeps) == ("network_error", 2, [2])
    assert outcome.retry_after_s is None
    error = outcome.error(tag_sent=False).envelope["error"]
    assert (error["retryable"], error["unknown_outcome"], error["retry_after_s"]) == (
        True,
        False,
        None,
    )


@pytest.mark.parametrize(
    "exc",
    [
        socket.gaierror(-2, "x"),
        TimeoutError(),
        OSError(113, "no route"),
        ssl.SSLError(1, "handshake"),
        ssl.SSLEOFError(8, "eof"),
        http.client.HTTPException(),
    ],
)
def test_connect_phase_failures_are_retried_once(exc: BaseException) -> None:
    outcome, script, _ = run(ConnectFail(exc), resp())
    assert (outcome.result, script.requests) == (Success(200), 2)


def test_a_certificate_failure_is_not_retried() -> None:
    exc = ssl.SSLCertVerificationError(1, "bad cert")
    outcome, script, gateway = run(ConnectFail(exc), resp())
    assert (code(outcome), script.requests, gateway.sleeps) == ("network_error", 1, [])
    assert outcome.error(tag_sent=True).envelope["error"]["retryable"] is False


def test_a_bug_while_idle_is_not_retried() -> None:
    outcome, script, _ = run(ConnectFail(ValueError("secret")), resp())
    assert (code(outcome), script.requests) == ("internal", 1)


# --- independent counters


def test_429_twice_then_refused_then_refused_is_four_requests() -> None:
    outcome, script, gateway = run(resp(429), resp(429), ConnectFail(), ConnectFail())
    assert (code(outcome), script.requests, gateway.sleeps) == ("network_error", 4, [2, 4, 2])


def test_429_twice_then_refused_then_200_succeeds_on_the_fourth() -> None:
    outcome, script, _ = run(resp(429), resp(429), ConnectFail(), resp())
    assert (outcome.result, script.requests) == (Success(200), 4)


def test_a_connection_failure_on_a_429_retry_is_retried_once() -> None:
    outcome, script, gateway = run(resp(429), ConnectFail(), resp())
    assert (outcome.result, script.requests, gateway.sleeps) == (Success(200), 3, [2, 2])


def test_a_refusal_before_429s_does_not_use_the_429_budget() -> None:
    outcome, script, gateway = run(ConnectFail(), resp(429), resp(429), resp(429))
    assert (code(outcome), script.requests, gateway.sleeps) == ("rate_limited", 4, [2, 2, 4])
    assert outcome.retry_after_s == 4


def test_the_most_requests_ever_made_is_four() -> None:
    outcome, script, _ = run(resp(429), resp(429), ConnectFail(), resp(429), resp(429))
    assert script.requests == 4 and script.steps == [resp(429)]
    assert code(outcome) == "rate_limited"


def test_a_final_429_reports_the_wait_last_performed() -> None:
    # 429, 429, refused (waits 2, 4, 2), then a 429 with no 429 retry left: the last wait is 2.
    outcome, _, _ = run(resp(429), resp(429), ConnectFail(), resp(429))
    assert outcome.facts.waits_s == (2, 4, 2)
    assert outcome.retry_after_s == 2


def test_two_connection_retries_never_happen() -> None:
    outcome, script, _ = run(resp(429), ConnectFail(), ConnectFail(), resp())
    assert (code(outcome), script.requests) == ("network_error", 3)


# --- never retried


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 500, 502, 503, 504, 599])
def test_other_statuses_are_final(status: int) -> None:
    outcome, script, gateway = run(resp(status), resp())
    assert (script.requests, gateway.sleeps) == (1, [])
    assert isinstance(outcome.result, ErrorSpec)


@pytest.mark.parametrize("status", [100, 101, 199, 301, 302, 418, 600, 999, 0, -1])
def test_odd_statuses_are_final(status: int) -> None:
    outcome, script, _ = run(resp(status), resp())
    assert script.requests == 1 and isinstance(outcome.result, ErrorSpec)


def test_a_200_with_a_bad_body_is_final() -> None:
    outcome, script, _ = run(resp(200, b"not json"), resp())
    assert (code(outcome), script.requests) == ("wrong_host_response", 1)


@pytest.mark.parametrize(
    "exc",
    [
        ConnectionResetError(104, "reset"),
        BrokenPipeError(32, "pipe"),
        TimeoutError(),
        ssl.SSLEOFError(8, "eof"),
        http.client.RemoteDisconnected("gone"),
        http.client.IncompleteRead(b"x"),
        http.client.BadStatusLine("x"),
    ],
)
def test_a_failure_after_the_gate_is_never_retried(exc: BaseException) -> None:
    outcome, script, gateway = run(WriteFail(exc), resp())
    assert script.requests == 1 and gateway.sleeps == []
    assert outcome.result.unknown_outcome is True  # type: ignore[union-attr]


def test_a_drop_after_the_first_byte_is_retryable_only_with_a_tag() -> None:
    outcome, script, _ = run(WriteFail(http.client.RemoteDisconnected("gone")))
    assert (code(outcome), script.requests) == ("outcome_unknown", 1)
    assert outcome.error(tag_sent=False).envelope["error"]["retryable"] is False
    assert outcome.error(tag_sent=True).envelope["error"]["retryable"] is True
    assert outcome.error(tag_sent=True).envelope["error"]["unknown_outcome"] is True


def test_a_write_failure_after_a_429_is_not_retried() -> None:
    outcome, script, gateway = run(resp(429), WriteFail(), resp())
    assert (code(outcome), script.requests, gateway.sleeps) == ("outcome_unknown", 2, [2])


def test_a_write_failure_after_a_connection_retry_is_not_retried() -> None:
    outcome, script, _ = run(ConnectFail(), WriteFail(), resp())
    assert (code(outcome), script.requests) == ("outcome_unknown", 2)


def test_a_failure_with_the_gate_writing_is_never_retried_even_when_it_looks_like_a_connect() -> (
    None
):
    # An OSError raised after the gate was entered is a write-phase failure by the gate alone.
    outcome, script, _ = run(WriteFail(ConnectionRefusedError(111, "x")), resp())
    assert (code(outcome), script.requests) == ("outcome_unknown", 1)


def test_a_probe_is_retried_like_a_send() -> None:
    outcome, script, gateway = run(resp(429), ConnectFail(), resp(200, b"{}"), op=Op.PROBE)
    assert (outcome.result, script.requests, gateway.sleeps) == (Success(200), 3, [2, 2])


def test_a_failed_probe_has_no_envelope() -> None:
    outcome, _, _ = run(resp(500), op=Op.PROBE)
    with pytest.raises(ValueError):
        outcome.error(tag_sent=False)


def test_a_probe_429_three_times_is_rate_limited() -> None:
    outcome, script, _ = run(resp(429), resp(429), resp(429), op=Op.PROBE)
    assert (code(outcome), script.requests, outcome.retry_after_s) == ("rate_limited", 3, 4)


def test_a_base_exception_propagates() -> None:
    with pytest.raises(KeyboardInterrupt):
        run(ConnectFail(KeyboardInterrupt()), resp())


# --- the deadline


def test_a_429_wait_longer_than_the_time_left_ends_the_send_without_sleeping() -> None:
    outcome, script, gateway = run(resp(429), resp(), remaining=lambda: 1.9)
    assert (code(outcome), script.requests, gateway.sleeps) == ("rate_limited", 1, [])
    assert outcome.retry_after_s == 2
    assert outcome.error(tag_sent=False).envelope["error"]["retry_after_s"] == 2


def test_the_time_left_is_read_for_each_wait() -> None:
    gateway = FakeGateway()
    start = gateway.monotonic()
    outcome, script, _ = run(
        resp(429),
        resp(429),
        resp(429),
        remaining=lambda: 5.0 - (gateway.monotonic() - start),
        gateway=gateway,
    )
    # 5 s left: wait 2 fits (3 left); wait 4 does not.
    assert (code(outcome), script.requests, gateway.sleeps) == ("rate_limited", 2, [2])
    assert outcome.retry_after_s == 4


def test_a_wait_equal_to_the_time_left_is_performed() -> None:
    outcome, script, gateway = run(resp(429), resp(), remaining=lambda: 2.0)
    assert (outcome.result, gateway.sleeps) == (Success(200), [2])


def test_a_connection_wait_that_does_not_fit_ends_as_network_error() -> None:
    outcome, script, gateway = run(ConnectFail(), resp(), remaining=lambda: 1.0)
    assert (code(outcome), script.requests, gateway.sleeps) == ("network_error", 1, [])
    assert outcome.retry_after_s is None


@pytest.mark.parametrize("left", [float("nan"), -1.0, -float("inf"), 0.0, 1e-9])
def test_a_nan_or_negative_time_left_never_waits(left: float) -> None:
    outcome, script, gateway = run(resp(429), resp(), remaining=lambda: left)
    assert (code(outcome), script.requests, gateway.sleeps) == ("rate_limited", 1, [])


@pytest.mark.parametrize("left", [float("inf"), 1e12])
def test_a_huge_time_left_still_waits_only_the_fixed_waits(left: float) -> None:
    outcome, _, gateway = run(resp(429), resp(429), resp(429), remaining=lambda: left)
    assert gateway.sleeps == [2, 4]


class AbandonAfterWait(LocalGate):
    def __init__(self, gateway: FakeGateway) -> None:
        super().__init__()
        self.gateway = gateway

    def abandoned(self) -> bool:
        return bool(self.gateway.sleeps)


def test_an_abandoned_gate_after_a_wait_makes_no_further_request() -> None:
    gateway = FakeGateway()
    outcome, script, _ = run(resp(429), resp(), gate=AbandonAfterWait(gateway), gateway=gateway)
    assert (script.requests, code(outcome)) == (1, "rate_limited")
    assert outcome.retry_after_s == 2


def test_an_abandoned_gate_before_a_wait_neither_sleeps_nor_requests_again() -> None:
    class AbandonedAtOnce(LocalGate):
        def abandoned(self) -> bool:
            return True

    outcome, script, gateway = run(resp(429), resp(), gate=AbandonedAtOnce())
    assert (script.requests, gateway.sleeps, code(outcome)) == (1, [], "rate_limited")
    assert (outcome.retry_after_s, outcome.facts.waits_s) == (2, ())


def test_an_abandoned_gate_before_a_connection_wait_does_not_sleep() -> None:
    class AbandonedAtOnce(LocalGate):
        def abandoned(self) -> bool:
            return True

    outcome, script, gateway = run(ConnectFail(), resp(), gate=AbandonedAtOnce())
    assert (script.requests, gateway.sleeps, code(outcome)) == (1, [], "network_error")


def test_return_to_idle_after_abandon_stays_abandoned_and_refuses_writing() -> None:
    gate = LocalGate()
    gate.abandon()
    gate.return_to_idle()
    assert gate.abandoned() is True
    with pytest.raises(RuntimeError):
        gate.enter_writing()


def test_return_to_idle_from_writing_goes_idle() -> None:
    gate = LocalGate()
    gate.enter_writing()
    gate.return_to_idle()
    assert gate.state() is Gate.IDLE


@pytest.mark.parametrize(
    "spec",
    [
        ErrorSpec("outcome_unknown", retry=Retry.CONNECTION),
        ErrorSpec("outcome_unknown", retry=Retry.RATE_LIMIT),
        ErrorSpec("internal", after_writing=True, retry=Retry.CONNECTION),
        ErrorSpec("internal", after_writing=True, retry=Retry.RATE_LIMIT),
    ],
    ids=["unknown-conn", "unknown-429", "writing-conn", "writing-429"],
)
def test_a_marked_spec_that_may_have_been_delivered_is_never_repeated(
    spec: ErrorSpec, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(retry_module, "classify_response", lambda raw, op: spec)
    monkeypatch.setattr(retry_module, "classify_exception", lambda exc, gate, op: spec)
    assert spec.unknown_outcome or spec.after_writing
    for step in (resp(429), WriteFail()):
        outcome, script, gateway = run(step, resp())
        assert (script.requests, gateway.sleeps) == (1, [])
        assert outcome.result is spec


# --- facts


def test_the_facts_carry_counts_and_seconds_only() -> None:
    outcome, _, _ = run(resp(429), ConnectFail(), resp())
    facts = outcome.facts
    assert (facts.requests, facts.rate_limit_retries, facts.connection_retries) == (3, 1, 1)
    assert (facts.waits_s, facts.waited_s) == ((2, 2), 4)
    assert all(type(v) in (int, tuple) for v in dataclasses.asdict(facts).values())


def test_a_raw_response_has_no_headers_to_read() -> None:
    assert [f.name for f in dataclasses.fields(RawResponse)] == ["status", "body", "too_large"]


# --- real sockets

RETRY_AFTER = ["nan", "-5", "1e999", "Wed, 21 Oct 2026 07:28:00 GMT", "5", "45", "0", "\xb2", ""]


def target_for(ha: FakeHA) -> Target:
    parsed = parse_base_url(f"{ha.scheme}://127.0.0.1:{ha.port}")
    assert parsed is not None
    return Target(parsed, TOKEN, "HA_TOKEN", None, 5.0, 5.0)


def real_run(ha: FakeHA, *, op: Op = Op.SEND, target: Target | None = None):
    real = RealGateway()
    fake = FakeGateway()
    target = target or target_for(ha)
    count = [0]

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        count[0] += 1
        return send_once(real, target, "mobile_app_test", BODY, before_write=before_write)

    gate = LocalGate()
    outcome = run_attempts(attempt, op=op, gate=gate, sleep=fake.sleep)
    return outcome, fake, count[0]


@pytest.mark.parametrize("value", RETRY_AFTER)
def test_retry_after_is_ignored_on_the_wire(value: str) -> None:
    reply = Reply(status=429, headers=(("Retry-After", value),))
    with FakeHA(script=[reply, reply, reply]) as ha:
        outcome, fake, count = real_run(ha)
        assert ha.connections == 3 and len(ha.requests) == 3
    assert (code(outcome), count, fake.sleeps, outcome.retry_after_s) == (
        "rate_limited",
        3,
        [2, 4],
        4,
    )


def test_429_twice_then_200_on_a_fresh_connection_each_time() -> None:
    with FakeHA(script=[Reply(status=429), Reply(status=429)]) as ha:
        outcome, fake, count = real_run(ha)
        assert (ha.connections, len(ha.requests)) == (3, 3)
    assert (outcome.result, fake.sleeps) == (Success(200), [2, 4])


def test_a_5xx_is_one_request_on_the_wire() -> None:
    with FakeHA(script=[Reply(status=503)]) as ha:
        outcome, fake, count = real_run(ha)
        assert len(ha.requests) == 1
    assert (code(outcome), count, fake.sleeps) == ("upstream_error", 1, [])


@pytest.mark.parametrize(
    "reply",
    [
        Reply(drop=True),
        Reply(reset=True, truncate_after=10),
        Reply(declared_length=50),
    ],
)
def test_a_drop_after_the_request_is_one_request_and_outcome_unknown(reply: Reply) -> None:
    with FakeHA(script=[reply, Reply()]) as ha:
        outcome, fake, count = real_run(ha)
        assert ha.connections == 1
    assert (code(outcome), count, fake.sleeps) == ("outcome_unknown", 1, [])
    assert outcome.error(tag_sent=False).envelope["error"]["retryable"] is False
    assert outcome.error(tag_sent=True).envelope["error"]["retryable"] is True


def closed_port_target() -> Target:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    parsed = parse_base_url(f"http://127.0.0.1:{port}")
    assert parsed is not None
    return Target(parsed, TOKEN, "HA_TOKEN", None, 5.0, 5.0)


def test_connection_refused_on_a_real_port_is_retried_once() -> None:
    with FakeHA() as ha:
        outcome, fake, count = real_run(ha, target=closed_port_target())
        assert ha.connections == 0
    assert (code(outcome), count, fake.sleeps) == ("network_error", 2, [2])


def test_429_twice_then_refused_is_at_most_four_requests_on_real_sockets() -> None:
    real = RealGateway()
    fake = FakeGateway()
    dead = closed_port_target()
    with FakeHA(script=[Reply(status=429), Reply(status=429)]) as ha:
        live = target_for(ha)
        targets = [live, live, dead, dead, dead]
        count = [0]

        def attempt(before_write: Callable[[], None]) -> RawResponse:
            target = targets[count[0]]
            count[0] += 1
            return send_once(real, target, "mobile_app_test", BODY, before_write=before_write)

        outcome = run_attempts(attempt, op=Op.SEND, gate=LocalGate(), sleep=fake.sleep)
        assert len(ha.requests) == 2
    assert (code(outcome), count[0], fake.sleeps) == ("network_error", 4, [2, 4, 2])


def test_a_truncated_head_is_one_request_and_possibly_delivered() -> None:
    with FakeHA(script=[Reply(truncate_after=20), Reply()]) as ha:
        outcome, fake, count = real_run(ha)
        assert ha.connections == 1
    assert (count, fake.sleeps) == (1, [])
    assert outcome.result.unknown_outcome is True  # type: ignore[union-attr]


# --- every script up to five steps long

KINDS: dict[str, Callable[[], Step]] = {
    "429": lambda: resp(429),
    "refused": lambda: ConnectFail(),
    "write": lambda: WriteFail(),
    "200": lambda: resp(),
    "503": lambda: resp(503),
}


def all_scripts(length: int) -> list[tuple[str, ...]]:
    scripts: list[tuple[str, ...]] = [()]
    for _ in range(length):
        scripts = [s + (k,) for s in scripts for k in KINDS]
    return scripts


def oracle(script: tuple[str, ...]) -> tuple[int, tuple[int, ...], str | int, int | None]:
    """Independent model: (requests, waits, final code or HTTP status, retry_after_s)."""
    rate = conn = 0
    waits: list[int] = []
    for n, kind in enumerate(script, start=1):
        if kind == "200":
            return n, tuple(waits), 200, None
        if kind == "429" and rate < 2:
            waits.append((2, 4)[rate])
            rate += 1
        elif kind == "refused" and conn < 1:
            waits.append(2)
            conn += 1
        else:
            final = {
                "429": "rate_limited",
                "refused": "network_error",
                "write": "outcome_unknown",
                "503": "upstream_error",
            }[kind]
            return n, tuple(waits), final, waits[-1] if kind == "429" else None
    raise AssertionError("scripts are long enough to always end")


@pytest.mark.parametrize("script", all_scripts(5), ids="-".join)
def test_no_script_makes_more_than_four_requests_or_unbounded_waits(
    script: tuple[str, ...],
) -> None:
    outcome, played, gateway = run(*(KINDS[k]() for k in script))
    assert played.requests <= 4
    assert set(gateway.sleeps) <= {2, 4} and sum(gateway.sleeps) <= 8
    assert outcome.facts.requests == played.requests
    assert outcome.facts.rate_limit_retries <= 2 and outcome.facts.connection_retries <= 1
    assert len(gateway.sleeps) == played.requests - 1 or isinstance(outcome.result, ErrorSpec)
    # nothing follows a write-phase failure, a 5xx or a success
    kinds = script[: played.requests]
    for kind in kinds[:-1]:
        assert kind in ("429", "refused")
    assert (
        outcome.facts.requests,
        tuple(gateway.sleeps),
        code(outcome) if isinstance(outcome.result, ErrorSpec) else outcome.result.http_status,
        outcome.retry_after_s,
    ) == oracle(script)
