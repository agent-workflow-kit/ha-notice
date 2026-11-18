"""The retry loop (issue #24): attempts, waits and what may be repeated.

``run_attempts`` runs one attempt after another and classifies each with ``response.py``. It
retries only what ``ErrorSpec.retry`` marks, per docs/interface.md (Home Assistant edge, Retries):

- ``Retry.RATE_LIMIT`` (a fully read 429): at most two retries, after 2 s and then 4 s. The
  ``Retry-After`` header is never read here or anywhere (``RawResponse`` has no headers), so no
  wait depends on input.
- ``Retry.CONNECTION`` (a failure while the gate is idle that is not a certificate failure): at
  most one retry, after 2 s. This includes the connection of a 429 retry.
- The two counters are independent: at most four requests per send (two 429 retries and one
  connection retry, in any order).
- Nothing else is retried, and nothing is retried when the spec says the outcome is unknown.
- A wait longer than the time that remains ends the send at once with the last result, without
  sleeping (the ``rate_limited`` envelope then carries that wait as ``retry_after_s``).

Every attempt opens a fresh connection (``Connection: close``) and takes the idle-to-writing gate
step through ``before_write``; a fully read 429 returns the gate to idle before the next attempt.
The gate, the worker thread and the whole-send deadline belong to #25; ``AttemptGate`` is the seam
and ``LocalGate`` the single-threaded stand-in. The loop reads no clock: waits go through the
``sleep`` it is given (the gateway's) and the time left comes from ``remaining``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from ha_notice.hass import RawResponse
from ha_notice.output import ErrorResult
from ha_notice.response import (
    ErrorSpec,
    Gate,
    Op,
    Retry,
    Success,
    classify_exception,
    classify_response,
)

__all__ = [
    "CONNECTION_WAIT_S",
    "RATE_LIMIT_WAITS_S",
    "AttemptFacts",
    "AttemptGate",
    "LocalGate",
    "Outcome",
    "run_attempts",
]

RATE_LIMIT_WAITS_S: tuple[int, ...] = (2, 4)
CONNECTION_WAIT_S = 2
MAX_CONNECTION_RETRIES = 1


class AttemptGate(Protocol):
    """What the loop needs from the writing gate. TODO(#25): the locked three-state gate
    (idle, writing, abandoned) implements this; its ``enter_writing`` raises to refuse once the
    gate is abandoned."""

    def enter_writing(self) -> None:
        """The idle-to-writing step, run before the first call that can write request bytes."""
        ...

    def state(self) -> Gate:
        """The state to classify a failed attempt by."""
        ...

    def return_to_idle(self) -> None:
        """A complete 429 was read: the host accepted nothing."""
        ...

    def abandoned(self) -> bool:
        """The deadline ended the send: no further attempt may start."""
        ...


class LocalGate:
    """A single-threaded gate with no lock and no deadline. TODO(#25): replaced by the real one."""

    def __init__(self) -> None:
        self._state = Gate.IDLE

    def enter_writing(self) -> None:
        self._state = Gate.WRITING

    def state(self) -> Gate:
        return self._state

    def return_to_idle(self) -> None:
        self._state = Gate.IDLE

    def abandoned(self) -> bool:
        return False


@dataclass(frozen=True)
class AttemptFacts:
    """What the loop did, for the log and the report: counts and seconds only, no text."""

    requests: int
    rate_limit_retries: int
    connection_retries: int
    waits_s: tuple[int, ...]  # every wait performed, in order

    @property
    def waited_s(self) -> int:
        return sum(self.waits_s)


@dataclass(frozen=True)
class Outcome:
    """The last result and the facts. ``retry_after_s`` is set only for a final ``rate_limited``:
    the wait last performed, or the wait that did not fit the time left."""

    result: Success | ErrorSpec
    facts: AttemptFacts
    retry_after_s: int | None = None

    def error(self, *, tag_sent: bool) -> ErrorResult:
        """The exit code and envelope of a failed outcome (not for a probe or a success)."""
        if not isinstance(self.result, ErrorSpec):
            raise ValueError("the outcome is a success")
        return self.result.build(tag_sent=tag_sent, retry_after_s=self.retry_after_s)


def _fits(wait: int, remaining: Callable[[], float] | None) -> bool:
    """Is ``wait`` not longer than the time left? A NaN or negative left never fits."""
    if remaining is None:
        return True
    left = remaining()
    return bool(wait <= left)  # false for NaN; a negative left is below any wait


def _may_retry(spec: ErrorSpec) -> bool:
    # Belt and braces: the markers are set only for not-written results, and a result that may
    # have been delivered is never repeated whatever its marker says.
    return not spec.unknown_outcome and not spec.after_writing


def run_attempts(
    attempt: Callable[[Callable[[], None]], RawResponse],
    *,
    op: Op,
    gate: AttemptGate,
    sleep: Callable[[float], None],
    remaining: Callable[[], float] | None = None,
) -> Outcome:
    """Run ``attempt(before_write)`` until it succeeds, fails for good or the retries run out.

    ``attempt`` makes one request on a fresh connection and calls ``before_write`` before it can
    write (``hass.send_once`` and ``probe_once`` take exactly that hook). ``remaining`` returns the
    seconds left in the send's deadline (``None``: unbounded). An ``Exception`` from an attempt is
    classified by the gate state; a ``BaseException`` that is not an ``Exception`` propagates.
    """
    rate_retries = 0
    conn_retries = 0
    waits: list[int] = []

    def outcome(result: Success | ErrorSpec, requests: int, retry_after: int | None) -> Outcome:
        facts = AttemptFacts(requests, rate_retries, conn_retries, tuple(waits))
        is_429 = isinstance(result, ErrorSpec) and result.code == "rate_limited"
        return Outcome(result, facts, retry_after if is_429 else None)

    requests = 0
    while True:
        requests += 1
        result: Success | ErrorSpec
        try:
            result = classify_response(attempt(gate.enter_writing), op=op)
        except Exception as exc:
            result = classify_exception(exc, gate.state(), op=op)
        if not isinstance(result, ErrorSpec) or not _may_retry(result):
            return outcome(result, requests, waits[-1] if waits else None)
        last_wait = waits[-1] if waits else None
        if result.retry is Retry.RATE_LIMIT:
            gate.return_to_idle()  # a complete 429: nothing was accepted
        if result.retry is Retry.RATE_LIMIT and rate_retries < len(RATE_LIMIT_WAITS_S):
            wait = RATE_LIMIT_WAITS_S[rate_retries]
            is_rate = True
        elif result.retry is Retry.CONNECTION and conn_retries < MAX_CONNECTION_RETRIES:
            wait = CONNECTION_WAIT_S
            is_rate = False
        else:
            return outcome(result, requests, last_wait)
        if not _fits(wait, remaining):
            return outcome(result, requests, wait)
        sleep(wait)
        waits.append(wait)
        if is_rate:
            rate_retries += 1
        else:
            conn_retries += 1
        if gate.abandoned():  # TODO(#25): the deadline fired during the wait
            return outcome(result, requests, wait)
