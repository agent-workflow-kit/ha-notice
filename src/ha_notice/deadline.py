"""The whole-send deadline (issue #25): the writing gate, the worker thread and the decision.

docs/interface.md (Home Assistant edge, Deadline) is normative. In short:

- ``run_with_deadline`` starts a daemon worker thread that runs the retry loop (``run_attempts``)
  and waits in the main thread, in slices of at most 100 ms, for the worker's result or the
  deadline. The loop's sleep is not sliced, so it must live in the worker; name resolution and an
  endless ``100 Continue`` stream cannot be interrupted either. Those two backstops are bounded
  only by this worker plus the caller ending the process with ``gateway.exit_process`` (``finish``)
  after the output is flushed and the log is written. The worker is never joined.
- ``WritingGate`` has three states (idle, writing, abandoned) and one lock. The lock guards short
  critical sections only and is never held across a socket call, a sleep or a wait: the worker
  takes it for ``enter_writing``, ``return_to_idle``, ``abandoned`` and ``publish``, the main
  thread for ``settle``. The result slot lives under the same lock, so a response and the deadline
  cannot both win.
- ``settle`` decides, once: a published result wins; otherwise an idle gate becomes abandoned
  (exit 12 ``network_error``, ``details.timeout`` true, retryable, ``unknown_outcome`` false) and a
  writing gate stays writing (exit 12 ``outcome_unknown``). Later results and later attempts are
  refused: once the decision is made no attempt may write (``enter_writing`` raises), so a worker
  that was writing at the deadline cannot start a second request in the time the caller needs to
  print and log. The abandoned result replaces the loop's result: a 429 that was being waited on
  never turns into ``rate_limited``.
- An uncaught ``BaseException`` in the worker is handed over as ``internal`` (exit 1;
  ``unknown_outcome`` only if the gate was writing). The worker prints nothing and the exception
  text and class are dropped.

The ``stop`` callable is the seam for the signal handler (``signals.SignalState.stopped``): a stop
is decided like the deadline. The send flow (``send.deliver``) prints, logs and calls ``finish``;
``finish`` does not flush stdout or stderr, so the flow prints and flushes before it. A failure of
``worker.start()`` ("can't start new thread") raises ``RuntimeError`` here; the send flow maps it
to exit 1 ``internal error``.
"""

from __future__ import annotations

import enum
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from ha_notice.gateway import Gateway
from ha_notice.hass import RawResponse
from ha_notice.output import ErrorResult
from ha_notice.response import ErrorSpec, Gate, Op, Success
from ha_notice.retry import AttemptFacts, Outcome, run_attempts

__all__ = [
    "SLICE_S",
    "GateRefused",
    "Kind",
    "Verdict",
    "WritingGate",
    "finish",
    "run_with_deadline",
]

SLICE_S = 0.1  # the main thread notices a stop and a late deadline within this many seconds
WORKER_NAME = "ha-notice-worker"


class GateRefused(OSError):
    """Raised by ``enter_writing`` once the send was abandoned: no byte is written. An
    ``OSError`` so that a refusal while idle reads as a connect-phase failure (the loop then sees
    ``abandoned()`` and stops). It carries no text."""

    def __init__(self) -> None:
        super().__init__()


class Kind(enum.Enum):
    COMPLETED = "completed"  # the worker published the loop's outcome
    DEADLINE = "deadline"  # the deadline (or a stop) decided by the gate state
    CRASH = "crash"  # the worker raised: exit 1 ``internal``


@dataclass(frozen=True)
class Verdict:
    """The final result of the network phase.

    ``result`` is a ``Success`` or an ``ErrorSpec``. ``gate`` is the phase that classified it.
    ``facts`` are the loop's counts (only for ``COMPLETED``). ``worker_may_run`` says that the
    worker thread may still be running (the deadline case): the caller must end the process with
    ``finish`` rather than return from ``main``.
    """

    kind: Kind
    result: Success | ErrorSpec
    gate: Gate
    facts: AttemptFacts | None = None
    retry_after_s: int | None = None

    @property
    def worker_may_run(self) -> bool:
        return self.kind is Kind.DEADLINE

    def error(self, *, tag_sent: bool) -> ErrorResult:
        """The exit code and envelope of a failed verdict (not for a probe or a success)."""
        if not isinstance(self.result, ErrorSpec):
            raise ValueError("the verdict is a success")
        return self.result.build(tag_sent=tag_sent, retry_after_s=self.retry_after_s)


@dataclass(frozen=True)
class _Crash:
    writing: bool


class WritingGate:
    """The locked three-state gate and the result slot. Implements ``retry.AttemptGate``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: Literal["idle", "writing", "abandoned"] = "idle"
        self._closed = False  # the decision was made: no further attempt may write
        self._slot: Outcome | _Crash | None = None
        self._verdict: Verdict | None = None
        self._done = threading.Event()

    # --- the worker's side -----------------------------------------------------------------

    def enter_writing(self) -> None:
        """Idle to writing, before the first call that can write request bytes. Raises
        ``GateRefused`` (and changes nothing) once the gate is abandoned or settled."""
        with self._lock:
            if self._state == "abandoned" or self._closed:
                raise GateRefused
            self._state = "writing"

    def state(self) -> Gate:
        """The phase to classify a failed attempt by. An abandoned gate was idle before."""
        with self._lock:
            return Gate.WRITING if self._state == "writing" else Gate.IDLE

    def return_to_idle(self) -> None:
        """A complete 429: no-op unless writing, and never after the decision."""
        with self._lock:
            if self._state == "writing" and not self._closed:
                self._state = "idle"

    def abandoned(self) -> bool:
        with self._lock:
            return self._state == "abandoned" or self._closed

    def publish(self, outcome: Outcome) -> bool:
        """Put the loop's outcome in the slot unless the decision was made. True if it counts."""
        return self._publish(outcome)

    def publish_crash(self) -> bool:
        """Put a worker crash in the slot (the phase is read now, under the lock)."""
        with self._lock:
            if self._closed or self._slot is not None:
                return False
            self._slot = _Crash(self._state == "writing")
            self._done.set()
            return True

    def _publish(self, outcome: Outcome) -> bool:
        with self._lock:
            if self._closed or self._slot is not None:
                return False
            self._slot = outcome
            self._done.set()
            return True

    # --- the main thread's side ------------------------------------------------------------

    def wait(self, seconds: float) -> bool:
        """Wait up to ``seconds`` for a published result (no lock is held while waiting)."""
        return self._done.wait(seconds)

    def settle(self, *, probe: bool = False) -> Verdict:
        """Decide once: the slot first, else by the gate state. Idempotent."""
        with self._lock:
            if self._verdict is not None:
                return self._verdict
            slot = self._slot
            if isinstance(slot, Outcome):
                phase = Gate.WRITING if self._state == "writing" else Gate.IDLE
                verdict = Verdict(
                    Kind.COMPLETED, slot.result, phase, slot.facts, slot.retry_after_s
                )
            elif isinstance(slot, _Crash):
                spec = ErrorSpec("internal", after_writing=slot.writing, probe=probe)
                phase = Gate.WRITING if slot.writing else Gate.IDLE
                verdict = Verdict(Kind.CRASH, spec, phase)
            elif self._state == "writing":
                verdict = Verdict(
                    Kind.DEADLINE, ErrorSpec("outcome_unknown", probe=probe), Gate.WRITING
                )
            else:
                self._state = "abandoned"
                spec = ErrorSpec("network_error", {"tls": False, "timeout": True}, probe=probe)
                verdict = Verdict(Kind.DEADLINE, spec, Gate.IDLE)
            self._closed = True
            self._verdict = verdict
            return verdict


def run_with_deadline(
    gateway: Gateway,
    attempt: Callable[[Callable[[], None]], RawResponse],
    *,
    op: Op,
    deadline: float,
    stop: Callable[[], bool] | None = None,
    gate: WritingGate | None = None,
) -> Verdict:
    """Run the retry loop in a daemon worker and return its verdict by ``deadline``.

    ``deadline`` is an absolute ``gateway.monotonic()`` time (the start of input plus
    ``timeout``). ``attempt(before_write)`` makes one request (``hass.send_once`` and
    ``probe_once`` with the target bound). ``stop`` is polled between slices; a true value is
    decided like the deadline (the signal handler's flag; a raising ``stop`` propagates unsettled,
    so ``stop`` must only read a flag). Returns at the deadline plus at
    most one slice; it never joins the worker.
    """
    the_gate = WritingGate() if gate is None else gate
    probe = op is Op.PROBE
    if not deadline - gateway.monotonic() > 0:  # already passed, or NaN: no worker, no attempt
        return the_gate.settle(probe=probe)  # a result already published still wins

    def remaining() -> float:
        return max(0.0, deadline - gateway.monotonic())

    def work() -> None:
        try:
            outcome = run_attempts(
                attempt, op=op, gate=the_gate, sleep=gateway.sleep, remaining=remaining
            )
            the_gate.publish(outcome)
        except BaseException:  # noqa: BLE001 - handed over as ``internal``; nothing is printed
            the_gate.publish_crash()

    worker = threading.Thread(target=work, name=WORKER_NAME, daemon=True)
    # start() can raise RuntimeError (cannot start new thread); send.deliver maps it to exit 1.
    worker.start()
    while not the_gate.wait(0):
        left = deadline - gateway.monotonic()
        if not left > 0 or (stop is not None and stop()):  # false for NaN
            break
        the_gate.wait(min(left, SLICE_S))
    return the_gate.settle(probe=probe)


def finish(gateway: Gateway, verdict: Verdict, code: int) -> int:
    """End the run with ``code`` after the output is flushed and the log is written.

    When the worker may still be running (a deadline), the process ends through
    ``gateway.exit_process`` and never returns; the worker is not joined. Otherwise ``code`` is
    returned for the normal exit path.
    """
    if verdict.worker_may_run:
        gateway.exit_process(code)
    return code
