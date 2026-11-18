"""Signals (issue #26, docs/interface.md, Home Assistant edge, Deadline).

SIGINT, SIGTERM and SIGHUP are handled once. The handler only records the signal number in a
list (``list.append`` is one atomic step, so no record is lost even if a second handler
interrupts the first; the first recorded signal decides. When several distinct signals are pending
together CPython runs their handlers in ascending signal number, so the lowest is recorded
first); it does no I/O, takes no lock and cannot raise. Everything else happens on
the main thread when it looks at the flag:

- Before the send starts (up to step 6, so also while input is read) a signal is exit 128+N with
  no envelope, no request and no log record (a 128+N exit is never logged): the code calls
  ``check`` at each point where it can stop, and ``remaining`` (see ``bound``) returns 0 so a
  blocked read ends within one slice.
- During the send the flag is the ``stop`` callable of ``deadline.run_with_deadline``: the main
  thread polls it every 100 ms and decides like the deadline, by the gate state. That result
  follows docs/interface.md (Deadline), log step included; ``send.deliver`` passes
  ``SignalState.stopped`` there.

Handlers are installed and restored through the gateway (``install``) and are restored on every
path; ``cli`` keeps them (flag-only) until after the final stream flush, so a late signal cannot
kill the process after the result was reported. The residual is interpreter shutdown after
``main`` returns. The default action of a signal that arrives before ``install`` is the OS's (143
for SIGTERM from a shell); a SIGINT then reaches ``cli.main`` as ``KeyboardInterrupt`` and is
mapped to 130.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager

from ha_notice.gateway import HANDLED_SIGNALS, Gateway

__all__ = ["SignalReceived", "SignalState", "install", "signal_exit_code"]

SIGNAL_EXIT_BASE = 128


def signal_exit_code(signum: int) -> int:
    """The shell convention: 128 + the signal number (SIGTERM 143, SIGINT 130, SIGHUP 129)."""
    return SIGNAL_EXIT_BASE + signum


class SignalReceived(BaseException):
    """Raised on the main thread at a checkpoint after a signal. Not an ``Exception`` so that no
    ``except Exception`` in the tool turns it into an envelope; ``cli.main`` maps it to ``code``."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class SignalState:
    """The flag the handler sets and the main thread reads."""

    def __init__(self) -> None:
        self._received: list[int] = []

    def handler(self, signum: int) -> None:
        """The signal handler. Must stay this small: see the module docstring."""
        self._received.append(signum)

    @property
    def signum(self) -> int | None:
        """The first signal received, or ``None``."""
        received = self._received
        return received[0] if received else None

    @property
    def exit_code(self) -> int | None:
        signum = self.signum
        return None if signum is None else signal_exit_code(signum)

    def stopped(self) -> bool:
        """The ``stop`` callable of ``run_with_deadline``: reads the flag and never raises."""
        return bool(self._received)

    def check(self) -> None:
        """A checkpoint before the send starts: raise ``SignalReceived`` if a signal arrived."""
        code = self.exit_code
        if code is not None:
            raise SignalReceived(code)

    def bound(self, remaining: Callable[[], float]) -> Callable[[], float]:
        """``remaining`` that returns 0 once a signal arrived, so an input read ends within a
        slice. The caller must then ``check`` before it maps the read to a timeout."""

        def bounded() -> float:
            return 0.0 if self._received else remaining()

        return bounded


@contextmanager
def install(gateway: Gateway, state: SignalState) -> Iterator[SignalState]:
    """Install the handlers through the gateway for the duration, restoring them on every path."""
    restore = gateway.install_signal_handlers(HANDLED_SIGNALS, state.handler)
    try:
        yield state
    finally:
        try:
            restore()
        except BaseException:
            state.check()  # a recorded signal's 128+N wins over the restore error
            raise
