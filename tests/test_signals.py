"""Signals (issue #26): SIGTERM, SIGINT and SIGHUP before the send, the stop seam, processes."""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ha_notice.cli import main
from ha_notice.deadline import Kind, run_with_deadline
from ha_notice.gateway import HANDLED_SIGNALS, RealGateway
from ha_notice.hass import RawResponse
from ha_notice.response import Gate, Op
from ha_notice.signals import SignalReceived, SignalState, install, signal_exit_code
from tests.fake_gateway import FakeGateway, StallingSource

SIGNALS = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]


# --- the pure pieces ----------------------------------------------------------------------


def test_exit_codes_are_128_plus_n() -> None:
    assert [signal_exit_code(s) for s in SIGNALS] == [143, 130, 129]


def test_the_handled_signals_are_exactly_the_three() -> None:
    assert set(HANDLED_SIGNALS) == set(SIGNALS)


def test_the_first_signal_wins() -> None:
    state = SignalState()
    assert state.signum is None and state.exit_code is None and not state.stopped()
    state.check()  # nothing received: no raise
    state.handler(signal.SIGHUP)
    state.handler(signal.SIGTERM)
    assert state.signum == signal.SIGHUP and state.exit_code == 129 and state.stopped()
    with pytest.raises(SignalReceived) as raised:
        state.check()
    assert raised.value.code == 129


def test_signal_received_is_not_an_exception() -> None:
    assert not issubclass(SignalReceived, Exception)


def test_bound_remaining_is_zero_after_a_signal() -> None:
    state = SignalState()
    bound = state.bound(lambda: 7.0)
    assert bound() == 7.0
    state.handler(signal.SIGINT)
    assert bound() == 0.0


def test_the_handler_does_nothing_but_record() -> None:
    state = SignalState()
    for _ in range(1000):
        state.handler(signal.SIGTERM)
    assert state.signum == signal.SIGTERM


def test_install_registers_and_restores_through_the_gateway() -> None:
    fake = FakeGateway()
    state = SignalState()
    with install(fake, state):
        assert set(fake.handlers) == set(SIGNALS)
        assert fake.deliver_signal(signal.SIGTERM)
    assert fake.handlers == {} and fake.restore_count == 1
    assert state.signum == signal.SIGTERM
    assert not fake.deliver_signal(signal.SIGTERM)


def test_install_restores_when_the_body_raises() -> None:
    fake = FakeGateway()
    with pytest.raises(RuntimeError), install(fake, SignalState()):
        raise RuntimeError
    assert fake.handlers == {} and fake.restore_count == 1


def test_real_gateway_installs_and_restores_the_previous_handlers() -> None:
    gw = RealGateway()
    before = {s: signal.getsignal(s) for s in SIGNALS}
    seen: list[int] = []
    restore = gw.install_signal_handlers(HANDLED_SIGNALS, seen.append)
    try:
        os.kill(os.getpid(), signal.SIGHUP)  # our own pid: this test started it
        deadline = time.monotonic() + 5
        while not seen and time.monotonic() < deadline:
            time.sleep(0.01)
        assert seen == [signal.SIGHUP]
    finally:
        restore()
    restore()  # idempotent
    assert {s: signal.getsignal(s) for s in SIGNALS} == before


def test_real_gateway_off_the_main_thread_installs_nothing() -> None:
    gw = RealGateway()
    before = {s: signal.getsignal(s) for s in SIGNALS}
    result: list[Callable[[], None]] = []
    t = threading.Thread(
        target=lambda: result.append(gw.install_signal_handlers(HANDLED_SIGNALS, print))
    )
    t.start()
    t.join(5)
    result[0]()
    assert {s: signal.getsignal(s) for s in SIGNALS} == before


# --- the send flow with the fake gateway ---------------------------------------------------


@pytest.fixture
def cfg(tmp_path: Path) -> str:
    path = tmp_path / "c.yaml"
    path.write_text("enabled: true\ntimeout: 30s\n", encoding="utf-8")
    return str(path)


class Hooked(FakeGateway):
    """Calls ``hook`` on the first ``read_source`` and at each ``isatty``."""

    hook: Callable[[], object] | None = None

    def read_source(self, source: Any, max_bytes: int, remaining: Callable[[], float]) -> Any:
        if self.hook is not None:
            self.hook()
        return super().read_source(source, max_bytes, remaining)


def _run(
    capsys: pytest.CaptureFixture[str], argv: list[str], gateway: FakeGateway
) -> tuple[int, str, str]:
    code = main(argv, {}, gateway)
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.mark.parametrize("signum", SIGNALS)
def test_a_signal_during_a_stalled_input_is_128_plus_n(
    capsys: pytest.CaptureFixture[str], cfg: str, signum: int
) -> None:
    fake = FakeGateway(sources={0: StallingSource(b'{"mess')})
    fake.schedule_signal(fake.now + 2.5, signum)  # arrives in a wait slice of the read
    code, out, err = _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], fake)
    assert (code, out, err) == (128 + signum, "", "")
    assert fake.handlers == {} and fake.restore_count == 1
    assert fake.exits == [] and fake.connections == []


def test_a_signal_is_not_read_as_a_timeout(capsys: pytest.CaptureFixture[str], cfg: str) -> None:
    fake = FakeGateway(sources={0: StallingSource(b"")})
    fake.schedule_signal(fake.now + 0.5, signal.SIGTERM)
    code, out, _ = _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], fake)
    assert code == 143 and "unavailable" not in out


def test_a_signal_at_the_start_of_the_read(capsys: pytest.CaptureFixture[str], cfg: str) -> None:
    fake = Hooked(sources={0: b'{"message":"hi"}'})
    fake.hook = lambda: fake.deliver_signal(signal.SIGINT)
    code, out, err = _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], fake)
    assert (code, out, err) == (130, "", "")


def test_a_signal_after_a_complete_read_still_wins_before_the_output(
    capsys: pytest.CaptureFixture[str], cfg: str
) -> None:
    fake = Hooked(sources={0: b'{"message":"hi"}'})
    original = fake.read_source

    def read(source: Any, max_bytes: int, remaining: Callable[[], float]) -> Any:
        result = original(source, max_bytes, remaining)
        fake.deliver_signal(signal.SIGTERM)  # after the last byte, before the output
        return result

    fake.read_source = read  # type: ignore[method-assign]
    code, out, err = _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], fake)
    assert (code, out, err) == (143, "", "")


def test_a_signal_with_input_that_is_invalid_is_still_a_signal(
    capsys: pytest.CaptureFixture[str], cfg: str
) -> None:
    fake = Hooked(sources={0: b"not json"})
    original = fake.read_source

    def read(source: Any, max_bytes: int, remaining: Callable[[], float]) -> Any:
        result = original(source, max_bytes, remaining)
        fake.deliver_signal(signal.SIGHUP)
        return result

    fake.read_source = read  # type: ignore[method-assign]
    code, out, err = _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], fake)
    assert (code, out, err) == (129, "", "")


def test_a_signal_during_a_file_read(
    capsys: pytest.CaptureFixture[str], cfg: str, tmp_path: Path
) -> None:
    path = tmp_path / "n.json"
    path.write_text('{"message":"hi"}', encoding="utf-8")
    fake = Hooked(sources={str(path): b'{"message":"hi"}'})
    fake.hook = lambda: fake.deliver_signal(signal.SIGTERM)
    code, out, _ = _run(
        capsys, ["--json", "--config", cfg, "send", "--dry-run", f"--file={path}"], fake
    )
    assert (code, out) == (143, "")


def test_first_signal_decides_the_code(capsys: pytest.CaptureFixture[str], cfg: str) -> None:
    fake = FakeGateway(sources={0: StallingSource(b"")})
    fake.schedule_signal(fake.now + 0.5, signal.SIGHUP)
    fake.schedule_signal(fake.now + 0.6, signal.SIGTERM)
    code, _, _ = _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], fake)
    assert code == 129


def test_a_signal_is_never_logged(
    capsys: pytest.CaptureFixture[str], cfg: str, tmp_path: Path
) -> None:
    fake = FakeGateway(sources={0: StallingSource(b"")})
    fake.schedule_signal(fake.now + 0.5, signal.SIGTERM)
    _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], fake)
    assert fake.exits == []
    assert not (tmp_path / ".local").exists()


def test_without_a_signal_the_handlers_are_restored_too(
    capsys: pytest.CaptureFixture[str], cfg: str
) -> None:
    fake = FakeGateway(sources={0: b'{"message":"hi"}'})
    code, _, _ = _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], fake)
    assert code == 0 and fake.install_count == 1 and fake.restore_count == 1


def test_handlers_are_restored_after_an_internal_error(
    capsys: pytest.CaptureFixture[str], cfg: str
) -> None:
    class Boom(FakeGateway):
        def read_source(self, *a: Any, **k: Any) -> Any:
            raise RuntimeError("boom")

    fake = Boom()
    code, out, _ = _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], fake)
    assert code == 1 and "boom" not in out
    assert fake.restore_count == 1


def test_keyboard_interrupt_is_130_and_prints_nothing(
    capsys: pytest.CaptureFixture[str], cfg: str
) -> None:
    class Interrupted(FakeGateway):
        def read_source(self, *a: Any, **k: Any) -> Any:
            raise KeyboardInterrupt

    fake = Interrupted()
    code, out, err = _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], fake)
    assert (code, out, err) == (130, "", "")
    assert fake.restore_count == 1


def test_system_exit_is_an_internal_error_without_its_text(
    capsys: pytest.CaptureFixture[str], cfg: str
) -> None:
    class Exits(FakeGateway):
        def read_source(self, *a: Any, **k: Any) -> Any:
            raise SystemExit("secret text")

    code, out, err = _run(capsys, ["--json", "--config", cfg, "send", "--dry-run"], Exits())
    assert code == 1 and "secret" not in out + err


# --- the stop seam of the deadline ---------------------------------------------------------


def test_stop_wired_to_the_flag_settles_by_the_gate_state() -> None:
    state = SignalState()
    release = threading.Event()

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        release.wait(10)
        raise OSError

    fake = FakeGateway()
    threading.Timer(0.25, lambda: state.handler(signal.SIGTERM)).start()
    started = time.monotonic()
    try:
        verdict = run_with_deadline(
            fake, attempt, op=Op.SEND, deadline=fake.monotonic() + 60, stop=state.stopped
        )
    finally:
        release.set()
    assert verdict.kind is Kind.DEADLINE and verdict.gate is Gate.IDLE
    assert time.monotonic() - started < 1.5  # noticed within a slice
    assert state.exit_code == 143


# --- real processes -----------------------------------------------------------------------

CHILD = """
import sys
from ha_notice.cli import main
from ha_notice.gateway import RealGateway

class Ready(RealGateway):
    def install_signal_handlers(self, signals, on_signal):
        restore = super().install_signal_handlers(signals, on_signal)
        sys.stderr.write("ready\\n")
        sys.stderr.flush()
        return restore

sys.exit(main(sys.argv[1:], gateway=Ready()))
"""


def _start(tmp_path: Path, extra: list[str]) -> subprocess.Popen[bytes]:
    cfg = tmp_path / "c.yaml"
    cfg.write_text("enabled: true\ntimeout: 30s\n", encoding="utf-8")
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path), "LC_ALL": "C"}
    return subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            CHILD,
            "--json",
            "--config",
            str(cfg),
            "send",
            "--dry-run",
            *extra,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )


def _wait_ready(proc: subprocess.Popen[bytes]) -> None:
    assert proc.stderr is not None
    ready, _, _ = select.select([proc.stderr], [], [], 30)
    assert ready, "the child never installed its handlers"
    assert proc.stderr.readline() == b"ready\n"


@pytest.mark.parametrize("signum", SIGNALS)
def test_a_real_process_exits_128_plus_n_on_a_stalled_stdin(tmp_path: Path, signum: int) -> None:
    proc = _start(tmp_path, [])
    try:
        _wait_ready(proc)
        assert proc.stdin is not None
        proc.stdin.write(b'{"message": "he')  # a producer that stalls
        proc.stdin.flush()
        time.sleep(0.2)
        started = time.monotonic()
        os.kill(proc.pid, signum)  # the child this test started
        proc.wait(timeout=20)  # stdin stays open: only the signal can end the read
        assert time.monotonic() - started < 5
        assert proc.stdout is not None and proc.stderr is not None
        out, err = proc.stdout.read(), proc.stderr.read()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(10)
    assert proc.returncode == 128 + signum
    assert out == b"" and err == b""
    assert not (tmp_path / ".local").exists()


def test_a_real_process_without_a_signal_still_works(tmp_path: Path) -> None:
    proc = _start(tmp_path, ["--message=hi"])
    try:
        out, _ = proc.communicate(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(10)
    assert proc.returncode == 0 and json.loads(out)["outcome"] == "dry_run"
