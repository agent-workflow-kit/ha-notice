"""The send flow in a real process (issue #27).

Each test starts ``python -c`` with a tiny wrapper that runs ``ha_notice.cli.main`` with the real
gateway, except that the home directory is a private test directory (the tool takes it from the
password database, never from ``HOME``, so a test cannot otherwise keep the log out of the real
state directory). The environment is built by the test (``env -i`` style), the server is a local
fake, and the only process a test signals is the one it started and still holds. A process that
does not end is reported by its timeout, never killed by pattern.
"""

from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ha_notice.output import INSECURE_HTTP_WARNING
from ha_notice.render import tag_from_dedupe_key
from ha_notice.state import STATE_WARNING
from tests.fake_ha import FakeHA, Reply

TOKEN = "HA_SECRET_tok_0f1e2d3c4b5a6978"
WRAPPER = """
import os, sys
from ha_notice.cli import main
from ha_notice.gateway import RealGateway

class Gateway(RealGateway):
    def home_dir(self):
        return os.environ["HA_NOTICE_TEST_HOME"]

sys.exit(main(None, None, Gateway()))
"""
# After ``main`` returned (the result is printed and flushed) the process gets a SIGTERM before it
# ends, as in the window of interpreter exit. The handler must still be ours: with the OS default
# the process would die with 143 (-15 here), which tells a caller that nothing was sent.
LATE_SIGNAL_WRAPPER = WRAPPER.replace(
    "sys.exit(main(None, None, Gateway()))",
    """code = main(None, None, Gateway())
import signal
for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    os.kill(os.getpid(), number)
sys.exit(code)""",
)
LIMIT_S = 60


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir(mode=0o700)
    return path


def make_env(home: Path, **extra: str) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HA_NOTICE_TEST_HOME": str(home),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "XDG_STATE_HOME": str(home),
        "HA_TOKEN": TOKEN,
        "LC_ALL": "C",
    }
    env.update(extra)
    return env


def write_config(tmp: Path, ha: FakeHA, extra: str = "") -> str:
    path = tmp / "config.yaml"
    path.write_text(
        f"base_url: {ha.base_url}\nservice: s\ntimeout: 10s\nallow_insecure_http: true\n{extra}",
        encoding="utf-8",
    )
    return str(path)


def command(*args: str) -> list[str]:
    return [sys.executable, "-c", WRAPPER, *args]


def log_records(home: Path) -> list[dict[str, Any]]:
    path = home / ".local" / "state" / "ha-notice" / "log.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def run(argv: list[str], env: dict[str, str], stdin: bytes = b"", **kw: Any) -> Any:
    return subprocess.run(
        command(*argv),
        input=stdin,
        env=env,
        capture_output=True,
        timeout=LIMIT_S,
        check=False,
        **kw,
    )


def test_a_real_process_sends_and_logs(tmp_path: Path, home: Path) -> None:
    with FakeHA(token=TOKEN) as ha:
        done = run(["--config", write_config(tmp_path, ha), "--json", "send", "--message=hi"],
                   make_env(home))  # fmt: skip
        assert done.returncode == 0 and len(ha.requests) == 1
        assert json.loads(done.stdout)["outcome"] == "sent"
        assert INSECURE_HTTP_WARNING in done.stderr.decode()
        assert [r["outcome"] for r in log_records(home)] == ["sent"]
        everything = (
            done.stdout + done.stderr + (home / ".local/state/ha-notice/log.jsonl").read_bytes()
        )
        assert TOKEN.encode() not in everything


def test_disabled_is_22_in_a_real_process(tmp_path: Path, home: Path) -> None:
    with FakeHA() as ha:
        cfg = write_config(tmp_path, ha, "enabled: false\n")
        done = run(["--config", cfg, "--json", "send", "--stdin-json"], make_env(home), b"x")
        assert (done.returncode, done.stdout, done.stderr) == (22, b'{"outcome":"disabled"}\n', b"")
        assert ha.connections == 0 and log_records(home) == []


def test_closed_stdout_leaves_the_exit_code_unchanged(tmp_path: Path, home: Path) -> None:
    with FakeHA(script=[Reply(), Reply(status=401)]) as ha:
        cfg = write_config(tmp_path, ha)
        argv = command("--config", cfg, "--json", "send", "--message=hi")
        for expected in (0, 12):
            done = subprocess.run(
                ["sh", "-c", 'exec "$@" >&-', "sh", *argv],
                env=make_env(home),
                stdin=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=LIMIT_S,
                check=False,
            )  # fmt: skip
            assert done.returncode == expected
        assert len(ha.requests) == 2


def test_a_pipe_closed_early_leaves_the_exit_code_unchanged(tmp_path: Path, home: Path) -> None:
    with FakeHA(script=[Reply(), Reply(status=401)]) as ha:
        cfg = write_config(tmp_path, ha)
        for expected in (0, 12):
            read_fd, write_fd = os.pipe()
            os.close(read_fd)  # the reader is gone before the result is written
            try:
                done = subprocess.run(
                    command("--config", cfg, "--json", "send", "--message=hi"),
                    env=make_env(home),
                    stdin=subprocess.DEVNULL,
                    stdout=write_fd,
                    stderr=subprocess.PIPE,
                    timeout=LIMIT_S,
                    check=False,
                )
            finally:
                os.close(write_fd)
            assert done.returncode == expected, done.stderr
            assert b"Traceback" not in done.stderr and b"BrokenPipe" not in done.stderr


def test_a_full_disk_on_stdout_leaves_the_exit_code_unchanged(tmp_path: Path, home: Path) -> None:
    with FakeHA(script=[Reply()]) as ha, open("/dev/full", "wb") as full:
        cfg = write_config(tmp_path, ha)
        done = subprocess.run(
            command("--config", cfg, "--json", "send", "--message=hi"),
            env=make_env(home),
            stdin=subprocess.DEVNULL,
            stdout=full,
            stderr=full,
            timeout=LIMIT_S,
            check=False,
        )
        assert done.returncode == 0 and len(ha.requests) == 1
        assert [r["outcome"] for r in log_records(home)] == ["sent"]


def test_a_c_locale_with_a_non_ascii_key_and_message(tmp_path: Path, home: Path) -> None:
    key = "clé-é"
    with FakeHA() as ha:
        cfg = write_config(tmp_path, ha)
        env = {k: v for k, v in make_env(home).items() if k != "HOME"}
        env["LC_ALL"] = "C"
        env["PYTHONUTF8"] = ""
        payload = json.dumps({"message": "héllo ✓"}, ensure_ascii=False).encode()
        done = run(["--config", cfg, "--json", "send", "--stdin-json", f"--dedupe-key={key}"],
                   env, payload)  # fmt: skip
        assert done.returncode == 0, done.stderr
        out = json.loads(done.stdout.decode("utf-8"))
        assert out["dedupe_key"] == key and out["tag_set"] is True
        [request] = ha.requests
        sent = json.loads(request.body.decode("utf-8"))
        assert sent["message"] == "héllo ✓" and sent["data"]["tag"] == tag_from_dedupe_key(key)
        assert "clé-é".encode() in done.stdout  # raw UTF-8 bytes, not \\u escapes


@pytest.fixture
def held() -> Iterator[list[subprocess.Popen[bytes]]]:
    procs: list[subprocess.Popen[bytes]] = []
    yield procs
    for proc in procs:  # only the processes this test started
        if proc.stdin is not None and not proc.stdin.closed:
            proc.stdin.close()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(10)
        for pipe in (proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()


def test_sigterm_during_the_send_reports_by_the_gate_and_logs(
    tmp_path: Path, home: Path, held: list[subprocess.Popen[bytes]]
) -> None:
    with FakeHA(script=[Reply(truncate_after=0, hang=True)]) as ha:
        cfg = write_config(tmp_path, ha)
        proc = subprocess.Popen(
            command("--config", cfg, "--json", "send", "--message=hi"),
            env=make_env(home),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        held.append(proc)
        ha.wait_for_requests(1, 30)  # the request is on the wire: the gate is writing
        started = time.monotonic()
        proc.send_signal(signal.SIGTERM)  # the exact process this test started
        out, err = proc.communicate(timeout=LIMIT_S)
        assert proc.returncode == 12 and time.monotonic() - started < 3
        body = json.loads(out)["error"]
        assert body["code"] == "outcome_unknown" and body["unknown_outcome"] is True
        [rec] = log_records(home)
        assert rec["outcome"] == "outcome_unknown" and rec["exit"] == 12
        assert TOKEN.encode() not in out + err


def test_a_held_log_lock_delays_only_the_log_in_a_real_process(
    tmp_path: Path, home: Path, held: list[subprocess.Popen[bytes]]
) -> None:
    state = home / ".local" / "state" / "ha-notice"
    state.mkdir(parents=True, mode=0o700)
    fd = os.open(state / "log.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        with FakeHA() as ha:
            cfg = write_config(tmp_path, ha)
            started = time.monotonic()
            proc = subprocess.Popen(
                command("--config", cfg, "--json", "send", "--message=hi"),
                env=make_env(home),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            held.append(proc)
            assert proc.stdout is not None
            line = proc.stdout.readline()  # the result, while the log step is still waiting
            line_at = time.monotonic() - started
            assert proc.poll() is None and json.loads(line)["outcome"] == "sent"
            err = proc.stderr.read() if proc.stderr is not None else b""
            assert proc.wait(LIMIT_S) == 0
            total = time.monotonic() - started
    finally:
        os.close(fd)
    assert total - line_at >= 0.5  # the log step waited for the lock
    assert total < 10 + 3  # timeout plus 3 s
    assert err.decode().count(STATE_WARNING) == 1 and log_records(home) == []


def test_a_signal_after_the_result_does_not_change_the_exit_code(
    tmp_path: Path, home: Path
) -> None:
    with FakeHA(token=TOKEN) as ha:
        argv = ["--config", write_config(tmp_path, ha), "--json", "send", "--message=hi"]
        done = subprocess.run(
            [sys.executable, "-c", LATE_SIGNAL_WRAPPER, *argv],
            input=b"",
            env=make_env(home),
            capture_output=True,
            timeout=LIMIT_S,
            check=False,
        )
        assert done.returncode == 0 and json.loads(done.stdout)["outcome"] == "sent"
        assert [r["outcome"] for r in log_records(home)] == ["sent"]
