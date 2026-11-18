"""validate in real processes against the fake Home Assistant (issue #28).

Same wrapper as tests/test_send_process.py: the real gateway with a private home, an ``env -i``
style environment, stdin from /dev/null. The tests signal and stop nothing but their own server.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from ha_notice.output import INSECURE_HTTP_WARNING
from tests.fake_ha import FakeHA, Reply
from tests.harness import schema_errors
from tests.test_send_process import LIMIT_S, TOKEN, command, log_records, make_env


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir(mode=0o700)
    return path


def _no_token(home: Path) -> dict[str, str]:
    env = make_env(home)
    del env["HA_TOKEN"]
    return env


def config(tmp: Path, ha: FakeHA, extra: str = "", timeout: str = "10s") -> str:
    path = tmp / "config.yaml"
    path.write_text(
        f"base_url: {ha.base_url}\nservice: s\ntimeout: {timeout}\n"
        f"allow_insecure_http: true\n{extra}",
        encoding="utf-8",
    )
    return str(path)


def validate(cfg: str, home: Path, *args: str, env: dict[str, str] | None = None) -> Any:
    return subprocess.run(
        command("--config", cfg, "--json", "validate", *args),
        env=make_env(home) if env is None else env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=LIMIT_S,
        check=False,
    )


def test_probe_ok_over_a_real_socket(tmp_path: Path, home: Path) -> None:
    with FakeHA(token=TOKEN, script=[Reply(body=b"{}")]) as ha:
        done = validate(config(tmp_path, ha), home, "--probe")
        body = json.loads(done.stdout)
        assert done.returncode == 0 and schema_errors("cli/validate", body) == []
        assert body["probe"] == {"api_ok": True}
        assert [(r.method, r.path) for r in ha.requests] == [("GET", "/api/")]
        assert ha.requests[0].header("Authorization") == f"Bearer {TOKEN}"
        assert ha.requests[0].header("Content-Type") is None
        assert INSECURE_HTTP_WARNING in done.stderr.decode()
        assert TOKEN.encode() not in done.stdout + done.stderr
        assert log_records(home) == []


def test_the_default_route_answers_a_probe_with_a_json_object(tmp_path: Path, home: Path) -> None:
    with FakeHA(token=TOKEN) as ha:
        assert validate(config(tmp_path, ha), home, "--probe").returncode == 0


def test_a_wrong_token_is_exit_12_with_auth_required(tmp_path: Path, home: Path) -> None:
    with FakeHA(token="HA_other") as ha:
        done = validate(config(tmp_path, ha), home, "--probe")
        body = json.loads(done.stdout)
        assert done.returncode == 12 and body["probe"] == {"api_ok": False}
        assert body["checks"][-1]["message"] == "auth_required (HTTP 401)"


def test_a_wrong_path_prefix_is_a_404(tmp_path: Path, home: Path) -> None:
    with FakeHA(token=TOKEN, prefix="x") as ha:
        done = validate(config(tmp_path, ha), home, "--probe")
        assert done.returncode == 12
        assert "base_url" in json.loads(done.stdout)["checks"][-1]["message"]


def test_a_200_list_fails_the_probe(tmp_path: Path, home: Path) -> None:
    with FakeHA(script=[Reply(body=b"[]")]) as ha:
        done = validate(config(tmp_path, ha), home, "--probe")
        assert done.returncode == 12 and json.loads(done.stdout)["probe"] == {"api_ok": False}


def test_a_stalled_host_ends_within_the_deadline_plus_three_seconds(
    tmp_path: Path, home: Path
) -> None:
    with FakeHA(script=[Reply(stall_before_read=True)]) as ha:
        started = time.monotonic()
        done = validate(config(tmp_path, ha, timeout="1s"), home, "--probe")
        assert time.monotonic() - started < 4
        body = json.loads(done.stdout)
        assert done.returncode == 12 and body["probe"] == {"api_ok": False}
        assert body["checks"][-1]["message"] == "outcome_unknown"


def test_a_429_is_retried_once_the_wait_fits(tmp_path: Path, home: Path) -> None:
    with FakeHA(script=[Reply(status=429, body=b"x"), Reply(body=b"{}")]) as ha:
        done = validate(config(tmp_path, ha), home, "--probe")
        assert done.returncode == 0 and len(ha.requests) == 2
        assert done.stderr.decode().count(INSECURE_HTTP_WARNING) == 1


def test_plain_validate_opens_no_connection_and_ignores_stdin(tmp_path: Path, home: Path) -> None:
    with FakeHA() as ha:
        done = validate(config(tmp_path, ha), home, env=_no_token(home))
        assert done.returncode == 12 and ha.connections == 0
        done = validate(config(tmp_path, ha), home)
        assert done.returncode == 0 and ha.connections == 0 and done.stderr == b""


def test_disabled_probe_is_22_in_a_real_process(tmp_path: Path, home: Path) -> None:
    with FakeHA() as ha:
        done = validate(
            config(tmp_path, ha, "enabled: false\n"), home, "--probe", env=_no_token(home)
        )
        assert (done.returncode, done.stdout) == (22, b'{"outcome":"disabled"}\n')
        assert ha.connections == 0
