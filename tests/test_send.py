"""The send flow end to end (issue #27): ``cli.main(argv, env, gateway)`` with a fake gateway.

Steps 5 to 7 of docs/interface.md: the token, the POST in the deadline worker, the result on
stdout and stderr, then the log step. The clock is the fake gateway's, so nothing sleeps; the
deadline and signal tests advance it from a test-owned thread that is joined in the test.
Real-socket tests are in tests/test_send_socket.py and real processes in
tests/test_send_process.py.
"""

from __future__ import annotations

import http.client
import json
import os
import signal
import stat
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from ha_notice import __version__, deadline
from ha_notice import send as send_module
from ha_notice.cli import main
from ha_notice.gateway import CaCandidates
from ha_notice.log import ROTATE_AT
from ha_notice.output import (
    INSECURE_HTTP_WARNING,
    MESSAGES,
    emitted_exit,
    record_emitted,
)
from ha_notice.render import serialize
from ha_notice.state import STATE_WARNING
from tests.fake_gateway import (
    ConnectionScript,
    FakeExit,
    FakeGateway,
    StallingSource,
    private_home,
)
from tests.harness import Golden, schema_errors

TOKEN = "HA_SECRET_tok_9f8e7d6c5b4a3210"
ENV = {"HA_TOKEN": TOKEN}
BASE = "base_url: https://ha.example\nservice: mobile_app_x\n"
FLAGS = [
    "--title=Backup done",
    "--message=Nightly backup finished",
    "--level=warn",
    "--link=https://ha.example/x",
    "--dedupe-key=k1",
]
TIMEOUT_S = 5.0
Result = tuple[int, str, str]


@dataclass
class Rig:
    """A private home, a config writer and a runner that records how the process ended."""

    tmp: Path
    gw: FakeGateway
    capsys: pytest.CaptureFixture[str]
    exited: bool = False

    @property
    def state_dir(self) -> Path:
        return Path(self.gw.home) / ".local" / "state" / "ha-notice"  # type: ignore[arg-type]

    @property
    def log_path(self) -> Path:
        return self.state_dir / "log.jsonl"

    def cfg(self, text: str = BASE + "default_group: ops\n", timeout: int = int(TIMEOUT_S)) -> str:
        path = self.tmp / "c.yaml"
        path.write_text(f"timeout: {timeout}s\n{text}", encoding="utf-8")
        return str(path)

    def run(
        self,
        argv: list[str],
        *,
        config: str | None = None,
        env: dict[str, str] | None = None,
        gateway: FakeGateway | None = None,
    ) -> Result:
        gw = self.gw if gateway is None else gateway
        cfg = self.cfg() if config is None else config
        self.exited = False
        try:
            code = main(["--config", cfg, *argv], ENV if env is None else env, gw)
        except FakeExit as done:  # the worker may still run: the process ends through exit_process
            self.exited = True
            code = done.code
        out = self.capsys.readouterr()
        return code, out.out, out.err

    def records(self) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        lines = self.log_path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines]

    def log_text(self) -> str:
        return self.log_path.read_text(encoding="utf-8").replace(
            f'"version":"{__version__}"', '"version":"0.1.0"'
        )


@pytest.fixture
def rig(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    self_signed_cert: tuple[Path, Path],
) -> Rig:
    gw = FakeGateway(
        home=private_home(tmp_path),
        ca=CaCandidates(str(self_signed_cert[0]), "", ()),
        sources={0: b'{"message":"hi"}'},
    )
    return Rig(tmp_path, gw, capsys)


def error_of(out: str) -> dict[str, Any]:
    doc = json.loads(out)
    assert schema_errors("cli/error", doc) == []
    return doc["error"]  # type: ignore[no-any-return]


def only_request(gw: FakeGateway) -> Any:
    assert len(gw.connections) == 1 and len(gw.connections[0].requests) == 1
    return gw.connections[0].requests[0]


# --- success --------------------------------------------------------------------------------


def test_sent_json_output_log_and_request_goldens(rig: Rig, golden: Golden) -> None:
    code, out, err = rig.run(["--json", "send", *FLAGS])
    assert (code, err) == (0, "")
    assert schema_errors("cli/send", json.loads(out)) == []
    golden.check("output", "send-sent.json", out)
    request = only_request(rig.gw)
    golden.check("request", "dry-run.json", request.body.decode())
    assert request.method == "POST"
    assert request.path == "/api/services/notify/mobile_app_x"
    golden.check("log", "send-sent.jsonl", rig.log_text(), schema="log")
    assert not rig.exited  # a completed send returns normally


def test_the_post_body_is_the_dry_run_body_for_flags_and_stdin(rig: Rig) -> None:
    code, out, _ = rig.run(["--json", "--dry-run", "send", *FLAGS])
    assert code == 0
    dry = serialize(json.loads(out)["rendered"])
    rig.run(["send", *FLAGS])
    rig.gw.sources[0] = json.dumps(
        {"title": "Backup done", "message": "Nightly backup finished", "level": "warn"}
        | {"link": "https://ha.example/x"}
    ).encode()
    rig.run(["send", "--stdin-json", "--dedupe-key=k1"])
    bodies = [c.requests[0].body for c in rig.gw.connections]
    assert bodies == [dry, dry]  # flag and stdin parity, and what was sent is what was shown


def test_the_request_carries_the_token_only_as_the_header(rig: Rig) -> None:
    rig.run(["send", "--message=hi"])
    request = only_request(rig.gw)
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"
    assert TOKEN not in request.path and TOKEN.encode() not in request.body
    assert [h for h, v in request.headers.items() if TOKEN in v] == ["Authorization"]
    assert rig.gw.resolve_calls == [("ha.example", 443)]
    assert all(c.spec.host == "ha.example" for c in rig.gw.connections)


def test_human_line_and_quiet(rig: Rig) -> None:
    assert rig.run(["send", *FLAGS]) == (0, "", "sent (warn, 0 ms)\n")
    assert rig.run(["--quiet", "send", *FLAGS]) == (0, "", "")
    assert rig.run(["--quiet", "--json", "send", "--message=hi"])[2] == ""


def test_a_slow_send_reports_its_duration(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(connect_delay=1.5)
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    assert code == 0 and json.loads(out)["duration_ms"] == 1500
    assert rig.records()[0]["duration_ms"] == 1500


def test_429_twice_then_sent_waits_2_then_4(rig: Rig) -> None:
    rig.gw.scripts.extend([ConnectionScript(status=429), ConnectionScript(status=429)])
    code, out, _ = rig.run(["--json", "send", "--message=hi"], config=rig.cfg(timeout=10))
    assert code == 0 and rig.gw.sleeps == [2, 4] and len(rig.gw.connections) == 3
    assert json.loads(out)["duration_ms"] == 6000


def test_verbose_prints_one_line_per_phase_and_nothing_secret(rig: Rig) -> None:
    code, _, err = rig.run(["--verbose", "send", *FLAGS])
    assert code == 0
    lines = [line.split(":")[0] for line in err.splitlines()]
    assert lines == ["input", "render", "send", "sent (warn, 0 ms)", "log"]
    for secret in (TOKEN, "ha.example", "mobile_app_x", "Backup", "/api/"):
        assert secret not in err


# --- the response table through the CLI -----------------------------------------------------


@dataclass(frozen=True)
class Row:
    script: ConnectionScript
    exit: int
    code: str | None
    status: int | None
    retryable: bool | None
    unknown: bool | None
    requests: int = 1


def _row(status: int, body: bytes = b"[]", **kw: Any) -> ConnectionScript:
    return ConnectionScript(status=status, body=body, **kw)


ROWS: dict[str, Row] = {
    "200_list": Row(_row(200), 0, None, 200, None, None),
    "200_list_content": Row(_row(200, b'[{"a":1}]'), 0, None, 200, None, None),
    "200_object": Row(_row(200, b"{}"), 12, "wrong_host_response", 200, False, True),
    "200_not_json": Row(_row(200, b"<html>"), 12, "wrong_host_response", 200, False, True),
    "200_empty": Row(_row(200, b""), 12, "wrong_host_response", 200, False, True),
    "200_dup_keys": Row(_row(200, b'[{"a":1,"a":2}]'), 12, "wrong_host_response", 200, False, True),
    "201": Row(_row(201), 12, "wrong_host_response", 201, False, True),
    "204": Row(_row(204, b""), 12, "wrong_host_response", 204, False, True),
    "301": Row(_row(301, b""), 12, "wrong_host_response", 301, False, False),
    "307": Row(_row(307, b""), 12, "wrong_host_response", 307, False, False),
    "400": Row(_row(400), 12, "host_rejected", 400, False, False),
    "401": Row(_row(401), 12, "auth_required", 401, False, False),
    "403": Row(_row(403), 12, "auth_required", 403, False, False),
    "404": Row(_row(404), 12, "wrong_host_response", 404, False, False),
    "405": Row(_row(405), 12, "wrong_host_response", 405, False, False),
    "418": Row(_row(418), 12, "wrong_host_response", 418, False, False),
    "429": Row(_row(429), 12, "rate_limited", 429, True, False, requests=3),
    "500": Row(_row(500), 12, "upstream_error", 500, False, True),
    "502": Row(_row(502), 12, "upstream_error", 502, False, True),
    "504": Row(_row(504), 12, "upstream_error", 504, False, True),
    # Not a status: like an answer that is not HTTP (details null, outcome possibly delivered).
    "100": Row(_row(100), 12, "wrong_host_response", None, False, True),
    "101": Row(_row(101), 12, "wrong_host_response", None, False, True),
    "199": Row(_row(199), 12, "wrong_host_response", None, False, True),
    "600": Row(_row(600), 12, "wrong_host_response", None, False, True),
    "999": Row(_row(999), 12, "wrong_host_response", None, False, True),
}


@pytest.mark.parametrize("name", list(ROWS))
def test_response_table(rig: Rig, name: str) -> None:
    row = ROWS[name]
    rig.gw.default_script = row.script
    code, out, err = rig.run(["--json", "send", "--message=hi"], config=rig.cfg(timeout=10))
    assert code == row.exit and len(rig.gw.connections) == row.requests
    if row.exit == 0:
        assert json.loads(out)["http_status"] == row.status
        return
    body = error_of(out)
    assert body["code"] == row.code
    assert body["retryable"] is row.retryable and body["unknown_outcome"] is row.unknown
    if row.status is None:
        assert body["details"] is None
    else:
        assert body["details"]["http_status"] == row.status
    assert err == f"{body['code']}: {body['message']}\n"
    assert (body["retry_after_s"] == 4) == (name == "429")
    record = rig.records()[0]
    assert record["exit"] == 12 and record["code"] == row.code
    assert record["outcome"] == ("outcome_unknown" if row.unknown else "failed")
    assert record["http_status"] == row.status
    assert schema_errors("log", record) == []


@pytest.mark.parametrize("name", [n for n, r in ROWS.items() if r.exit == 12])
def test_response_table_with_a_dedupe_key(rig: Rig, name: str) -> None:
    """With a tag ``upstream_error`` (and ``outcome_unknown``) is retryable, a retry replaces the
    notification; every other cell, ``wrong_host_response`` after a 2xx included, is unchanged.
    The log records ``tag_set``."""
    row = ROWS[name]
    rig.gw.default_script = row.script
    argv = ["--json", "send", "--message=hi", "--dedupe-key=k"]
    code, out, _ = rig.run(argv, config=rig.cfg(timeout=10))
    body = error_of(out)
    assert code == 12 and body["code"] == row.code and body["unknown_outcome"] is row.unknown
    assert body["retryable"] is (True if row.code == "upstream_error" else row.retryable)
    record = rig.records()[0]
    assert record["tag_set"] is True and schema_errors("log", record) == []


def test_400_carries_the_hint_and_404_names_base_url(rig: Rig) -> None:
    rig.gw.default_script = _row(400)
    body = error_of(rig.run(["--json", "send", "--message=hi"])[1])
    assert body["details"]["hint"].startswith("check the notify service name")
    rig.gw.default_script = _row(404)
    body = error_of(rig.run(["--json", "send", "--message=hi"])[1])
    assert "base_url" in body["message"]


def test_exit_12_human_lines_are_fixed(rig: Rig) -> None:
    table = {
        401: "auth_required",
        500: "upstream_error",
        404: "wrong_host_response",
        400: "host_rejected",
    }
    for status, code in table.items():
        rig.gw.default_script = _row(status)
        got = rig.run(["send", "--message=hi"])
        message = error_of(rig.run(["--json", "send", "--message=hi"])[1])["message"]
        assert got == (12, "", f"{code}: {message}\n")
        if code != "wrong_host_response":
            assert message == MESSAGES[code]


def test_429_three_times_is_rate_limited_with_waits_2_and_4(rig: Rig) -> None:
    rig.gw.default_script = _row(429)
    code, out, _ = rig.run(["--json", "send", "--message=hi"], config=rig.cfg(timeout=10))
    assert code == 12 and rig.gw.sleeps == [2, 4]
    assert error_of(out)["retry_after_s"] == 4


def test_429_whose_wait_does_not_fit_ends_at_once(rig: Rig) -> None:
    rig.gw.default_script = _row(429, connect_delay=2.9)
    code, out, _ = rig.run(["--json", "send", "--message=hi"], config=rig.cfg(timeout=4))
    assert code == 12 and rig.gw.sleeps == []  # 1.1 s left, the 2 s wait is not performed
    assert error_of(out)["retry_after_s"] == 2


# --- exceptions by phase ----------------------------------------------------------------------


def test_connect_refused_is_retried_once_then_network_error(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(connect_error=ConnectionRefusedError(111, "x"))
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 12 and body["code"] == "network_error"
    assert body["details"] == {"tls": False, "timeout": False}
    assert body["retryable"] is True and body["unknown_outcome"] is False
    assert len(rig.gw.connections) == 2 and rig.gw.sleeps == [2]
    assert all(c.bytes_written == 0 for c in rig.gw.connections)
    assert rig.records()[0]["outcome"] == "failed"


@pytest.mark.parametrize(
    "exc",
    [
        ConnectionResetError(104, "x"),
        BrokenPipeError(32, "x"),
        TimeoutError("x"),
        http.client.RemoteDisconnected("x"),
        http.client.IncompleteRead(b""),
    ],
)
@pytest.mark.parametrize("tagged", [False, True])
def test_a_loss_after_writing_is_outcome_unknown_and_never_retried(
    rig: Rig, exc: BaseException, tagged: bool
) -> None:
    rig.gw.default_script = ConnectionScript(response_error=exc)
    key = ["--dedupe-key=k"] if tagged else []
    code, out, _ = rig.run(["--json", "send", "--message=hi", *key])
    body = error_of(out)
    assert code == 12 and body["code"] == "outcome_unknown"
    assert body["unknown_outcome"] is True and body["retryable"] is tagged
    assert len(rig.gw.connections) == 1 and rig.gw.sleeps == []
    assert rig.records()[0]["outcome"] == "outcome_unknown"
    assert rig.records()[0]["tag_set"] is tagged


def test_a_non_http_answer_after_writing_is_wrong_host_response_unknown(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(response_error=http.client.BadStatusLine("x"))
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 12 and body["code"] == "wrong_host_response"
    assert body["details"] is None and body["unknown_outcome"] is True
    assert rig.records()[0]["outcome"] == "outcome_unknown"


def test_an_exception_from_the_first_request_call_is_outcome_unknown(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(
        request_error=ConnectionResetError(104, "x"), request_bytes_before_error=0
    )
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    assert code == 12 and error_of(out)["code"] == "outcome_unknown"


def test_connect_and_io_timeouts_never_exceed_the_time_that_remains(rig: Rig) -> None:
    rig.run(["send", "--message=hi"], config=rig.cfg(BASE + "connect_timeout: 20s\n", timeout=7))
    spec = rig.gw.connections[0].spec
    assert spec.connect_timeout == 7.0 and spec.io_timeout == 7.0
    rig.run(["send", "--message=hi"], config=rig.cfg(BASE + "connect_timeout: 2s\n", timeout=7))
    assert rig.gw.connections[1].spec.connect_timeout == 2.0


# --- credential, trust ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [None, "", "  ", "has space", "tab\there", "é" * 3, "x" * 4097, "ab\r\ncd", "€", "日本"],
)
def test_a_bad_token_is_credential_invalid_with_the_name_only(rig: Rig, value: str | None) -> None:
    env = {} if value is None else {"HA_TOKEN": value}
    code, out, err = rig.run(["--json", "send", "--message=hi"], env=env)
    body = error_of(out)
    assert code == 12 and body["code"] == "credential_invalid"
    assert body["details"] == {"env": "HA_TOKEN"}
    assert body["retryable"] is False and body["unknown_outcome"] is False
    assert rig.gw.connections == [] and rig.gw.resolve_calls == []
    if value:
        assert value not in out + err + rig.log_text()
    assert rig.records()[0]["code"] == "credential_invalid"


def test_the_token_env_named_by_the_config_is_the_one_read(rig: Rig) -> None:
    config = rig.cfg(BASE + "token_env: HA_OTHER\n")
    code, out, _ = rig.run(["--json", "send", "--message=hi"], config=config)
    assert code == 12 and error_of(out)["details"] == {"env": "HA_OTHER"}
    code, _, _ = rig.run(["--json", "send", "--message=hi"], config=config, env={"HA_OTHER": TOKEN})
    assert code == 0


def test_a_trailing_crlf_is_trimmed(rig: Rig) -> None:
    assert rig.run(["send", "--message=hi"], env={"HA_TOKEN": TOKEN + "\r\n"})[0] == 0
    assert only_request(rig.gw).headers["Authorization"] == f"Bearer {TOKEN}"


def test_the_token_is_read_after_the_input(rig: Rig) -> None:
    rig.gw.sources[0] = b"{}"  # refused at step 3: the credential is never looked at
    code, _, _ = rig.run(["--json", "send", "--stdin-json"], env={})
    assert code == 20 and rig.gw.connections == []
    code, out, _ = rig.run(["--json", "send", "--message=hi"], env={})
    assert code == 12 and error_of(out)["code"] == "credential_invalid"


def test_no_usable_trust_is_network_error_with_tls_and_no_connection(rig: Rig) -> None:
    rig.gw.ca = CaCandidates("", "", ())
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 12 and body["code"] == "network_error"
    assert body["details"] == {"tls": True, "timeout": False} and body["retryable"] is False
    assert "CA certificates" in body["message"] and rig.gw.connections == []


# --- disabled, usage, config ------------------------------------------------------------------


def test_disabled_with_a_real_send_is_22_without_input_token_or_connection(rig: Rig) -> None:
    config = rig.cfg(BASE + "enabled: false\n")
    assert rig.run(["--json", "send", "--message=hi"], config=config, env={}) == (
        22,
        '{"outcome":"disabled"}\n',
        "",
    )
    assert rig.run(["send", "--message=hi"], config=config) == (22, "", "disabled in config\n")
    assert rig.gw.connections == [] and rig.records() == [] and not rig.state_dir.exists()


def test_disabled_does_not_hide_a_flag_combination_error(rig: Rig) -> None:
    config = rig.cfg("enabled: false\n")
    argv = ["--json", "send", "--stdin-json", "--file", "x", "--dedupe-key=k"]
    code, out, _ = rig.run(argv, config=config)
    assert code == 2 and error_of(out)["code"] == "usage"


def test_missing_destination_exits_2_before_stdin_is_read(rig: Rig) -> None:
    reads: list[int | str] = []
    original = rig.gw.read_source

    def spy(source: int | str, max_bytes: int, remaining: Callable[[], float]) -> Any:
        reads.append(source)
        return original(source, max_bytes, remaining)

    rig.gw.read_source = spy  # type: ignore[method-assign]
    code, out, _ = rig.run(["--json", "send", "--stdin-json"], config=rig.cfg("service: x\n"))
    assert code == 2 and error_of(out)["details"] == {"key": "base_url"} and reads == []


def test_the_insecure_http_warning_survives_quiet_and_is_in_the_output(rig: Rig) -> None:
    config = rig.cfg("base_url: http://ha.example\nservice: s\nallow_insecure_http: true\n")
    for flags in ([], ["--quiet"], ["--json"], ["--quiet", "--json"]):
        code, out, err = rig.run([*flags, "send", "--message=hi"], config=config)
        assert code == 0 and err.splitlines()[0] == INSECURE_HTTP_WARNING
        assert "ha.example" not in err and TOKEN not in err
    code, out, err = rig.run(["--json", "send", "--message=hi"], config=config)
    assert json.loads(out)["warnings"] == ["insecure_http"]


def test_insecure_http_golden(rig: Rig, golden: Golden) -> None:
    config = rig.cfg("base_url: http://ha.example\nservice: s\nallow_insecure_http: true\n")
    _, out, _ = rig.run(["--json", "send", "--message=hi"], config=config)
    golden.check("output", "send-sent-insecure.json", out)
    assert schema_errors("cli/send", json.loads(out)) == []


def test_https_and_dry_run_print_no_insecure_warning(rig: Rig) -> None:
    assert INSECURE_HTTP_WARNING not in rig.run(["send", "--message=hi"])[2]
    config = rig.cfg("base_url: http://ha.example\nservice: s\nallow_insecure_http: true\n")
    assert rig.run(["--dry-run", "send", "--message=hi"], config=config)[2].count("warning") == 0


HTTP_CONFIG = "base_url: http://ha.example\nservice: s\nallow_insecure_http: true\n"


def _slow_input_gateway(rig: Rig, leave: float) -> FakeGateway:
    """A gateway whose input read ends with ``leave`` seconds of the 5 s deadline left."""

    class Slow(FakeGateway):
        def read_source(self, *a: Any, **k: Any) -> Any:
            result = super().read_source(*a, **k)
            self.advance(TIMEOUT_S - leave)
            return result

    return Slow(home=rig.gw.home, ca=rig.gw.ca, sources=rig.gw.sources)


def test_no_insecure_warning_when_the_deadline_is_used_up_before_any_request(rig: Rig) -> None:
    gw = _slow_input_gateway(rig, 0.0)
    code, out, err = rig.run(
        ["--json", "send", "--stdin-json"], config=rig.cfg(HTTP_CONFIG), gateway=gw
    )
    body = error_of(out)
    assert code == 12 and body["code"] == "network_error" and body["details"]["timeout"] is True
    assert gw.connections == [] and INSECURE_HTTP_WARNING not in err


def test_a_millisecond_left_still_warns_and_caps_the_socket_timeouts(rig: Rig) -> None:
    gw = _slow_input_gateway(rig, 0.001)
    code, _, err = rig.run(["send", "--stdin-json"], config=rig.cfg(HTTP_CONFIG), gateway=gw)
    assert code == 0 and err.splitlines()[0] == INSECURE_HTTP_WARNING
    spec = gw.connections[0].spec
    assert spec.io_timeout == 0.01 and spec.connect_timeout <= 0.01


def test_a_429_retry_prints_the_insecure_warning_once_per_run(rig: Rig) -> None:
    rig.gw.scripts.extend([ConnectionScript(status=429), ConnectionScript(status=429)])
    config = rig.cfg(HTTP_CONFIG, timeout=10)
    code, _, err = rig.run(["send", "--message=hi"], config=config)
    assert code == 0 and len(rig.gw.connections) == 3
    assert err.count(INSECURE_HTTP_WARNING) == 1


def test_the_insecure_warning_text_is_in_the_docs_and_the_schema() -> None:
    root = Path(__file__).resolve().parent.parent
    assert INSECURE_HTTP_WARNING in (root / "docs/interface.md").read_text(encoding="utf-8")
    schema = (root / "schemas/cli/send.json").read_text(encoding="utf-8")
    assert INSECURE_HTTP_WARNING in schema


def test_a_failed_http_request_still_warns_and_a_credential_failure_does_not(rig: Rig) -> None:
    config = rig.cfg("base_url: http://ha.example\nservice: s\nallow_insecure_http: true\n")
    rig.gw.default_script = _row(401)
    err = rig.run(["--quiet", "send", "--message=hi"], config=config)[2]
    assert err.splitlines()[0] == INSECURE_HTTP_WARNING and "auth_required" in err
    err = rig.run(["--quiet", "send", "--message=hi"], config=config, env={})[2]
    assert INSECURE_HTTP_WARNING not in err  # no request was made


# --- the log step -----------------------------------------------------------------------------


def test_log_goldens(rig: Rig, golden: Golden) -> None:
    rig.gw.default_script = _row(401)
    rig.run(["send", "--message=hi"], config=rig.cfg(BASE))
    golden.check("log", "send-auth-required.jsonl", rig.log_text(), schema="log")


def test_a_refusal_is_logged_with_nulls(rig: Rig, golden: Golden) -> None:
    rig.gw.sources[0] = b'{"title":"x"}'
    code, out, _ = rig.run(["--json", "send", "--stdin-json"])
    assert code == 20 and error_of(out)["reason"] == "empty_message"
    golden.check("log", "send-refused.jsonl", rig.log_text(), schema="log")


def test_a_refusal_logs_null_level_even_when_a_valid_level_was_read(rig: Rig) -> None:
    rig.gw.sources[0] = b'{"message":"tts","level":"warn"}'
    code, out, _ = rig.run(["--json", "send", "--stdin-json"])
    assert code == 20 and error_of(out)["reason"] == "command_keyword"
    (rec,) = rig.records()
    for key in ("level", "bytes", "truncated", "message_sha256", "dedupe_key_sha256", "tag_set"):
        assert rec[key] is None, key


def test_an_input_timeout_is_logged_as_failed_unavailable(rig: Rig, golden: Golden) -> None:
    rig.gw.sources[0] = StallingSource(b'{"mess')
    code, out, _ = rig.run(["--json", "send", "--stdin-json"])
    body = error_of(out)
    assert code == 12 and body["code"] == "unavailable" and body["details"] == {"phase": "input"}
    assert rig.gw.connections == []
    golden.check("log", "send-unavailable.jsonl", rig.log_text(), schema="log")


def test_a_bad_file_is_exit_2_and_not_logged(rig: Rig) -> None:
    code, out, _ = rig.run(["--json", "send", "--file", "/missing"])
    assert code == 2 and error_of(out)["code"] == "usage" and not rig.state_dir.exists()


def test_the_result_is_printed_before_the_log_step_starts(
    rig: Rig, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[str] = []
    original = rig.gw.open_state_dir

    def spy(home: str) -> int:
        seen.append(capsys.readouterr().out)
        return original(home)

    rig.gw.open_state_dir = spy  # type: ignore[method-assign]
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    assert code == 0 and json.loads(seen[0])["outcome"] == "sent" and out == ""


def test_log_false_and_dry_run_touch_nothing(rig: Rig) -> None:
    calls: list[str] = []
    for name in ("open_state_dir", "open_state_file", "try_lock", "write_fd"):
        original = getattr(rig.gw, name)

        def spy(*a: Any, _n: str = name, _o: Callable[..., Any] = original, **k: Any) -> Any:
            calls.append(_n)
            return _o(*a, **k)

        setattr(rig.gw, name, spy)
    assert rig.run(["send", "--message=hi"], config=rig.cfg(BASE + "log: false\n"))[0] == 0
    assert rig.run(["send", "--message=hi"], config=rig.cfg(BASE + "log: false\n"), env={})[0] == 12
    assert rig.run(["--dry-run", "send", "--message=hi"])[0] == 0
    assert rig.run(["--dry-run", "send", "--message="], config=rig.cfg(BASE))[0] == 20
    assert calls == [] and not (Path(str(rig.gw.home)) / ".local").exists()


def test_signals_are_never_logged(rig: Rig) -> None:
    class Sig(FakeGateway):
        def ca_candidates(self) -> CaCandidates:
            self.deliver_signal(signal.SIGTERM)
            return super().ca_candidates()

    gw = Sig(home=rig.gw.home, ca=rig.gw.ca)
    assert rig.run(["--json", "send", "--message=hi"], gateway=gw) == (143, "", "")
    assert gw.connections == [] and not rig.state_dir.exists()


def test_a_log_lock_held_by_another_process_delays_only_the_log(rig: Rig, tmp_path: Path) -> None:
    import fcntl

    rig.state_dir.mkdir(parents=True, mode=0o700)
    fd = os.open(rig.state_dir / "log.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)  # a lock on another open file description conflicts
    try:
        started = rig.gw.now
        code, out, err = rig.run(["--json", "send", "--message=hi"])
        assert code == 0 and json.loads(out)["outcome"] == "sent"
        assert err == STATE_WARNING + "\n"
        assert rig.gw.now - started <= TIMEOUT_S + 3  # the whole run, log step included
        assert rig.records() == []
    finally:
        os.close(fd)


@pytest.mark.parametrize("which", ["log.jsonl", "log.lock"])
@pytest.mark.parametrize("kind", ["fifo", "symlink", "dir"])
def test_a_hostile_state_entry_costs_one_warning_and_never_the_exit_code(
    rig: Rig, which: str, kind: str
) -> None:
    rig.state_dir.mkdir(parents=True, mode=0o700)
    path = rig.state_dir / which
    target = rig.tmp / "elsewhere"
    target.write_text("keep\n")
    if kind == "fifo":
        os.mkfifo(path)
    elif kind == "symlink":
        path.symlink_to(target)
    else:
        path.mkdir()
    code, out, err = rig.run(["--json", "send", "--message=hi"])
    assert code == 0 and json.loads(out)["outcome"] == "sent"
    assert err == STATE_WARNING + "\n"
    assert target.read_text() == "keep\n"
    if kind == "fifo":
        assert stat.S_ISFIFO(path.lstat().st_mode)


@pytest.mark.parametrize("problem", ["symlinked_dir", "mode_0755", "no_home"])
def test_an_unusable_state_directory_warns_once_and_keeps_every_exit_code(
    rig: Rig, problem: str
) -> None:
    parent = rig.state_dir.parent
    parent.mkdir(parents=True)
    if problem == "symlinked_dir":
        (rig.tmp / "real").mkdir(mode=0o700)
        rig.state_dir.symlink_to(rig.tmp / "real")
    elif problem == "mode_0755":
        rig.state_dir.mkdir(mode=0o755)
        rig.state_dir.chmod(0o755)
    else:
        rig.gw.state_error = __import__("ha_notice.gateway", fromlist=["x"]).StateDirError()
    for script, status in ((_row(200), 0), (_row(401), 12), (_row(500), 12)):
        rig.gw.default_script = script
        code, _, err = rig.run(["--json", "send", "--message=hi"])
        assert code == status and err.count(STATE_WARNING) == 1


def test_a_log_error_warning_is_not_an_error_path_line(rig: Rig) -> None:
    rig.state_dir.mkdir(parents=True, mode=0o700)
    os.mkfifo(rig.state_dir / "log.jsonl")
    code, out, err = rig.run(["--quiet", "--json", "send", "--message=hi"])
    assert code == 0 and err == STATE_WARNING + "\n"  # a warning survives --quiet


def test_log_rotation_still_works_from_a_send(rig: Rig) -> None:
    rig.state_dir.mkdir(parents=True, mode=0o700)
    (rig.state_dir / "log.jsonl").write_bytes(b"x" * ROTATE_AT)
    assert rig.run(["send", "--message=hi"])[0] == 0
    assert (rig.state_dir / "log.jsonl.1").stat().st_size == ROTATE_AT
    assert len(rig.records()) == 1


# --- the deadline, signals and the end of the process -----------------------------------------


def _when(
    ready: Callable[[], bool], action: Callable[[], object], *, within: float = 8.0
) -> threading.Thread:
    """A test-owned thread that runs ``action`` once ``ready`` holds (bounded)."""

    def work() -> None:
        gate = threading.Event()
        for _ in range(int(within / 0.002)):
            if ready():
                break
            gate.wait(0.002)
        action()

    thread = threading.Thread(target=work, name="test-driver", daemon=True)
    thread.start()
    return thread


@pytest.fixture
def release() -> Iterator[threading.Event]:
    event = threading.Event()
    yield event
    event.set()


def _writing(gw: FakeGateway) -> bool:
    return bool(gw.connections and gw.connections[0].requests)


def test_the_deadline_while_writing_is_outcome_unknown_and_the_process_exits(
    rig: Rig, release: threading.Event, golden: Golden
) -> None:
    rig.gw.default_script = ConnectionScript(stall_after_first_byte=release)
    started = rig.gw.now
    driver = _when(lambda: _writing(rig.gw), lambda: rig.gw.advance(TIMEOUT_S + 0.1))
    code, out, err = rig.run(["--json", "send", "--message=hi"])
    driver.join(10)
    assert code == 12 and rig.exited and rig.gw.exits == [12]
    body = error_of(out)
    assert body["code"] == "outcome_unknown" and body["unknown_outcome"] is True
    assert err == f"outcome_unknown: {body['message']}\n"
    assert len(rig.gw.connections[0].requests) == 1
    assert rig.gw.now - started <= TIMEOUT_S + 3
    rec = rig.records()
    assert len(rec) == 1 and rec[0]["duration_ms"] == int((TIMEOUT_S + 0.1) * 1000)
    assert rec[0]["ts"] == "2023-11-14T22:13:25.100Z"


def test_the_deadline_while_connecting_is_network_error_and_nothing_is_written(
    rig: Rig, release: threading.Event
) -> None:
    rig.gw.default_script = ConnectionScript(connect_block=release)
    driver = _when(lambda: bool(rig.gw.connections), lambda: rig.gw.advance(TIMEOUT_S + 0.1))
    code, out, err = rig.run(["--json", "send", "--message=hi"])
    driver.join(10)
    body = error_of(out)
    assert code == 12 and rig.exited and rig.gw.exits == [12]
    assert body["code"] == "network_error" and body["details"] == {"tls": False, "timeout": True}
    assert body["retryable"] is True and body["unknown_outcome"] is False
    assert rig.gw.connections[0].bytes_written == 0 and rig.gw.connections[0].requests == []
    assert rig.records()[0]["outcome"] == "failed" and rig.records()[0]["code"] == "network_error"
    assert out.endswith("\n") and err.startswith("network_error:")


def test_the_outcome_unknown_log_golden(rig: Rig, release: threading.Event, golden: Golden) -> None:
    rig.gw.default_script = ConnectionScript(stall_after_first_byte=release)
    driver = _when(lambda: _writing(rig.gw), lambda: rig.gw.advance(TIMEOUT_S))
    code, _, _ = rig.run(["send", "--message=hi"], config=rig.cfg(BASE))
    driver.join(10)
    assert code == 12
    golden.check("log", "send-outcome-unknown.jsonl", rig.log_text(), schema="log")


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_signal_during_the_send_is_decided_by_the_gate_and_logged(
    rig: Rig, release: threading.Event, signum: int
) -> None:
    rig.gw.default_script = ConnectionScript(stall_after_first_byte=release)
    driver = _when(lambda: _writing(rig.gw), lambda: rig.gw.deliver_signal(signum))
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    driver.join(10)
    assert code == 12 and rig.exited  # not 128+N: the send had started
    assert error_of(out)["code"] == "outcome_unknown"
    assert [r["outcome"] for r in rig.records()] == ["outcome_unknown"]


def test_a_signal_during_the_connect_phase_is_network_error(
    rig: Rig, release: threading.Event
) -> None:
    rig.gw.default_script = ConnectionScript(connect_block=release)
    driver = _when(lambda: bool(rig.gw.connections), lambda: rig.gw.deliver_signal(signal.SIGTERM))
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    driver.join(10)
    body = error_of(out)
    assert code == 12 and body["code"] == "network_error" and body["details"]["timeout"] is True
    assert rig.gw.connections[0].bytes_written == 0


def _hook_before_write(
    monkeypatch: pytest.MonkeyPatch, around: Callable[[Callable[[], None]], None]
) -> list[deadline.WritingGate]:
    """Make the worker call ``around(enter_writing)`` where it would enter ``writing``. Returns
    the gates the send creates."""
    gates: list[deadline.WritingGate] = []

    class Spy(deadline.WritingGate):
        def __init__(self) -> None:
            super().__init__()
            gates.append(self)

    real = send_module.send_once

    def hooked(gateway: Any, target: Any, service: str, body: bytes, *, before_write: Any) -> Any:
        return real(gateway, target, service, body, before_write=lambda: around(before_write))

    monkeypatch.setattr(send_module, "WritingGate", Spy)
    monkeypatch.setattr(send_module, "send_once", hooked)
    return gates


def test_a_signal_just_after_the_gate_enters_writing_is_outcome_unknown(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, release: threading.Event
) -> None:
    def enter_then_signal(enter_writing: Callable[[], None]) -> None:
        enter_writing()
        rig.gw.deliver_signal(signal.SIGTERM)  # the gate is writing, no byte written yet

    _hook_before_write(monkeypatch, enter_then_signal)
    rig.gw.default_script = ConnectionScript(stall_after_first_byte=release)
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 12 and rig.exited and rig.gw.exits == [12]
    assert body["code"] == "outcome_unknown" and body["unknown_outcome"] is True
    assert len(rig.gw.connections) == 1
    assert [r["outcome"] for r in rig.records()] == ["outcome_unknown"]


def test_a_signal_just_before_the_gate_enters_writing_is_network_error_and_writes_nothing(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def signal_then_try(enter_writing: Callable[[], None]) -> None:
        rig.gw.deliver_signal(signal.SIGTERM)
        for _ in range(2000):  # until the main thread has decided (it polls every 100 ms)
            if gates[0].abandoned():
                break
            threading.Event().wait(0.005)
        enter_writing()  # refused: the gate was abandoned while idle

    gates = _hook_before_write(monkeypatch, signal_then_try)
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 12 and rig.exited
    assert body["code"] == "network_error" and body["unknown_outcome"] is False
    assert all(c.requests == [] and c.bytes_written == 0 for c in rig.gw.connections)
    assert [r["outcome"] for r in rig.records()] == ["failed"]


def test_a_signal_before_the_worker_starts_is_128_plus_n_and_sends_nothing(rig: Rig) -> None:
    class Sig(FakeGateway):
        def ca_candidates(self) -> CaCandidates:  # runs in make_target, before the worker
            self.deliver_signal(signal.SIGHUP)
            return super().ca_candidates()

    gw = Sig(home=rig.gw.home, ca=rig.gw.ca)
    assert rig.run(["--json", "send", "--message=hi"], gateway=gw) == (129, "", "")
    assert gw.connections == [] and rig.records() == []


def test_a_signal_during_render_stops_a_dry_run_with_no_output(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = send_module.serialize

    def serialize_then_signal(body: Any) -> bytes:
        data = real(body)
        rig.gw.deliver_signal(signal.SIGTERM)  # after the render, before the dry run prints
        return data

    monkeypatch.setattr(send_module, "serialize", serialize_then_signal)
    code, out, _ = rig.run(["--json", "--verbose", "--dry-run", "send", "--message=hi"])
    assert (code, out) == (143, "") and rig.records() == []


def test_a_signal_while_the_token_is_read_is_128_plus_n_and_not_logged(rig: Rig) -> None:
    class Env(dict[str, str]):
        def get(self, key: str, default: Any = None) -> Any:
            rig.gw.deliver_signal(signal.SIGTERM)
            return "has space"  # a bad token: the credential_invalid branch

    assert rig.run(["--json", "send", "--message=hi"], env=Env()) == (143, "", "")
    assert rig.gw.connections == [] and rig.records() == []


def test_a_signal_while_the_trust_is_loaded_is_128_plus_n_and_not_logged(rig: Rig) -> None:
    class Sig(FakeGateway):
        def ca_candidates(self) -> CaCandidates:
            self.deliver_signal(signal.SIGINT)
            return CaCandidates("", "", ())  # no usable trust: the TrustError branch

    gw = Sig(home=rig.gw.home)
    assert rig.run(["--json", "send", "--message=hi"], gateway=gw) == (130, "", "")
    assert gw.connections == [] and rig.records() == []


def test_a_signal_during_the_log_step_does_not_change_the_exit_code(rig: Rig) -> None:
    class Sig(FakeGateway):
        def wall_time(self) -> float:  # asked for by the log step only
            self.deliver_signal(signal.SIGTERM)
            return super().wall_time()

    gw = Sig(home=rig.gw.home, ca=rig.gw.ca)
    code, out, _ = rig.run(["--json", "send", "--message=hi"], gateway=gw)
    assert code == 0 and json.loads(out)["outcome"] == "sent" and len(rig.records()) == 1


def test_a_reported_result_wins_over_a_later_signal_in_the_except_branch(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def deliver_then_break(inv: Any, config: Any, plan: Any) -> int:
        record_emitted(0)
        inv.signals.handler(signal.SIGTERM)
        raise RuntimeError("after the result")

    monkeypatch.setattr(send_module, "deliver", deliver_then_break)
    assert rig.run(["send", "--message=hi"])[0] == 0


def test_a_signal_wins_over_an_exception_when_nothing_was_reported(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def break_after_signal(inv: Any, config: Any, plan: Any) -> int:
        inv.signals.handler(signal.SIGTERM)
        raise RuntimeError("no result yet")

    monkeypatch.setattr(send_module, "deliver", break_after_signal)
    assert rig.run(["send", "--message=hi"])[0] == 143


def test_cannot_start_new_thread_is_exit_1_internal_error_and_not_logged(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(deadline.threading.Thread, "start", boom)
    code, out, err = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 1 and body["code"] == "internal" and body["message"] == "internal error"
    assert body["unknown_outcome"] is False and "start" not in err and "thread" not in err
    assert rig.gw.connections == [] and rig.records() == []


def test_a_worker_crash_before_writing_is_exit_1_not_logged(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(connect_error=KeyboardInterrupt())
    code, out, err = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 1 and body["unknown_outcome"] is False and "Keyboard" not in out + err
    assert rig.records() == []


def test_a_worker_crash_after_writing_is_exit_1_unknown_and_logged(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(request_error=SystemExit(3))
    code, out, err = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 1 and body["unknown_outcome"] is True and body["message"] == "internal error"
    assert "SystemExit" not in out + err
    rec = rig.records()
    assert len(rec) == 1 and rec[0]["outcome"] == "outcome_unknown" and rec[0]["code"] == "internal"
    assert rec[0]["exit"] == 1 and schema_errors("log", rec[0]) == []


def test_a_failure_while_idle_that_is_not_a_network_error_is_exit_1_not_logged(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(connect_error=ValueError("x"))
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    assert code == 1 and error_of(out)["unknown_outcome"] is False and rig.records() == []


@pytest.mark.parametrize(
    ("script", "unknown"),
    [(_row(401), True), (ConnectionScript(connect_error=ConnectionRefusedError(111, "x")), False)],
)
def test_progress_writing_follows_the_gate_state_of_the_verdict(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, script: ConnectionScript, unknown: bool
) -> None:
    def broken(self: Any, *, tag_sent: bool) -> Any:
        raise ValueError("a bug between the verdict and the report")

    monkeypatch.setattr(deadline.Verdict, "error", broken)
    rig.gw.default_script = script
    code, out, err = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 1 and body["code"] == "internal" and body["unknown_outcome"] is unknown
    assert out.count("\n") == 1 and err.count("\n") == 1  # never a second envelope
    if unknown:  # the interface logs an exit 1 after writing as outcome_unknown / internal
        assert_logged_internal(rig)
    else:
        assert rig.records() == []


def assert_logged_internal(rig: Rig) -> None:
    rec = rig.records()
    assert len(rec) == 1 and schema_errors("log", rec[0]) == []
    assert (rec[0]["exit"], rec[0]["outcome"], rec[0]["code"]) == (1, "outcome_unknown", "internal")
    assert rec[0]["reason"] is None and rec[0]["http_status"] is None
    assert rec[0]["level"] == "info" and rec[0]["tag_set"] is False


def test_an_exception_from_the_deadline_after_writing_is_exit_1_logged_once(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def writing_then_raise(gateway: Any, attempt: Any, **kw: Any) -> Any:
        kw["gate"].enter_writing()
        raise RuntimeError("after the gate entered writing")

    monkeypatch.setattr(send_module, "run_with_deadline", writing_then_raise)
    code, out, err = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 1 and body["unknown_outcome"] is True and out.count("\n") == 1
    assert "after the gate" not in out + err
    assert_logged_internal(rig)


def test_a_thread_start_failure_after_writing_records_writing_and_settles_the_gate(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def writing_then_raise(gateway: Any, attempt: Any, **kw: Any) -> Any:
        seen["gate"] = kw["gate"]
        kw["gate"].enter_writing()
        raise RuntimeError("can't start new thread")

    real = send_module.internal_after_writing

    def spy(inv: Any, config: Any, plan: Any, fixed_at: float) -> int:
        seen["writing"] = inv.progress.writing
        seen["settled"] = seen["gate"].abandoned()
        return real(inv, config, plan, fixed_at)

    monkeypatch.setattr(send_module, "run_with_deadline", writing_then_raise)
    monkeypatch.setattr(send_module, "internal_after_writing", spy)
    code, _, _ = rig.run(["--json", "send", "--message=hi"])
    assert code == 1
    assert seen["writing"] is True
    assert seen["settled"] is True


def test_a_bug_in_the_verdict_after_writing_flushes_logs_then_finishes_with_the_verdict(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(self: Any, *, tag_sent: bool) -> Any:
        raise ValueError("a bug between the verdict and the report")

    events: list[str] = []
    finished: list[Any] = []
    real_log, real_flush = send_module.log_facts, send_module.flush_streams

    def log_spy(*args: Any) -> None:
        events.append("log")
        real_log(*args)

    def flush_spy() -> None:
        events.append("flush")
        real_flush()

    def finish_spy(gateway: Any, verdict: Any, code: int) -> int:
        events.append("finish")
        finished.append((verdict, code))
        return code

    monkeypatch.setattr(deadline.Verdict, "error", broken)
    monkeypatch.setattr(send_module, "log_facts", log_spy)
    monkeypatch.setattr(send_module, "flush_streams", flush_spy)
    monkeypatch.setattr(send_module, "finish", finish_spy)
    rig.gw.default_script = _row(401)
    code, _, _ = rig.run(["--json", "send", "--message=hi"])
    assert code == 1
    assert events[-3:] == ["log", "flush", "finish"]
    assert len(finished) == 1 and isinstance(finished[0][0], deadline.Verdict)
    assert finished[0][1] == 1
    assert len(rig.records()) == 1


def test_an_exception_from_the_deadline_while_idle_is_not_logged(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_idle(gateway: Any, attempt: Any, **kw: Any) -> Any:
        raise RuntimeError("idle")

    monkeypatch.setattr(send_module, "run_with_deadline", raise_idle)
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    assert code == 1 and error_of(out)["unknown_outcome"] is False and rig.records() == []


@pytest.mark.parametrize(
    ("script", "unknown"),
    [(_row(401), True), (ConnectionScript(connect_error=ConnectionRefusedError(111, "x")), False)],
)
def test_conclude_falls_back_to_internal_when_nothing_was_printed(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, script: ConnectionScript, unknown: bool
) -> None:
    real = send_module.emit_error
    calls: list[int] = []

    def flaky(json_mode: bool, error: Any) -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("printing failed before anything was written")
        real(json_mode, error)

    monkeypatch.setattr(send_module, "emit_error", flaky)
    rig.gw.default_script = script
    code, out, _ = rig.run(["--json", "send", "--message=hi"])
    body = error_of(out)
    assert code == 1 and body["code"] == "internal" and out.count("\n") == 1
    assert body["unknown_outcome"] is unknown
    if unknown:
        assert_logged_internal(rig)
    else:
        assert rig.records() == []


def test_one_envelope_per_run_when_printing_fails_after_the_result(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    def break_log(*a: Any, **k: Any) -> None:
        raise RuntimeError("after the result")

    monkeypatch.setattr(send_module, "write_log_record", break_log)
    code, out, err = rig.run(["--json", "send", "--message=hi"])
    assert code == 0 and out.count("\n") == 1 and json.loads(out)["outcome"] == "sent"
    assert "internal" not in err and emitted_exit() == 0


# --- secrets ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "script",
    [
        ConnectionScript(),
        _row(401),
        _row(500),
        ConnectionScript(request_error=ValueError(TOKEN)),
        ConnectionScript(request_error=http.client.InvalidURL(TOKEN)),
        ConnectionScript(connect_error=OSError(TOKEN)),
        ConnectionScript(response_error=http.client.BadStatusLine(TOKEN)),
        ConnectionScript(request_error=SystemExit(TOKEN)),
        _row(200, TOKEN.encode()),
    ],
)
def test_the_token_leak_test_through_the_whole_cli(rig: Rig, script: ConnectionScript) -> None:
    rig.gw.default_script = script
    argv = ["--json", "--verbose", "send", "--message=hi", "--dedupe-key=k"]
    assert TOKEN not in " ".join(argv)
    code, out, err = rig.run(argv)
    log = rig.log_path.read_text(encoding="utf-8") if rig.log_path.exists() else ""
    assert TOKEN not in out + err + log and code in (0, 1, 12)
    for conn in rig.gw.connections:
        assert conn.spec.host == "ha.example"
        for request in conn.requests:
            leaked = [k for k, v in request.headers.items() if TOKEN in v]
            assert leaked in ([], ["Authorization"]) and TOKEN not in request.path
            assert request.body is not None and TOKEN.encode() not in request.body
    assert {host for host, _ in rig.gw.resolve_calls} <= {"ha.example"}


def test_the_token_is_not_in_the_env_echo_or_a_traceback_when_the_worker_crashes(
    rig: Rig,
) -> None:
    rig.gw.default_script = ConnectionScript(request_error=RuntimeError(TOKEN))
    code, out, err = rig.run(["--json", "send", "--message=hi"])
    assert TOKEN not in out + err and "Traceback" not in err
