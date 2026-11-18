"""The validate command (issue #28): checks, probe, output and exit codes.

``cli.main(argv, env, gateway)`` with the fake gateway, so nothing sleeps and no socket opens.
Real-socket and real-process coverage is in tests/test_validate_process.py.
"""

from __future__ import annotations

import json
import signal
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from ha_notice.cli import main
from ha_notice.gateway import CaCandidates
from ha_notice.output import INSECURE_HTTP_WARNING
from tests.fake_gateway import ConnectionScript, FakeExit, FakeGateway, private_home
from tests.harness import Golden, schema_errors

TOKEN = "HA_SECRET_tok_1a2b3c4d5e6f7089"
ENV = {"HA_TOKEN": TOKEN}
BASE = "base_url: https://ha.example\nservice: mobile_app_x\n"
HTTP = "base_url: http://ha.example\nservice: s\nallow_insecure_http: true\n"
TIMEOUT_S = 5
Result = tuple[int, str, str]


@dataclass
class Rig:
    tmp: Path
    gw: FakeGateway
    capsys: pytest.CaptureFixture[str]
    exited: bool = False

    def cfg(self, text: str = BASE, timeout: int = TIMEOUT_S) -> str:
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
        self.exited = False
        try:
            code = main(
                ["--config", self.cfg() if config is None else config, *argv],
                ENV if env is None else env,
                gw,
            )
        except FakeExit as done:
            self.exited = True
            code = done.code
        out = self.capsys.readouterr()
        return code, out.out, out.err


@pytest.fixture
def rig(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], self_signed_cert: tuple[Path, Path]
) -> Rig:
    gw = FakeGateway(
        home=private_home(tmp_path),
        ca=CaCandidates(str(self_signed_cert[0]), "", ()),
        default_script=ConnectionScript(body=b"{}"),
    )
    return Rig(tmp_path, gw, capsys)


@pytest.fixture
def release() -> Iterator[threading.Event]:
    event = threading.Event()
    yield event
    event.set()


def doc(out: str) -> dict[str, Any]:
    assert out.endswith("\n") and out.count("\n") == 1
    value = json.loads(out)
    assert schema_errors("cli/validate", value) == []
    return value  # type: ignore[no-any-return]


def names(out: str) -> list[str]:
    return [c["name"] for c in doc(out)["checks"]]


# --- plain validate -------------------------------------------------------------------------


def test_plain_validate_checks_config_and_credential_and_makes_no_call(
    rig: Rig, golden: Golden
) -> None:
    code, out, err = rig.run(["--json", "validate"])
    assert code == 0 and err == ""
    golden.check("output", "validate-ok.json", out, schema="cli/validate")
    assert rig.gw.connections == [] and rig.gw.resolve_calls == []
    assert not (Path(rig.gw.home) / ".local").exists()  # type: ignore[arg-type]  # no state, no log


def test_plain_validate_never_reads_stdin(rig: Rig) -> None:
    rig.gw.tty_fds = {0}  # a terminal on stdin would be a usage error for send
    assert rig.run(["--json", "validate"])[0] == 0


def test_human_output_is_one_line_per_check_on_stderr(rig: Rig) -> None:
    code, out, err = rig.run(["validate"])
    assert (code, out) == (0, "")
    assert err == (
        "config: ok: the configuration is usable\n"
        "credential: ok: the token is set and well formed\n"
    )


def test_quiet_keeps_failed_checks_only(rig: Rig) -> None:
    assert rig.run(["--quiet", "validate"]) == (0, "", "")
    code, out, err = rig.run(["--quiet", "validate"], env={})
    assert code == 12 and out == ""
    assert err.splitlines() == [
        "credential: failed: credential_invalid: the token variable (HA_TOKEN) "
        "is missing or malformed"
    ]


def test_dry_run_has_no_effect(rig: Rig, golden: Golden) -> None:
    code, out, _ = rig.run(["--dry-run", "--json", "validate"])
    assert (
        code == 0 and out == (Path(__file__).parent / "golden/output/validate-ok.json").read_text()
    )


@pytest.mark.parametrize("flag", ["--stdin-json", "--message=a", "--dedupe-key=k"])
def test_send_flags_are_refused(rig: Rig, flag: str) -> None:
    assert rig.run(["validate", flag])[0] == 2


# --- config check ---------------------------------------------------------------------------


def test_missing_base_url_is_a_failed_config_check_with_exit_2(rig: Rig, golden: Golden) -> None:
    code, out, err = rig.run(["--json", "validate"], config=rig.cfg("service: s\n"))
    assert code == 2
    golden.check("output", "validate-missing-base-url.json", out, schema="cli/validate")
    assert err == ""


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("service: s\n", "base_url is missing or invalid"),
        ("base_url: https://ha.example\n", "service is missing or invalid"),
        ("", "base_url is missing or invalid"),  # base_url is checked before service
    ],
)
def test_missing_destination_keys_in_order(rig: Rig, text: str, message: str) -> None:
    code, out, _ = rig.run(["--json", "validate"], config=rig.cfg(text))
    assert code == 2 and doc(out)["checks"] == [{"name": "config", "ok": False, "message": message}]


def test_an_unreadable_ca_file_is_a_failed_config_check(rig: Rig, tmp_path: Path) -> None:
    config = rig.cfg(BASE + f"ca_file: {tmp_path / 'nope.pem'}\n")
    code, out, _ = rig.run(["--json", "validate"], config=config)
    body = doc(out)
    assert code == 2 and body["checks"][0]["name"] == "config" and len(body["checks"]) == 1
    assert "ca_file" in body["checks"][0]["message"] and str(tmp_path) not in out


def test_a_failed_config_check_ends_the_run_before_the_credential(rig: Rig) -> None:
    code, out, _ = rig.run(
        ["--json", "validate", "--probe"], config=rig.cfg("service: s\n"), env={}
    )
    assert code == 2 and names(out) == ["config"] and "probe" not in doc(out)
    assert rig.gw.connections == []


@pytest.mark.parametrize("text", ["unknown_key: 1\n", "timeout: nope\n", "enabled: [\n"])
def test_a_config_that_cannot_load_is_the_envelope_with_exit_2(rig: Rig, text: str) -> None:
    code, out, err = rig.run(["--json", "validate"], config=rig.cfg(BASE + text))
    body = json.loads(out)
    assert code == 2 and schema_errors("cli/error", body) == []
    assert body["error"]["code"] == "config_invalid" and err.startswith("config_invalid: ")


@pytest.mark.parametrize("path", ["", "/nonexistent/c.yaml"])
def test_an_empty_or_missing_config_path_is_config_invalid_for_config(rig: Rig, path: str) -> None:
    code, out, _ = rig.run(["--json", "validate"], config=path)
    body = json.loads(out)["error"]
    assert code == 2 and body["code"] == "config_invalid"
    assert body["details"] == {"key": "--config"} if path == "" else body["details"]["key"]


# --- credential check -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "env",
    [{}, {"HA_TOKEN": ""}, {"HA_TOKEN": "  "}, {"HA_TOKEN": "a b"}, {"HA_TOKEN": "x" * 4097},
     {"HA_TOKEN": "tokén"}, {"HA_TOKEN": "tok\x00"}],
)  # fmt: skip
def test_a_bad_credential_is_exit_12_and_leaks_nothing(
    rig: Rig, golden: Golden, env: dict[str, str]
) -> None:
    code, out, err = rig.run(["--json", "validate"], env=env)
    assert code == 12 and names(out) == ["config", "credential"]
    for value in env.values():
        assert not value or value not in out + err
    if not env:
        golden.check("output", "validate-bad-credential.json", out, schema="cli/validate")


def test_a_trailing_newline_in_the_token_is_trimmed(rig: Rig) -> None:
    assert rig.run(["--json", "validate"], env={"HA_TOKEN": TOKEN + "\r\n"})[0] == 0


def test_the_token_is_never_printed(rig: Rig) -> None:
    for argv in (["--json", "validate"], ["--json", "--verbose", "validate", "--probe"]):
        out = "".join(rig.run(argv)[1:])
        assert TOKEN not in out


# --- enabled: false -------------------------------------------------------------------------


DISABLED = "enabled: false\n"


def test_plain_validate_with_enabled_false_exits_0_and_reports_it(rig: Rig) -> None:
    code, out, _ = rig.run(["--json", "validate"], config=rig.cfg(BASE + DISABLED))
    assert code == 0 and doc(out)["enabled"] is False and doc(out)["ok"] is True


def test_plain_validate_with_enabled_false_still_reports_a_broken_credential(rig: Rig) -> None:
    code, out, _ = rig.run(["--json", "validate"], config=rig.cfg(BASE + DISABLED), env={})
    assert code == 12 and doc(out)["enabled"] is False and doc(out)["ok"] is False


@pytest.mark.parametrize("flag", ["--probe", "--test-message", "--probe --test-message"])
@pytest.mark.parametrize("env", [ENV, {}])
def test_probe_and_test_message_with_enabled_false_exit_22_before_any_check(
    rig: Rig, flag: str, env: dict[str, str]
) -> None:
    code, out, err = rig.run(
        ["--json", "validate", *flag.split()], config=rig.cfg(BASE + DISABLED), env=env
    )
    assert (code, out, err) == (22, '{"outcome":"disabled"}\n', "")
    assert schema_errors("cli/validate", json.loads(out)) == []
    assert rig.gw.connections == [] and rig.gw.resolve_calls == []


def test_disabled_without_json_is_one_line(rig: Rig) -> None:
    code, out, err = rig.run(["validate", "--probe"], config=rig.cfg(BASE + DISABLED))
    assert (code, out, err) == (22, "", "disabled in config\n")


def test_disabled_comes_before_the_destination_check(rig: Rig) -> None:
    code, out, _ = rig.run(["--json", "validate", "--probe"], config=rig.cfg(DISABLED), env={})
    assert code == 22 and out == '{"outcome":"disabled"}\n'


# --- probe ----------------------------------------------------------------------------------


def only_request(gw: FakeGateway) -> Any:
    assert len(gw.connections) == 1 and len(gw.connections[0].requests) == 1
    return gw.connections[0].requests[0]


def test_probe_ok_is_a_get_of_api_and_nothing_else(rig: Rig, golden: Golden) -> None:
    code, out, err = rig.run(["--json", "validate", "--probe"])
    assert code == 0 and err == ""
    golden.check("output", "validate-probe-ok.json", out, schema="cli/validate")
    request = only_request(rig.gw)
    assert (request.method, request.path, request.body) == ("GET", "/api/", None)
    headers = {k.lower(): v for k, v in request.headers.items()}
    assert headers["authorization"] == f"Bearer {TOKEN}"
    assert "content-type" not in headers and "content-length" not in headers
    assert rig.gw.connections[0].spec.host == "ha.example"


def test_probe_honours_a_path_prefix(rig: Rig) -> None:
    config = rig.cfg("base_url: https://ha.example/ha\nservice: s\n")
    assert rig.run(["--json", "validate", "--probe"], config=config)[0] == 0
    assert only_request(rig.gw).path == "/ha/api/"


def test_probe_is_not_logged(rig: Rig) -> None:
    rig.run(["--json", "validate", "--probe"])
    assert not (Path(rig.gw.home) / ".local").exists()  # type: ignore[arg-type]


@pytest.mark.parametrize("body", [b"{}", b'{"message":"API running."}', b' {"a":[1,{"b":null}]} '])
def test_a_200_json_object_is_ok(rig: Rig, body: bytes) -> None:
    rig.gw.default_script = ConnectionScript(body=body)
    code, out, _ = rig.run(["--json", "validate", "--probe"])
    assert code == 0 and doc(out)["probe"] == {"api_ok": True}


@pytest.mark.parametrize(
    "body",
    [b"[]", b"[{}]", b"null", b'"x"', b"1", b"", b"<html>", b'{"a":1,"a":2}', b'{"a":', b"\xff{}",
     b"{" * 100000 + b"}" * 100000, b"{}" + b" " * 70000],
)  # fmt: skip
def test_a_200_that_is_not_a_json_object_fails_with_wrong_host_response(
    rig: Rig, body: bytes
) -> None:
    rig.gw.default_script = ConnectionScript(body=body)
    code, out, _ = rig.run(["--json", "validate", "--probe"])
    result = doc(out)
    assert code == 12 and result["probe"] == {"api_ok": False} and result["ok"] is False
    assert result["checks"][-1] == {
        "name": "probe",
        "ok": False,
        "message": "wrong_host_response (HTTP 200)",
    }


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "auth_required (HTTP 401)"),
        (403, "auth_required (HTTP 403)"),
        (404, "wrong_host_response (HTTP 404); base_url or its path prefix is probably wrong"),
        (405, "wrong_host_response (HTTP 405); base_url or its path prefix is probably wrong"),
        (400, "host_rejected (HTTP 400)"),
        (500, "upstream_error (HTTP 500)"),
        (503, "upstream_error (HTTP 503)"),
        (302, "wrong_host_response (HTTP 302)"),
        (204, "wrong_host_response (HTTP 204)"),
        (418, "wrong_host_response (HTTP 418)"),
    ],
)
def test_probe_status_rows_name_the_code_with_exit_12(rig: Rig, status: int, message: str) -> None:
    rig.gw.default_script = ConnectionScript(status=status, body=b"secret body " + TOKEN.encode())
    code, out, err = rig.run(["--json", "validate", "--probe"])
    result = doc(out)
    assert code == 12 and result["probe"] == {"api_ok": False}
    assert result["checks"][-1]["message"] == message
    assert "secret body" not in out + err and TOKEN not in out + err
    assert "unknown_outcome" not in out and "outcome_unknown" not in out
    assert len(rig.gw.connections) == 1  # nothing here is retried


def test_probe_401_golden(rig: Rig, golden: Golden) -> None:
    rig.gw.default_script = ConnectionScript(status=401)
    code, out, _ = rig.run(["--json", "validate", "--probe"])
    assert code == 12
    golden.check("output", "validate-probe-auth.json", out, schema="cli/validate")


def test_probe_retries_a_429_and_succeeds(rig: Rig) -> None:
    rig.gw.scripts.append(ConnectionScript(status=429))
    code, out, _ = rig.run(["--json", "validate", "--probe"])
    assert code == 0 and doc(out)["probe"] == {"api_ok": True}
    assert len(rig.gw.connections) == 2 and rig.gw.sleeps == [2]


def test_probe_429_three_times_fails_with_rate_limited(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(status=429)
    code, out, _ = rig.run(["--json", "validate", "--probe"], config=rig.cfg(BASE, timeout=20))
    assert code == 12 and doc(out)["checks"][-1]["message"] == "rate_limited (HTTP 429)"
    assert len(rig.gw.connections) == 3 and rig.gw.sleeps == [2, 4]


def test_probe_retries_one_connect_failure(rig: Rig) -> None:
    rig.gw.scripts.append(ConnectionScript(connect_error=ConnectionRefusedError(111, "x")))
    code, _, _ = rig.run(["--json", "validate", "--probe"])
    assert code == 0 and len(rig.gw.connections) == 2 and rig.gw.sleeps == [2]


def test_probe_connect_failure_twice_is_network_error(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(connect_error=ConnectionRefusedError(111, "x"))
    code, out, err = rig.run(["--json", "validate", "--probe"])
    assert code == 12 and doc(out)["checks"][-1]["message"] == "network_error"
    assert "ha.example" not in out + err


def test_probe_certificate_failure_names_ca_file(rig: Rig) -> None:
    import ssl

    rig.gw.default_script = ConnectionScript(
        connect_error=ssl.SSLCertVerificationError(1, "bad cert for ha.example")
    )
    code, out, err = rig.run(["--json", "validate", "--probe"])
    assert code == 12 and doc(out)["checks"][-1]["message"] == "network_error; check ca_file"
    assert len(rig.gw.connections) == 1 and "bad cert" not in out + err


def test_probe_with_an_unusable_ca_file_is_a_failed_probe_not_an_exit_1(
    rig: Rig, tmp_path: Path
) -> None:
    pem = tmp_path / "ca.pem"
    pem.write_text("not a certificate\n")
    config = rig.cfg(BASE + f"ca_file: {pem}\n")
    code, out, _ = rig.run(["--json", "validate", "--probe"], config=config)
    assert code == 12 and doc(out)["checks"][-1]["message"] == "network_error; check ca_file"
    assert rig.gw.connections == []
    assert rig.run(["--json", "validate"], config=config)[0] == 0  # only readability is checked


def test_a_stalled_host_is_the_deadline_and_ends_the_process(
    rig: Rig, release: threading.Event
) -> None:
    rig.gw.default_script = ConnectionScript(connect_block=release)

    def drive() -> None:
        for _ in range(4000):
            if rig.gw.connections:
                break
            release.wait(0.002)
        rig.gw.advance(TIMEOUT_S + 0.1)

    driver = threading.Thread(target=drive, daemon=True)
    driver.start()
    start = rig.gw.now
    code, out, _ = rig.run(["--json", "validate", "--probe"])
    driver.join(10)
    assert code == 12 and rig.exited and rig.gw.exits == [12]
    result = doc(out)
    assert result["probe"] == {"api_ok": False}
    assert result["checks"][-1]["message"] == "network_error; the host did not answer in time"
    assert rig.gw.now - start <= TIMEOUT_S + 3


def test_the_probe_deadline_starts_with_the_probe_check(rig: Rig) -> None:
    class Slow(FakeGateway):
        def read_config(self, path: str, max_bytes: int) -> bytes | None:
            data = super().read_config(path, max_bytes)
            if path.endswith("c.yaml"):
                self.advance(TIMEOUT_S * 3)  # the config check used more than the whole timeout
            return data

    gw = Slow(home=rig.gw.home, ca=rig.gw.ca, default_script=ConnectionScript(body=b"{}"))
    code, out, _ = rig.run(["--json", "validate", "--probe"], gateway=gw)
    assert code == 0 and doc(out)["probe"] == {"api_ok": True}


def test_probe_after_a_failed_credential_makes_no_call(rig: Rig) -> None:
    code, out, _ = rig.run(["--json", "validate", "--probe"], env={})
    assert code == 12 and names(out) == ["config", "credential"] and "probe" not in doc(out)
    assert rig.gw.connections == []


# --- insecure http --------------------------------------------------------------------------


def test_the_insecure_warning_is_printed_once_before_the_probe_request(rig: Rig) -> None:
    rig.gw.scripts.append(ConnectionScript(status=429))
    code, out, err = rig.run(["--json", "--quiet", "validate", "--probe"], config=rig.cfg(HTTP))
    assert code == 0 and err.count(INSECURE_HTTP_WARNING) == 1 and "warnings" not in out
    assert len(rig.gw.connections) == 2


def test_no_insecure_warning_without_a_request(rig: Rig) -> None:
    assert INSECURE_HTTP_WARNING not in rig.run(["validate"], config=rig.cfg(HTTP))[2]
    err = rig.run(["validate", "--probe"], config=rig.cfg(HTTP), env={})[2]
    assert INSECURE_HTTP_WARNING not in err
    assert INSECURE_HTTP_WARNING not in rig.run(["validate", "--probe"])[2]  # https


def test_the_insecure_warning_is_printed_when_the_probe_fails(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(status=401)
    err = rig.run(["validate", "--probe"], config=rig.cfg(HTTP))[2]
    assert err.splitlines()[0] == INSECURE_HTTP_WARNING and "probe: failed" in err


# --- test message ---------------------------------------------------------------------------

BODY = b'{"title":"ha-notice","message":"validate: test message"}'
LIST = ConnectionScript(body=b"[]")  # what a send expects (a probe expects an object)


def posts(gw: FakeGateway) -> list[Any]:
    return [r for c in gw.connections for r in c.requests if r.method == "POST"]


def methods(gw: FakeGateway) -> list[str]:
    return [r.method for c in gw.connections for r in c.requests]


def log_records(rig: Rig) -> list[dict[str, Any]]:
    path = Path(rig.gw.home) / ".local" / "state" / "ha-notice" / "log.jsonl"  # type: ignore[arg-type]
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_the_default_test_message_passes_every_rule_and_is_stable() -> None:
    from ha_notice.payload import sanitize_message, sanitize_title, validate_notification
    from ha_notice.validate import TEST_MESSAGE, TEST_TITLE

    note = validate_notification(
        {"title": TEST_TITLE, "message": TEST_MESSAGE, "level": "info"}, []
    )
    assert (note.title, note.message, note.level, note.link) == (
        "ha-notice",
        "validate: test message",
        "info",
        None,
    )
    assert sanitize_message(TEST_MESSAGE) == TEST_MESSAGE
    assert sanitize_title(TEST_TITLE) == TEST_TITLE
    assert TEST_MESSAGE.isascii() and " " in TEST_MESSAGE


def test_test_message_ok_sends_one_post_through_the_normal_path(rig: Rig, golden: Golden) -> None:
    rig.gw.default_script = LIST
    code, out, err = rig.run(["--json", "validate", "--test-message"])
    assert (code, err) == (0, "")
    golden.check("output", "validate-test-message-ok.json", out, schema="cli/validate")
    request = only_request(rig.gw)
    assert (request.method, request.path) == ("POST", "/api/services/notify/mobile_app_x")
    golden.check("request", "validate-test-message.json", request.body.decode())
    headers = {k.lower(): v for k, v in request.headers.items()}
    assert headers["authorization"] == f"Bearer {TOKEN}"
    assert headers["content-type"] == "application/json"


def test_test_message_uses_the_config_group_like_any_send(rig: Rig) -> None:
    rig.gw.default_script = LIST
    config = rig.cfg(BASE + "default_group: ops\n")
    assert rig.run(["--json", "validate", "--test-message"], config=config)[0] == 0
    assert json.loads(only_request(rig.gw).body)["data"] == {"group": "ops"}


def test_test_message_is_logged_like_a_send_and_never_records_content(
    rig: Rig, golden: Golden
) -> None:
    rig.gw.default_script = LIST
    rig.run(["--json", "validate", "--test-message", "--actor", "human:tester"])
    path = Path(rig.gw.home) / ".local" / "state" / "ha-notice" / "log.jsonl"  # type: ignore[arg-type]
    text = path.read_text(encoding="utf-8")
    assert "validate" not in text and "test message" not in text and TOKEN not in text
    record = json.loads(text)
    assert schema_errors("log", record) == []
    assert (record["outcome"], record["exit"], record["level"], record["tag_set"]) == (
        "sent",
        0,
        "info",
        False,
    )
    assert record["dedupe_key_sha256"] is None and record["bytes"] == len(BODY)
    assert (record["actor"], record["actor_source"]) == ("human:tester", "flag")
    from ha_notice import __version__

    golden.check(
        "log",
        "validate-test-message-sent.jsonl",
        text.replace(f'"version":"{__version__}"', '"version":"0.1.0"'),
        schema="log",
    )


def test_test_message_with_log_false_writes_no_log(rig: Rig) -> None:
    rig.gw.default_script = LIST
    assert rig.run(["validate", "--test-message"], config=rig.cfg(BASE + "log: false\n"))[0] == 0
    assert log_records(rig) == []


def test_dry_run_does_not_stop_the_test_message(rig: Rig) -> None:
    rig.gw.default_script = LIST
    code, out, _ = rig.run(["--dry-run", "--json", "validate", "--test-message"])
    assert code == 0 and names(out) == ["config", "credential", "test_message"]
    assert len(posts(rig.gw)) == 1 and len(log_records(rig)) == 1


def test_human_output_says_delivery_is_not_observable(rig: Rig) -> None:
    rig.gw.default_script = LIST
    code, out, err = rig.run(["validate", "--test-message"])
    assert code == 0 and out == ""
    last = err.splitlines()[-1]
    assert last.startswith("test_message: ok: ") and "not observable" in last
    assert "destination" in last
    assert rig.run(["--quiet", "validate", "--test-message"])[2] == ""


def test_probe_then_test_message_run_in_order_with_two_requests(rig: Rig, golden: Golden) -> None:
    rig.gw.scripts.append(ConnectionScript(body=b"{}"))
    rig.gw.default_script = LIST
    code, out, err = rig.run(["--json", "validate", "--probe", "--test-message"])
    assert (code, err) == (0, "")
    golden.check("output", "validate-probe-test-message-ok.json", out, schema="cli/validate")
    assert methods(rig.gw) == ["GET", "POST"]


@pytest.mark.parametrize(
    ("script", "message", "outcome"),
    [
        (ConnectionScript(status=401), "auth_required", "failed"),
        (ConnectionScript(status=400), "host_rejected", "failed"),
        (ConnectionScript(status=404), "wrong_host_response", "failed"),
        (ConnectionScript(body=b"{}"), "wrong_host_response", "outcome_unknown"),
    ],
    ids=["401", "400", "404", "200_object"],
)
def test_a_failed_send_is_a_failed_check_with_exit_12_and_a_fixed_message(
    rig: Rig, script: ConnectionScript, message: str, outcome: str
) -> None:
    rig.gw.default_script = script
    code, out, err = rig.run(["--json", "validate", "--test-message"])
    assert code == 12 and err == ""
    check = doc(out)["checks"][-1]
    assert (check["name"], check["ok"]) == ("test_message", False)
    assert "not observable" in check["message"] and "destination" in check["message"]
    assert message not in check["message"]  # the interface: only the exit code is carried
    assert TOKEN not in out and "ha.example" not in out and "validate:" not in check["message"]
    assert [r["outcome"] for r in log_records(rig)] == [outcome]
    assert log_records(rig)[0]["code"] == message
    assert len(posts(rig.gw)) == 1


def test_a_failed_send_golden(rig: Rig, golden: Golden) -> None:
    rig.gw.default_script = ConnectionScript(status=401)
    out = rig.run(["--json", "validate", "--test-message"])[1]
    golden.check("output", "validate-test-message-failed.json", out, schema="cli/validate")


def test_a_failed_check_after_a_good_probe_exits_12(rig: Rig) -> None:
    rig.gw.scripts.append(ConnectionScript(body=b"{}"))
    rig.gw.default_script = ConnectionScript(status=500)
    code, out, _ = rig.run(["--json", "validate", "--probe", "--test-message"])
    result = doc(out)
    assert code == 12 and result["ok"] is False and result["probe"] == {"api_ok": True}
    assert [(c["name"], c["ok"]) for c in result["checks"]][-2:] == [
        ("probe", True),
        ("test_message", False),
    ]
    assert methods(rig.gw) == ["GET", "POST"]  # a 500 without a tag is not retried: one POST


def test_a_429_is_retried_like_a_send_and_sends_once_in_the_end(rig: Rig) -> None:
    rig.gw.scripts.append(ConnectionScript(status=429))
    rig.gw.default_script = LIST
    code, _, _ = rig.run(["--json", "validate", "--test-message"])
    assert code == 0 and methods(rig.gw) == ["POST", "POST"]
    assert [r["outcome"] for r in log_records(rig)] == ["sent"]


def test_an_unknown_outcome_is_never_sent_twice(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(
        request_error=ConnectionResetError(), request_bytes_before_error=5
    )
    code, out, _ = rig.run(["--json", "validate", "--test-message"])
    assert code == 12 and doc(out)["checks"][-1]["ok"] is False
    assert len(rig.gw.connections) == 1
    assert [r["outcome"] for r in log_records(rig)] == ["outcome_unknown"]


def test_a_stalled_host_is_the_deadline_and_ends_the_process_after_the_report(
    rig: Rig, release: threading.Event
) -> None:
    rig.gw.default_script = ConnectionScript(stall_after_first_byte=release)

    def drive() -> None:
        for _ in range(4000):
            if rig.gw.connections and rig.gw.connections[0].requests:
                break
            release.wait(0.002)
        rig.gw.advance(TIMEOUT_S + 0.1)

    driver = threading.Thread(target=drive, daemon=True)
    driver.start()
    code, out, _ = rig.run(["--json", "validate", "--test-message"])
    driver.join(10)
    assert code == 12 and rig.exited and rig.gw.exits == [12]
    assert doc(out)["checks"][-1]["ok"] is False
    records = log_records(rig)
    assert [r["outcome"] for r in records] == ["outcome_unknown"]  # logged before the exit


def test_the_test_message_deadline_starts_with_the_check(rig: Rig) -> None:
    class Slow(FakeGateway):
        def read_config(self, path: str, max_bytes: int) -> bytes | None:
            data = super().read_config(path, max_bytes)
            if path.endswith("c.yaml"):
                self.advance(TIMEOUT_S * 3)
            return data

    gw = Slow(home=rig.gw.home, ca=rig.gw.ca, default_script=LIST)
    assert rig.run(["--json", "validate", "--test-message"], gateway=gw)[0] == 0
    assert len(posts(gw)) == 1


def test_the_test_message_deadline_is_its_own_after_a_slow_probe(rig: Rig) -> None:
    rig.gw.scripts.append(ConnectionScript(body=b"{}", connect_delay=2.9))
    rig.gw.default_script = ConnectionScript(body=b"[]", connect_delay=2.9)
    code, _, _ = rig.run(["--json", "validate", "--probe", "--test-message"])
    assert code == 0 and not rig.exited and len(posts(rig.gw)) == 1


def test_a_test_message_is_not_sent_after_a_failed_probe_or_credential(rig: Rig) -> None:
    rig.gw.scripts.append(ConnectionScript(status=401))
    code, out, _ = rig.run(["--json", "validate", "--probe", "--test-message"])
    assert code == 12 and names(out) == ["config", "credential", "probe"]
    assert methods(rig.gw) == ["GET"] and log_records(rig) == []
    code, out, _ = rig.run(["--json", "validate", "--test-message"], env={})
    assert code == 12 and names(out) == ["config", "credential"]
    assert methods(rig.gw) == ["GET"]


def test_a_missing_service_is_a_failed_config_check_and_sends_nothing(rig: Rig) -> None:
    config = rig.cfg("base_url: https://ha.example\n")
    code, out, _ = rig.run(["--json", "validate", "--test-message"], config=config)
    assert code == 2 and names(out) == ["config"] and rig.gw.connections == []


def test_the_token_never_leaks_through_the_test_message_outputs(rig: Rig) -> None:
    rig.gw.default_script = LIST
    code, out, err = rig.run(["--verbose", "validate", "--test-message"])
    assert code == 0 and TOKEN not in out + err
    assert "validate: test message" not in out + err


# --- insecure http and the test message -----------------------------------------------------


def test_the_insecure_warning_is_printed_once_for_a_probe_and_a_test_message(rig: Rig) -> None:
    rig.gw.scripts.append(ConnectionScript(body=b"{}"))
    rig.gw.default_script = LIST
    args = ["--quiet", "validate", "--probe", "--test-message"]
    code, _, err = rig.run(args, config=rig.cfg(HTTP))
    assert code == 0 and err.count(INSECURE_HTTP_WARNING) == 1 and len(rig.gw.connections) == 2


def test_the_insecure_warning_is_printed_once_for_a_test_message_alone(rig: Rig) -> None:
    rig.gw.default_script = LIST
    err = rig.run(["--json", "validate", "--test-message"], config=rig.cfg(HTTP))[2]
    assert err.splitlines() == [INSECURE_HTTP_WARNING]


def test_no_insecure_warning_when_no_test_message_request_is_made(rig: Rig) -> None:
    err = rig.run(["validate", "--test-message"], config=rig.cfg(HTTP), env={})[2]
    assert INSECURE_HTTP_WARNING not in err and rig.gw.connections == []


# --- signals --------------------------------------------------------------------------------


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_signal_before_the_probe_is_128_plus_n_with_no_output(rig: Rig, signum: int) -> None:
    class Sig(FakeGateway):
        def ca_candidates(self) -> CaCandidates:  # runs in make_target, before the worker
            self.deliver_signal(signum)
            return super().ca_candidates()

    gw = Sig(home=rig.gw.home, ca=rig.gw.ca)
    assert rig.run(["--json", "validate", "--probe"], gateway=gw) == (128 + signum, "", "")
    assert gw.connections == []


def test_a_signal_during_plain_validate_is_128_plus_n(rig: Rig) -> None:
    class Sig(FakeGateway):
        def read_config(self, path: str, max_bytes: int) -> bytes | None:
            data = super().read_config(path, max_bytes)
            self.deliver_signal(signal.SIGTERM)
            return data

    gw = Sig(home=rig.gw.home)
    assert rig.run(["--json", "validate"], gateway=gw) == (143, "", "")


def test_a_signal_during_the_probe_is_decided_like_the_deadline(
    rig: Rig, release: threading.Event
) -> None:
    rig.gw.default_script = ConnectionScript(connect_block=release)

    def drive() -> None:
        for _ in range(4000):
            if rig.gw.connections:
                break
            release.wait(0.002)
        rig.gw.deliver_signal(signal.SIGTERM)

    driver = threading.Thread(target=drive, daemon=True)
    driver.start()
    code, out, _ = rig.run(["--json", "validate", "--probe"])
    driver.join(10)
    assert code == 12 and rig.exited
    assert doc(out)["checks"][-1]["message"].startswith("network_error")


@pytest.mark.parametrize(
    "script",
    [
        ConnectionScript(connect_error=ValueError("x")),
        ConnectionScript(request_error=KeyError("x"), request_bytes_before_error=5),
    ],
    ids=["connect_error", "request_error_after_partial_write"],
)
def test_an_internal_probe_verdict_is_exit_1_with_one_internal_envelope(
    rig: Rig, script: ConnectionScript
) -> None:
    rig.gw.default_script = script
    code, out, err = rig.run(["--json", "validate", "--probe"])
    assert code == 1 and out.count("\n") == 1
    body = json.loads(out)
    assert body["error"]["code"] == "internal" and "checks" not in body
    assert err.splitlines().count("internal: internal error") == 1
    assert TOKEN not in out + err


# --- failures that are bugs -----------------------------------------------------------------


def test_one_envelope_only_when_the_report_fails(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    from ha_notice import validate as v

    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("x")

    monkeypatch.setattr(v, "dumps", boom)
    code, out, _ = rig.run(["--json", "validate"])
    assert code == 1 and out.count("\n") == 1
    assert json.loads(out)["error"]["code"] == "internal"


# --- test message: signals and bugs ---------------------------------------------------------


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_signal_before_the_test_message_is_128_plus_n_with_no_output_and_no_log(
    rig: Rig, signum: int
) -> None:
    class Sig(FakeGateway):
        def ca_candidates(self) -> CaCandidates:  # runs in make_target, before the worker
            self.deliver_signal(signum)
            return super().ca_candidates()

    gw = Sig(home=rig.gw.home, ca=rig.gw.ca, default_script=LIST)
    assert rig.run(["--json", "validate", "--test-message"], gateway=gw) == (128 + signum, "", "")
    assert gw.connections == [] and log_records(rig) == []


def test_a_signal_during_the_send_is_decided_by_the_gate_like_the_deadline(
    rig: Rig, release: threading.Event
) -> None:
    rig.gw.default_script = ConnectionScript(stall_after_first_byte=release)

    def drive() -> None:
        for _ in range(4000):
            if rig.gw.connections and rig.gw.connections[0].requests:
                break
            release.wait(0.002)
        rig.gw.deliver_signal(signal.SIGTERM)

    driver = threading.Thread(target=drive, daemon=True)
    driver.start()
    code, out, _ = rig.run(["--json", "validate", "--test-message"])
    driver.join(10)
    assert code == 12 and rig.exited  # not 143: the send had started
    assert doc(out)["checks"][-1]["ok"] is False
    assert [r["outcome"] for r in log_records(rig)] == ["outcome_unknown"]


def test_an_internal_failure_before_writing_is_exit_1_and_not_logged(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(connect_error=ValueError("x"))
    code, out, err = rig.run(["--json", "validate", "--test-message"])
    assert code == 1 and out.count("\n") == 1
    body = json.loads(out)["error"]
    assert body["code"] == "internal" and body["unknown_outcome"] is False
    assert err.splitlines().count("internal: internal error") == 1
    assert log_records(rig) == [] and TOKEN not in out + err


def test_an_internal_failure_after_writing_is_exit_1_unknown_outcome_and_logged(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(
        request_error=KeyError("x"), request_bytes_before_error=5
    )
    code, out, err = rig.run(["--json", "validate", "--test-message"])
    assert code == 1 and out.count("\n") == 1
    body = json.loads(out)["error"]
    assert body["code"] == "internal" and body["unknown_outcome"] is True
    assert err.splitlines().count("internal: internal error") == 1
    records = log_records(rig)
    assert [(r["outcome"], r["code"], r["exit"]) for r in records] == [
        ("outcome_unknown", "internal", 1)
    ]
    assert len(rig.gw.connections) == 1


def test_a_failing_report_after_the_send_is_one_unknown_outcome_envelope_and_a_log(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ha_notice import validate as v

    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("x")

    rig.gw.default_script = LIST
    monkeypatch.setattr(v, "dumps", boom)
    code, out, _ = rig.run(["--json", "validate", "--test-message"])
    assert code == 1 and out.count("\n") == 1
    error = json.loads(out)["error"]
    assert error["code"] == "internal" and error["unknown_outcome"] is True
    assert len(posts(rig.gw)) == 1
    assert [(r["outcome"], r["code"]) for r in log_records(rig)] == [
        ("outcome_unknown", "internal")
    ]
