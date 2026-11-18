"""The ``clear`` command (issue #38): parser, rendering, the flow with the fake gateway, goldens.

``clear --dedupe-key=<k>`` sends the companion-app command message ``clear_notification`` with
the tag derived from the key, through the machinery of ``send`` (docs/interface.md, ``clear``).
Real-socket tests are in tests/test_clear_socket.py.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
import signal
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ha_notice import cli as cli_module
from ha_notice import render as render_module
from ha_notice import send as send_module
from ha_notice.cli import main
from ha_notice.gateway import CaCandidates
from ha_notice.payload import PayloadError, notification_from_flags
from ha_notice.render import render, render_clear, serialize, tag_from_dedupe_key
from ha_notice.state import STATE_WARNING
from tests.fake_gateway import ConnectionScript, FakeGateway, private_home
from tests.harness import Golden, schema_errors
from tests.test_send import (
    BASE,
    ENV,
    ROWS,
    TIMEOUT_S,
    TOKEN,
    Rig,
    _row,
    _when,
    _writing,
    error_of,
    only_request,
)

KEY = "k1"
TAG = tag_from_dedupe_key(KEY)
BODY = {"message": "clear_notification", "data": {"tag": TAG}}
CLEAR = ["--json", "clear", f"--dedupe-key={KEY}"]


@pytest.fixture
def rig(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    self_signed_cert: tuple[Path, Path],
) -> Rig:
    gw = FakeGateway(
        home=private_home(tmp_path),
        ca=CaCandidates(str(self_signed_cert[0]), "", ()),
        sources={0: b'{"message":"must not be read"}'},
    )
    return Rig(tmp_path, gw, capsys)


@pytest.fixture
def release() -> Iterator[threading.Event]:
    event = threading.Event()
    yield event
    event.set()


# --- rendering -------------------------------------------------------------------------------


def test_render_clear_is_the_exact_body() -> None:
    rendered = render_clear(TAG)
    assert rendered.body == BODY and rendered.truncated is False
    assert list(rendered.body) == ["message", "data"] and list(rendered.body["data"]) == ["tag"]
    assert serialize(rendered.body) == (
        b'{"message":"clear_notification","data":{"tag":"' + TAG.encode() + b'"}}'
    )
    assert "title" not in rendered.body


@pytest.mark.parametrize("key", ["k1", "é", "😀" * 10, "a" * 1024, "x y\n", "-dash"])
def test_the_tag_is_the_one_of_send(key: str) -> None:
    digest = hashlib.sha256(key.encode()).hexdigest()[:24]
    assert render_clear(tag_from_dedupe_key(key)).body["data"]["tag"] == f"awkit-{digest}"
    send_body = render(
        notification_from_flags(title=None, message="m", level=None, link=None, link_hosts=None),
        max_chars=1000,
        default_group=None,
        level_prefix={"info": ""},
        tag=tag_from_dedupe_key(key),
    ).body
    assert send_body["data"]["tag"] == render_clear(tag_from_dedupe_key(key)).body["data"]["tag"]


@pytest.mark.parametrize(
    "tag", ["", "awkit-", "awkit-XYZ", "AWKIT-" + "0" * 24, "x" * 30, TAG + "0"]
)
def test_render_clear_refuses_anything_but_a_tag(tag: str) -> None:
    with pytest.raises(ValueError):
        render_clear(tag)


# --- send can never clear --------------------------------------------------------------------

VARIANTS = [
    "clear_notification",
    "CLEAR_NOTIFICATION",
    "Clear_Notification",
    "  clear_notification  ",
    "\nclear_notification\n",
    "ｃlear_notification",  # fullwidth c
    "clear_ｎotification",
    "clea\x00r_notification",  # the sanitizer removes the NUL first
    "clear_notificatio­n",  # soft hyphen is removed first
]


@pytest.mark.parametrize("message", VARIANTS)
def test_send_still_refuses_clear_notification(message: str) -> None:
    with pytest.raises(PayloadError) as info:
        notification_from_flags(title=None, message=message, level=None, link=None, link_hosts=None)
    assert info.value.reason == "command_keyword"


@pytest.mark.parametrize("message", VARIANTS)
def test_send_with_clear_notification_exits_20_through_the_cli(rig: Rig, message: str) -> None:
    code, out, _ = rig.run(["--json", "send", f"--message={message}", f"--dedupe-key={KEY}"])
    body = error_of(out)
    assert (code, body["code"], body["reason"]) == (20, "refused", "command_keyword")
    assert rig.gw.connections == []


def test_send_input_can_never_make_the_clear_body(rig: Rig) -> None:
    """Whatever the message, the body of a send is never the clear body: a message that is the
    keyword is refused, and no other input renders to it (a title or a link beside it changes
    nothing; the tag only goes into ``data``)."""
    messages = [*VARIANTS, "clear_notification x", "clear notification", "clear_notification.", "x"]
    for message in messages:
        code, out, _ = rig.run(
            ["--json", "--dry-run", "send", f"--message={message}", "--dedupe-key=k"]
        )
        if code == 0:
            assert json.loads(out)["rendered"]["message"] != "clear_notification"
        else:
            assert code == 20
    for message in messages:  # the same through stdin JSON
        rig.gw.sources[0] = json.dumps({"message": message, "title": "t"}).encode()
        code, out, _ = rig.run(["--json", "--dry-run", "send", "--stdin-json"])
        assert code == 20 or json.loads(out)["rendered"]["message"] != "clear_notification"


def test_only_the_clear_plan_builds_a_command_body() -> None:
    """``render_clear`` is called from ``build_clear_plan`` alone; the send path never names it."""
    src = Path(inspect.getfile(send_module)).parent
    users = [
        p.name
        for p in src.glob("*.py")
        if re.search(r"\brender_clear\(", p.read_text(encoding="utf-8")) and p.name != "render.py"
    ]
    assert users == ["send.py"]
    assert "render_clear" not in inspect.getsource(send_module.build_plan)
    assert "render_clear" not in inspect.getsource(send_module.run_send)
    assert "render_clear" not in inspect.getsource(render_module.render)
    assert "clear_notification" not in inspect.getsource(send_module.build_plan)


# --- the parser ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["clear"],
        ["clear", "--dedupe-key="],
        ["clear", "--dedupe-key"],
        ["clear", "--dedupe-key", ""],
        ["clear", "--dedupe-key=" + "a" * 1025],
        ["clear", "--dedupe-key", "-abc"],
        ["clear", "--dedupe-key", "--x"],
        ["clear", "--dedupe-key=a", "--dedupe-key=b"],
        ["clear", "--dedupe-key=a", "--message=hi"],
        ["clear", "--dedupe-key=a", "--title=t"],
        ["clear", "--dedupe-key=a", "--stdin-json"],
        ["clear", "--dedupe-key=a", "--file=x"],
        ["clear", "--dedupe-key=a", "--level=info"],
        ["clear", "--dedupe-key=a", "--link=https://x.example"],
        ["clear", "--dedupe-key=a", "--decision-id=x"],
        ["clear", "--dedupe-key=a", "--probe"],
        ["clear", "--dedupe-key=a", "--bogus"],
        ["clear", "--dedupe-key=a", "extra"],
        ["clear", "--dedupe-key=a", "--"],
        ["clear", "--dedupe-key=a", "-x"],
        ["clear", "--dedupe-key=a", "--verbose", "--quiet"],
        ["clear", "--dedupe-key=a", "--actor=bad"],
        ["clear", "--dedupe-key=a", "--dedup=b"],
        ["--dedupe-key=a", "clear"],
    ],
)
def test_clear_usage_errors_exit_2_before_anything_else(rig: Rig, argv: list[str]) -> None:
    code, out, err = rig.run(["--json", *argv])
    body = error_of(out)
    assert (code, body["code"]) == (2, "usage")
    assert err == f"usage: {body['message']}\n" and "a" * 10 not in err
    assert rig.gw.connections == [] and not rig.state_dir.exists()


def test_a_usage_error_wins_over_a_disabled_tool_and_a_bad_config(rig: Rig) -> None:
    assert rig.run(["clear"], config=rig.cfg("enabled: false\n"))[0] == 2
    assert rig.run(["clear"], config=str(rig.tmp / "missing.yaml"))[0] == 2


def test_an_invalid_utf8_key_is_a_usage_error(rig: Rig) -> None:
    code, out, _ = rig.run(["--json", "clear", "--dedupe-key=\udcff"])
    assert code == 2 and error_of(out)["code"] == "usage"


@pytest.mark.parametrize(
    "argv",
    [
        ["clear", "--dedupe-key=k"],
        ["clear", "--dedupe-key", "k"],
        ["clear", "--dedupe-key=-lead"],
        ["clear", "--dedupe-key=" + "a" * 1024],
        ["clear", "--dedupe-key=😀"],
        ["--json", "clear", "--dedupe-key=k"],
        ["clear", "--dedupe-key=k", "--json"],
        ["--quiet", "clear", "--dedupe-key=k"],
        ["clear", "--quiet", "--dedupe-key=k"],
        ["--verbose", "clear", "--dedupe-key=k"],
        ["--dry-run", "clear", "--dedupe-key=k"],
        ["clear", "--dry-run", "--dedupe-key=k"],
        ["--actor=auto:x", "clear", "--dedupe-key=k"],
        ["clear", "--actor=human:x", "--dedupe-key=k"],
    ],
)
def test_clear_accepts(rig: Rig, argv: list[str]) -> None:
    assert rig.run(argv)[0] == 0


def test_help_works_for_clear(rig: Rig) -> None:
    code, out, err = rig.run(["clear", "-h"])
    assert code == 0 and "--dedupe-key" in out and "--message" not in out and err == ""
    assert rig.run(["-h", "clear"])[0] == 0
    assert rig.run(["clear", "--help", "--dedupe-key=k"])[0] == 0


def test_no_stdin_is_read(rig: Rig) -> None:
    rig.gw.sources.clear()  # a read of fd 0 would be a failure of the fake
    calls: list[Any] = []
    original = rig.gw.read_source
    rig.gw.read_source = lambda *a, **k: (calls.append(a), original(*a, **k))[1]  # type: ignore[method-assign]
    assert rig.run(CLEAR)[0] == 0 and calls == []


# --- the flow --------------------------------------------------------------------------------


def test_sent_output_request_and_log_goldens(rig: Rig, golden: Golden) -> None:
    code, out, err = rig.run(CLEAR)
    assert (code, err) == (0, "")
    assert schema_errors("cli/clear", json.loads(out)) == []
    golden.check("output", "clear-sent.json", out, schema="cli/clear")
    request = only_request(rig.gw)
    assert request.method == "POST" and request.path == "/api/services/notify/mobile_app_x"
    assert request.body == serialize(BODY)
    golden.check("request", "clear.json", request.body.decode())
    golden.check("log", "clear-sent.jsonl", rig.log_text(), schema="log")
    [record] = rig.records()
    assert record["message_sha256"] is None and record["tag_set"] is True
    assert record["dedupe_key_sha256"] == hashlib.sha256(KEY.encode()).hexdigest()[:16]
    assert record["level"] == "info" and record["bytes"] == len(serialize(BODY))
    assert record["truncated"] is False and record["outcome"] == "sent"


def test_a_failed_clear_log_golden(rig: Rig, golden: Golden) -> None:
    rig.gw.default_script = _row(401)
    assert rig.run(CLEAR)[0] == 12
    golden.check("log", "clear-auth-required.jsonl", rig.log_text(), schema="log")


def test_the_missing_key_usage_golden(rig: Rig, golden: Golden) -> None:
    code, out, _ = rig.run(["--json", "clear"])
    assert code == 2
    golden.check("output", "usage-clear-missing-key.json", out, schema="cli/error")


def test_the_human_line_and_quiet(rig: Rig) -> None:
    assert rig.run(["clear", f"--dedupe-key={KEY}"]) == (0, "", "sent (info, 0 ms)\n")
    assert rig.run(["--quiet", "clear", f"--dedupe-key={KEY}"]) == (0, "", "")


def test_the_request_carries_the_token_only_as_the_header(rig: Rig) -> None:
    rig.run(CLEAR)
    request = only_request(rig.gw)
    assert [h for h, v in request.headers.items() if TOKEN in v] == ["Authorization"]
    assert TOKEN.encode() not in request.body and TOKEN not in request.path
    assert all(c.spec.host == "ha.example" for c in rig.gw.connections)


def test_the_dry_run_prints_the_exact_body_and_touches_nothing(rig: Rig, golden: Golden) -> None:
    calls: list[str] = []
    for name in ("open_state_dir", "open_state_file", "try_lock", "write_fd", "connect", "resolve"):
        original = getattr(rig.gw, name)

        def spy(*a: Any, _n: str = name, _o: Any = original, **k: Any) -> Any:
            calls.append(_n)
            return _o(*a, **k)

        setattr(rig.gw, name, spy)
    code, out, err = rig.run(["--dry-run", *CLEAR], config=rig.cfg(""), env={})
    assert (code, err) == (0, "")  # no base_url, no service, no token needed
    doc = json.loads(out)
    assert schema_errors("cli/clear", doc) == [] and doc["rendered"] == BODY
    assert doc["bytes"] == len(serialize(BODY)) and doc["http_status"] is None
    golden.check("output", "clear-dry-run.json", out, schema="cli/clear")
    assert (
        calls == []
        and rig.gw.connections == []
        and not (Path(str(rig.gw.home)) / ".local").exists()
    )
    human = rig.run(["--dry-run", "clear", f"--dedupe-key={KEY}"], config=rig.cfg(""), env={})
    assert human == (0, "", serialize(BODY).decode() + "\n")
    assert rig.run(["--dry-run", "--quiet", "clear", f"--dedupe-key={KEY}"])[1:] == ("", "")


def test_dry_run_body_is_the_post_body(rig: Rig) -> None:
    dry = serialize(json.loads(rig.run(["--dry-run", *CLEAR])[1])["rendered"])
    rig.run(CLEAR)
    assert only_request(rig.gw).body == dry


def test_disabled_is_exit_22_with_no_read_and_no_call(rig: Rig) -> None:
    code, out, err = rig.run(CLEAR, config=rig.cfg("enabled: false\n"))
    assert (code, json.loads(out), err) == (22, {"outcome": "disabled"}, "")
    assert rig.gw.connections == [] and not rig.state_dir.exists()
    assert rig.run(["clear", f"--dedupe-key={KEY}"], config=rig.cfg("enabled: false\n"))[2] == (
        "disabled in config\n"
    )
    assert rig.run(["--dry-run", *CLEAR], config=rig.cfg("enabled: false\n"))[0] == 22


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("service: s\n", "base_url"),
        ("base_url: https://ha.example\n", "service"),
        (BASE + "ca_file: /nonexistent/ca.pem\n", "ca_file"),
        ("base_url: ftp://x\nservice: s\n", "base_url"),
    ],
)
def test_destination_problems_are_exit_2_config_invalid_as_for_send(
    rig: Rig, text: str, key: str
) -> None:
    code, out, _ = rig.run(CLEAR, config=rig.cfg(text))
    body = error_of(out)
    assert (code, body["code"], body["details"]["key"]) == (2, "config_invalid", key)
    assert rig.gw.connections == [] and not rig.state_dir.exists()


def test_a_missing_or_invalid_token_is_credential_invalid(rig: Rig) -> None:
    for env in ({}, {"HA_TOKEN": "bad token"}, {"HA_TOKEN": ""}):
        code, out, _ = rig.run(CLEAR, env=env)
        body = error_of(out)
        assert (code, body["code"], body["details"]) == (
            12,
            "credential_invalid",
            {"env": "HA_TOKEN"},
        )
    assert rig.gw.connections == []
    assert rig.records()[0]["code"] == "credential_invalid" and rig.records()[0]["tag_set"] is True


@pytest.mark.parametrize("name", list(ROWS))
def test_response_table_for_clear(rig: Rig, name: str) -> None:
    """Every row of the response table, with the retry rules of a tagged request (a clear always
    carries its tag, so ``outcome_unknown`` and ``upstream_error`` are retryable)."""
    row = ROWS[name]
    rig.gw.default_script = row.script
    code, out, err = rig.run(CLEAR, config=rig.cfg(timeout=10))
    assert code == row.exit and len(rig.gw.connections) == row.requests
    if row.exit == 0:
        assert json.loads(out)["http_status"] == row.status
        return
    body = error_of(out)
    assert body["code"] == row.code and body["unknown_outcome"] is row.unknown
    assert body["retryable"] is (True if row.code == "upstream_error" else row.retryable)
    assert err == f"{body['code']}: {body['message']}\n"
    record = rig.records()[0]
    assert record["tag_set"] is True and record["message_sha256"] is None
    assert record["outcome"] == ("outcome_unknown" if row.unknown else "failed")
    assert schema_errors("log", record) == []


def test_429_is_retried_twice_then_sent(rig: Rig) -> None:
    rig.gw.scripts.extend([ConnectionScript(status=429), ConnectionScript(status=429)])
    code, out, _ = rig.run(CLEAR, config=rig.cfg(timeout=10))
    assert code == 0 and rig.gw.sleeps == [2, 4] and len(rig.gw.connections) == 3
    assert {c.requests[0].body for c in rig.gw.connections} == {serialize(BODY)}


def test_a_connect_failure_is_retried_once(rig: Rig) -> None:
    rig.gw.default_script = ConnectionScript(connect_error=ConnectionRefusedError(111, "x"))
    code, out, _ = rig.run(CLEAR, config=rig.cfg(timeout=10))
    assert code == 12 and error_of(out)["code"] == "network_error"
    assert rig.gw.sleeps == [2] and len(rig.gw.connections) == 2


def test_a_drop_after_the_first_byte_is_outcome_unknown_retryable_and_never_resent(
    rig: Rig,
) -> None:
    rig.gw.default_script = ConnectionScript(response_error=ConnectionResetError(104, "x"))
    code, out, _ = rig.run(CLEAR)
    body = error_of(out)
    assert code == 12 and body["code"] == "outcome_unknown"
    assert body["retryable"] is True and body["unknown_outcome"] is True
    assert len(rig.gw.connections) == 1 and len(rig.gw.connections[0].requests) == 1
    assert rig.records()[0]["outcome"] == "outcome_unknown"


def test_the_deadline_while_writing_is_outcome_unknown(rig: Rig, release: threading.Event) -> None:
    rig.gw.default_script = ConnectionScript(stall_after_first_byte=release)
    driver = _when(lambda: _writing(rig.gw), lambda: rig.gw.advance(TIMEOUT_S + 0.1))
    code, out, _ = rig.run(CLEAR)
    driver.join(10)
    body = error_of(out)
    assert code == 12 and rig.exited and body["code"] == "outcome_unknown"
    assert body["retryable"] is True and len(rig.gw.connections[0].requests) == 1
    assert rig.records()[0]["tag_set"] is True


def test_the_deadline_while_connecting_is_network_error(rig: Rig, release: threading.Event) -> None:
    rig.gw.default_script = ConnectionScript(connect_block=release)
    driver = _when(lambda: bool(rig.gw.connections), lambda: rig.gw.advance(TIMEOUT_S + 0.1))
    code, out, _ = rig.run(CLEAR)
    driver.join(10)
    body = error_of(out)
    assert code == 12 and body["code"] == "network_error" and body["unknown_outcome"] is False
    assert rig.gw.connections[0].requests == []


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_signal_during_the_send_is_decided_by_the_gate(
    rig: Rig, release: threading.Event, signum: int
) -> None:
    rig.gw.default_script = ConnectionScript(stall_after_first_byte=release)
    driver = _when(lambda: _writing(rig.gw), lambda: rig.gw.deliver_signal(signum))
    code, out, _ = rig.run(CLEAR)
    driver.join(10)
    assert code == 12 and error_of(out)["code"] == "outcome_unknown"


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_signal_before_the_send_is_128_plus_n_and_unlogged(rig: Rig, signum: int) -> None:
    class Sig(FakeGateway):
        def ca_candidates(self) -> CaCandidates:
            self.deliver_signal(signum)
            return super().ca_candidates()

    gw = Sig(home=rig.gw.home, ca=rig.gw.ca)
    assert rig.run(CLEAR, gateway=gw) == (128 + signum, "", "")
    assert gw.connections == [] and not rig.state_dir.exists()


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_signal_at_the_start_of_clear_is_128_plus_n_and_unlogged(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, signum: int
) -> None:
    real = cli_module.run_clear

    def signalled(inv: Any) -> int:
        rig.gw.deliver_signal(signum)  # pending before run_clear's first check
        return real(inv)

    monkeypatch.setattr(cli_module, "run_clear", signalled)
    assert rig.run(CLEAR) == (128 + signum, "", "")
    assert rig.gw.connections == [] and not rig.state_dir.exists()


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
def test_a_signal_after_the_render_is_128_plus_n_with_no_send_and_no_log(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, signum: int, dry_run: bool
) -> None:
    real = send_module.build_clear_plan

    def signalled(*args: Any) -> Any:
        plan = real(*args)
        rig.gw.deliver_signal(signum)  # pending before the check after the render
        return plan

    monkeypatch.setattr(send_module, "build_clear_plan", signalled)
    argv = ["--dry-run", *CLEAR] if dry_run else CLEAR
    assert rig.run(argv) == (128 + signum, "", "")
    assert rig.gw.connections == [] and not rig.state_dir.exists()


def test_clear_prints_and_flushes_the_result_before_it_writes_the_log(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    real = send_module.log_facts

    def log_spy(*args: Any) -> None:
        seen.append(rig.capsys.readouterr().out)  # what was written to stdout before the log
        real(*args)

    monkeypatch.setattr(send_module, "log_facts", log_spy)
    code, out, _ = rig.run(CLEAR)
    assert code == 0 and out == "" and len(seen) == 1
    assert json.loads(seen[0])["outcome"] == "sent"
    assert len(rig.records()) == 1


def test_log_false_writes_nothing(rig: Rig) -> None:
    assert rig.run(CLEAR, config=rig.cfg(BASE + "log: false\n"))[0] == 0
    assert not rig.state_dir.exists()


def test_a_state_directory_problem_is_one_warning_and_the_exit_code_is_kept(rig: Rig) -> None:
    rig.state_dir.parent.mkdir(parents=True)
    rig.state_dir.mkdir(mode=0o755)
    rig.state_dir.chmod(0o755)
    code, out, err = rig.run(CLEAR)
    assert code == 0 and json.loads(out)["outcome"] == "sent"
    assert err == STATE_WARNING + "\n"


def test_insecure_http_warns_once_and_is_in_warnings(rig: Rig) -> None:
    cfg = rig.cfg("base_url: http://ha.example\nservice: s\nallow_insecure_http: true\n")
    code, out, err = rig.run(["--quiet", *CLEAR], config=cfg)
    doc = json.loads(out)
    assert (
        code == 0 and doc["warnings"] == ["insecure_http"] and schema_errors("cli/clear", doc) == []
    )
    assert err.count("insecure_http") == 1


def test_the_token_never_leaks(rig: Rig) -> None:
    for script in (ConnectionScript(), ConnectionScript(status=401), ConnectionScript(status=500)):
        rig.gw.default_script = script
        code, out, err = rig.run(["--verbose", *CLEAR])
        assert TOKEN not in out + err
    assert TOKEN not in rig.log_path.read_text(encoding="utf-8")


def test_the_key_and_the_tag_are_not_in_stderr_or_the_log(rig: Rig) -> None:
    key = "very-secret-key-123"
    rig.gw.default_script = ConnectionScript(status=500)
    _, out, err = rig.run(["--verbose", "clear", f"--dedupe-key={key}"])
    assert key not in err and tag_from_dedupe_key(key) not in err
    assert key not in rig.log_path.read_text(encoding="utf-8")
    ok = rig.run(["--json", "clear", f"--dedupe-key={key}", "--dry-run"])[1]
    assert json.loads(ok)["dedupe_key"] == key  # echoed to stdout as for send


def test_validate_is_unchanged_by_clear(rig: Rig) -> None:
    code, out, _ = rig.run(["--json", "validate"])
    assert code == 0 and "checks" in json.loads(out)


def test_main_is_callable_with_clear_only_flags_in_a_fresh_process_state(rig: Rig) -> None:
    assert main(["--config", rig.cfg(), "clear", f"--dedupe-key={KEY}"], ENV, rig.gw) == 0
