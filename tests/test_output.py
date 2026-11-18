"""Output, exit-code table and error envelope (issue #7)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ha_notice import cli, output
from ha_notice.cli import main
from ha_notice.output import (
    ErrorResult,
    build_error,
    emit_disabled,
    emit_error,
    fail,
    flush_streams,
    safe_key,
    safe_pointer,
)
from tests.fake_gateway import FakeGateway
from tests.harness import Golden, schema_error_pairs, schema_errors

Result = tuple[int, str, str]

HINT = output.HOST_REJECTED_HINT
RESPONSE_CODES = ("auth_required", "host_rejected", "rate_limited", "upstream_error")


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str]) -> Any:
    def _run(argv: list[str], gateway: Any = None) -> Result:
        code = main(argv, {}, FakeGateway() if gateway is None else gateway)
        out = capsys.readouterr()
        return code, out.out, out.err

    return _run


def _valid(result: ErrorResult) -> dict[str, Any]:
    assert schema_errors("cli/error", result.envelope) == []
    text = output.dumps(result.envelope)
    assert "\n" not in text and "\r" not in text
    assert json.loads(text) == result.envelope
    return result.envelope["error"]


# --- the exit-code table -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "exit_code"),
    [
        ("usage", 2),
        ("config_invalid", 2),
        ("internal", 1),
        ("refused", 20),
        ("host_rejected", 12),
        ("auth_required", 12),
        ("credential_invalid", 12),
        ("rate_limited", 12),
        ("upstream_error", 12),
        ("network_error", 12),
        ("outcome_unknown", 12),
        ("wrong_host_response", 12),
        ("unavailable", 12),
    ],
)
def test_every_code_maps_to_its_exit_code(code: str, exit_code: int) -> None:
    assert output.EXIT_CODES[code] == exit_code


def test_exit_code_constants() -> None:
    assert (output.EXIT_OK, output.EXIT_INTERNAL, output.EXIT_USAGE) == (0, 1, 2)
    assert (output.EXIT_FAILED, output.EXIT_REFUSED, output.EXIT_DISABLED) == (12, 20, 22)
    assert not {10, 11, 13, 21} & set(output.EXIT_CODES.values())


# --- the exit-12 table, cell by cell, with and without a tag -------------------------------

# code, extra kwargs, (retryable, unknown_outcome) without a tag, the same with a tag
EXIT_12_CELLS: list[tuple[str, dict[str, Any], tuple[bool, bool], tuple[bool, bool]]] = [
    ("host_rejected", {"http_status": 400, "hint": HINT}, (False, False), (False, False)),
    ("auth_required", {"http_status": 401}, (False, False), (False, False)),
    ("credential_invalid", {"env": "HA_TOKEN"}, (False, False), (False, False)),
    ("rate_limited", {"http_status": 429, "retry_after_s": 4}, (True, False), (True, False)),
    ("unavailable", {}, (True, False), (True, False)),
    ("network_error", {"tls": False, "timeout": True}, (True, False), (True, False)),
    ("network_error", {"tls": True, "timeout": False}, (False, False), (False, False)),
    ("outcome_unknown", {}, (False, True), (True, True)),
    ("upstream_error", {"http_status": 502}, (False, True), (True, True)),
    ("wrong_host_response", {"http_status": 404}, (False, False), (False, False)),
    ("wrong_host_response", {"http_status": 200}, (False, True), (False, True)),
    ("wrong_host_response", {"http_status": 204}, (False, True), (False, True)),
    # an answer that is not HTTP after writing: no status, possibly delivered
    ("wrong_host_response", {}, (False, True), (False, True)),
]


@pytest.mark.parametrize(("code", "extra", "plain", "tagged"), EXIT_12_CELLS)
def test_exit_12_cells_with_and_without_a_dedupe_key(
    code: str, extra: dict[str, Any], plain: tuple[bool, bool], tagged: tuple[bool, bool]
) -> None:
    for tag_sent, want in ((False, plain), (True, tagged)):
        result = build_error(code, tag_sent=tag_sent, **extra)
        error = _valid(result)
        assert result.exit_code == 12
        assert error["code"] == code and error["reason"] is None
        assert (error["retryable"], error["unknown_outcome"]) == want


def test_every_exit_12_code_has_a_cell() -> None:
    covered = {c for c, *_ in EXIT_12_CELLS}
    assert covered == {c for c, n in output.EXIT_CODES.items() if n == 12}


def test_rate_limited_requires_and_only_it_carries_retry_after() -> None:
    assert _valid(build_error("rate_limited", http_status=429, retry_after_s=2.5))[
        "retry_after_s"
    ] == pytest.approx(2.5)
    with pytest.raises(ValueError):
        build_error("rate_limited", http_status=429)
    with pytest.raises(ValueError):
        build_error("upstream_error", http_status=500, retry_after_s=2)
    with pytest.raises(ValueError):
        build_error("rate_limited", http_status=429, retry_after_s=-1)
    with pytest.raises(ValueError):
        build_error("rate_limited", http_status=429, retry_after_s=float("nan"))


def test_tag_sent_is_meaningless_outside_the_two_possibly_delivered_codes() -> None:
    assert _valid(build_error("rate_limited", http_status=429, retry_after_s=2, tag_sent=True))[
        "retryable"
    ]
    assert not _valid(build_error("auth_required", http_status=401, tag_sent=True))["retryable"]


def test_unavailable_always_carries_phase_input() -> None:
    assert _valid(build_error("unavailable"))["details"] == {"phase": "input"}


# --- exit 2, 20 and 1 ----------------------------------------------------------------------


def test_exit_2_codes_have_null_flags() -> None:
    for result in (build_error("usage"), build_error("config_invalid", key="base_url")):
        error = _valid(result)
        assert result.exit_code == 2
        assert error["retryable"] is None and error["unknown_outcome"] is None


@pytest.mark.parametrize(
    ("reason", "details"),
    [
        ("invalid_payload", {"pointer": ""}),
        ("invalid_payload", {"pointer": "/message"}),
        ("empty_message", {}),
        ("command_keyword", {}),
        ("link_invalid", {}),
        ("link_invalid", {"pointer": "/link"}),
        ("link_scheme", {}),
    ],
)
def test_exit_20_is_code_refused_with_a_reason(reason: str, details: dict[str, Any]) -> None:
    result = build_error("refused", reason=reason, **details)
    error = _valid(result)
    assert result.exit_code == 20
    assert error["code"] == "refused" and error["reason"] == reason
    assert error["retryable"] is None and error["unknown_outcome"] is None


def test_refused_needs_a_known_reason_and_other_codes_forbid_one() -> None:
    for bad in (None, "", "nope", "refused"):
        with pytest.raises(ValueError):
            build_error("refused", reason=bad)
    with pytest.raises(ValueError):
        build_error("usage", reason="empty_message")
    with pytest.raises(ValueError):
        build_error("invalid_payload")  # a reason, not a code
    with pytest.raises(ValueError):
        build_error("refused", reason="invalid_payload")  # pointer is required


def test_internal_flags() -> None:
    before = build_error("internal")
    after = build_error("internal", after_writing=True)
    assert before.exit_code == after.exit_code == 1
    e_before, e_after = _valid(before), _valid(after)
    assert (e_before["retryable"], e_before["unknown_outcome"]) == (False, False)
    assert (e_after["retryable"], e_after["unknown_outcome"]) == (False, True)


def test_after_writing_is_only_for_internal() -> None:
    with pytest.raises(ValueError):
        build_error("usage", after_writing=True)


# --- details -------------------------------------------------------------------------------


def test_details_by_code() -> None:
    assert _valid(build_error("config_invalid", key="base_url"))["details"] == {"key": "base_url"}
    assert _valid(build_error("credential_invalid", env="HA_X"))["details"] == {"env": "HA_X"}
    got = _valid(build_error("host_rejected", http_status=400, hint=HINT))
    assert got["details"] == {"http_status": 400, "hint": HINT}
    got = _valid(build_error("network_error", tls=True, timeout=False))
    assert got["details"] == {"tls": True, "timeout": False}
    assert _valid(build_error("usage"))["details"] is None
    assert _valid(build_error("outcome_unknown"))["details"] is None


def test_details_key_order_follows_the_interface() -> None:
    got = _valid(build_error("host_rejected", http_status=400, hint=HINT))["details"]
    assert list(got) == ["http_status", "hint"]
    got = _valid(build_error("network_error", timeout=True, tls=False))["details"]
    assert list(got) == ["tls", "timeout"]


@pytest.mark.parametrize(
    ("code", "kwargs"),
    [
        ("config_invalid", {}),
        ("credential_invalid", {}),
        ("auth_required", {}),
        ("network_error", {"tls": True}),
        ("usage", {"key": "x"}),
        ("outcome_unknown", {"http_status": 200}),
        ("auth_required", {"http_status": 99}),
        ("auth_required", {"http_status": 600}),
        ("auth_required", {"http_status": True}),
        ("auth_required", {"http_status": 401, "hint": "x"}),  # hint only on host_rejected
        ("network_error", {"tls": "yes", "timeout": False}),
        ("config_invalid", {"key": 5}),
        ("refused", {"reason": "link_invalid", "pointer": "/x"}),
        ("refused", {"reason": "invalid_payload", "pointer": "message"}),
        ("refused", {"reason": "invalid_payload", "pointer": "/a b"}),
        ("refused", {"reason": "invalid_payload", "pointer": "/message\n"}),
        ("refused", {"reason": "empty_message", "pointer": ""}),
    ],
)
def test_details_that_would_not_match_the_schema_are_programming_errors(
    code: str, kwargs: dict[str, Any]
) -> None:
    with pytest.raises(ValueError):
        build_error(code, **kwargs)


def test_unknown_code_and_non_string_code_raise() -> None:
    for code in ("nope", "", "disabled", None, 12):
        with pytest.raises(ValueError):
            build_error(code)  # type: ignore[arg-type]


HOSTILE = [
    "",
    "a" * 5000,
    "a b",
    "a\nb",
    "ключ",
    "\ud800",
    "a/b",
    "~0",
    "x‮y",
    "..",
    "a" * 65,
    "$(id)",
    '"}{',
]


@pytest.mark.parametrize("field", HOSTILE)
def test_a_hostile_field_name_as_a_pointer_is_question_mark(field: str) -> None:
    assert safe_pointer(field) == "/?"
    error = _valid(build_error("refused", reason="invalid_payload", pointer=safe_pointer(field)))
    assert error["details"] == {"pointer": "/?"}


def test_safe_pointer_keeps_ordinary_names_and_the_root() -> None:
    assert safe_pointer(None) == ""
    assert safe_pointer("message") == "/message"
    assert safe_pointer("a_b-9") == "/a_b-9"
    assert safe_pointer("a" * 64) == "/" + "a" * 64
    assert safe_pointer("message\n") == "/?"  # a trailing LF is not a match


def test_a_config_key_of_5000_characters_is_question_mark() -> None:
    assert safe_key("k" * 5000) == "?"
    error = _valid(build_error("config_invalid", key=safe_key("k" * 5000)))
    assert error["details"] == {"key": "?"}


@pytest.mark.parametrize("name", ["", "a-b", "a b", "a.b", "é", "k" * 65, "a\n", "\ud800", "x\x00"])
def test_safe_key_refuses_anything_but_a_plain_name(name: str) -> None:
    assert safe_key(name) == "?"


def test_safe_key_keeps_a_plain_name() -> None:
    assert safe_key("base_url") == "base_url"
    assert safe_key("k" * 64) == "k" * 64


def test_a_file_path_key_is_kept_but_bounded_and_the_envelope_stays_valid() -> None:
    path = "/home/u/.config/ha-notice/config.yaml"
    assert _valid(build_error("config_invalid", key=path))["details"] == {"key": path}
    over = _valid(build_error("config_invalid", key="/" + "p" * 5000))
    assert over["details"] == {"key": "?"}
    nasty = _valid(build_error("config_invalid", key='/a\nb"\\\ud800‮'))
    assert nasty["details"]["key"] == "?"


@pytest.mark.parametrize("key", ["a\u2028b", "a\u2029b", "a\x85b", "a\x00b", "a\nb", "a\x1bb"])
def test_a_key_with_a_non_printable_character_is_question_mark(
    key: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _valid(build_error("config_invalid", key=key))["details"] == {"key": "?"}
    fail(True, "config_invalid", key=key)
    assert len(capsys.readouterr().out.splitlines()) == 1


def test_a_nasty_key_prints_as_one_line_of_valid_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fail(True, "config_invalid", key="/a\nb\r \ud800")
    out = capsys.readouterr()
    assert out.out.count("\n") == 1 and out.out.endswith("\n")
    assert schema_errors("cli/error", json.loads(out.out)) == []
    assert out.err == "config_invalid: invalid configuration\n"


# --- messages are fixed --------------------------------------------------------------------


def test_every_code_and_reason_has_a_fixed_one_line_message() -> None:
    texts = list(output.MESSAGES.values()) + list(output.REASON_MESSAGES.values())
    assert len(texts) == len(set(texts))  # distinct, so a caller can tell them apart
    for text in texts:
        assert text and text.isascii() and text.isprintable() and len(text) <= 120


def test_messages_cover_every_code_and_reason() -> None:
    from tests.harness import load_schema

    defs = load_schema("defs")["$defs"]
    assert set(output.MESSAGES) == set(defs["error_code"]["enum"]) - {"refused"}
    assert set(output.REASON_MESSAGES) == set(defs["refusal_reason"]["enum"])
    assert set(output.EXIT_CODES) == set(defs["error_code"]["enum"])


@pytest.mark.parametrize(
    "bad", ["a\nb", "a\rb", "", "x" * 2049, "a\x00b", "a\x1b[0m", "a\u2028b", "a\x85b"]
)
def test_a_message_override_must_be_one_clean_line(bad: str) -> None:
    with pytest.raises(ValueError):
        build_error("usage", message=bad)


def test_the_envelope_never_contains_what_the_caller_cannot_pass() -> None:
    secret = "SECRET-TOKEN-123"
    for code in output.EXIT_CODES:
        if code == "refused":
            continue
        kwargs: dict[str, Any] = {}
        if code == "config_invalid":
            kwargs["key"] = safe_key(secret + "é")
        if code == "credential_invalid":
            kwargs["env"] = "HA_TOKEN"
        if code in RESPONSE_CODES or code == "wrong_host_response":
            kwargs["http_status"] = 500
        if code == "host_rejected":
            kwargs.update(http_status=400, hint=HINT)
        if code == "rate_limited":
            kwargs["retry_after_s"] = 2
        if code == "network_error":
            kwargs.update(tls=False, timeout=False)
        assert secret not in output.dumps(build_error(code, **kwargs).envelope)


# --- the human lines -----------------------------------------------------------------------


def test_emit_error_without_json_is_one_stderr_line_and_empty_stdout(run: Any) -> None:
    code, out, err = run(["bogus"])
    assert (code, out) == (2, "")
    assert err == "usage: invalid command line; see ha-notice --help\n"


def test_exit_20_line_names_the_reason(capsys: pytest.CaptureFixture[str]) -> None:
    assert fail(False, "refused", reason="empty_message") == 20
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == f"refused (empty_message): {output.REASON_MESSAGES['empty_message']}\n"


def test_exit_20_with_json_prints_the_envelope_and_the_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert fail(True, "refused", reason="link_scheme") == 20
    out = capsys.readouterr()
    assert json.loads(out.out)["error"]["reason"] == "link_scheme"
    assert out.err.startswith("refused (link_scheme): ") and out.err.count("\n") == 1


def test_fail_returns_the_exit_code_of_the_code() -> None:
    assert fail(False, "credential_invalid", env="HA_X") == 12
    assert fail(False, "config_invalid", key="home") == 2
    assert fail(False, "internal") == 1


def test_emit_error_takes_only_a_built_result(capsys: pytest.CaptureFixture[str]) -> None:
    emit_error(True, build_error("outcome_unknown"))
    lines = capsys.readouterr().out.splitlines()
    assert [json.loads(x)["error"]["code"] for x in lines] == ["outcome_unknown"]
    with pytest.raises(TypeError):
        emit_error(True, {"error": {"code": "x", "message": "m"}})  # type: ignore[arg-type]
    assert not hasattr(output, "error_envelope") and not hasattr(cli, "error_envelope")


def test_disabled_with_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert emit_disabled(True) == 22
    out = capsys.readouterr()
    assert out.out == '{"outcome":"disabled"}\n' and out.err == ""
    assert schema_errors("cli/send", json.loads(out.out)) == []


def test_disabled_without_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert emit_disabled(False) == 22
    out = capsys.readouterr()
    assert out.out == "" and out.err == "disabled in config\n"


# --- ordering and flushing -----------------------------------------------------------------


class _Recorder:
    def __init__(self, name: str, log: list[str]) -> None:
        self.name, self.log = name, log
        self.buffer = self

    def write(self, data: bytes) -> int:
        self.log.append(f"{self.name}.write")
        return len(data)

    def flush(self) -> None:
        self.log.append(f"{self.name}.flush")


def test_stdout_is_written_and_flushed_before_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    log: list[str] = []
    monkeypatch.setattr(sys, "stdout", _Recorder("out", log))
    monkeypatch.setattr(sys, "stderr", _Recorder("err", log))
    fail(True, "usage", message="no command given")
    assert log.index("out.flush") < log.index("err.write")
    assert [e for e in log if e.endswith(".write")] == ["out.write", "err.write"]


def test_flush_streams_flushes_stdout_then_stderr_once_each(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log: list[str] = []
    monkeypatch.setattr(sys, "stdout", _Recorder("out", log))
    monkeypatch.setattr(sys, "stderr", _Recorder("err", log))
    flush_streams()
    assert log == ["out.flush", "err.flush"]


def test_flush_streams_tolerates_failures_and_missing_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Bad:
        def flush(self) -> None:
            raise BrokenPipeError

    monkeypatch.setattr(sys, "stdout", Bad())
    monkeypatch.setattr(sys, "stderr", None)
    flush_streams()


def test_a_failing_stdout_does_not_stop_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class Bad:
        def write(self, text: str) -> int:
            raise BrokenPipeError

        def flush(self) -> None:
            raise BrokenPipeError

    monkeypatch.setattr(sys, "stdout", Bad())
    assert fail(True, "internal") == 1
    assert capsys.readouterr().err == "internal: internal error\n"


# --- main: unexpected exceptions are exit 1 ------------------------------------------------

SECRET = "SECRET-IN-EXCEPTION-é"


class _Boom(Exception):
    pass


def _boom(*_: Any, **__: Any) -> Any:
    raise _Boom(SECRET)


def _assert_internal(code: int, out: str, err: str, *, unknown: bool, json_mode: bool) -> None:
    assert code == 1
    assert err == "internal: internal error\n"
    assert SECRET not in out + err and "_Boom" not in out + err and "Traceback" not in out + err
    if json_mode:
        assert out.count("\n") == 1
        doc = json.loads(out)
        assert schema_errors("cli/error", doc) == []
        error = doc["error"]
        assert error["code"] == "internal" and error["retryable"] is False
        assert error["unknown_outcome"] is unknown
        assert error["details"] is None and error["reason"] is None
    else:
        assert out == ""


@pytest.mark.parametrize("json_mode", [True, False])
def test_a_handler_exception_is_exit_1_internal(
    run: Any, monkeypatch: pytest.MonkeyPatch, json_mode: bool
) -> None:
    monkeypatch.setitem(cli.HANDLERS, "send", _boom)
    argv = ["send", "--message=a"] + (["--json"] if json_mode else [])
    _assert_internal(*run(argv), unknown=False, json_mode=json_mode)


@pytest.mark.parametrize("exc", [RecursionError, MemoryError, KeyError, UnicodeError, OSError])
def test_any_exception_class_is_caught(
    run: Any, monkeypatch: pytest.MonkeyPatch, exc: type[Exception]
) -> None:
    def handler(inv: cli.Invocation) -> int:
        raise exc(SECRET)

    monkeypatch.setitem(cli.HANDLERS, "validate", handler)
    _assert_internal(*run(["--json", "validate"]), unknown=False, json_mode=True)


def test_unknown_outcome_follows_the_progress_of_the_handler(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(inv: cli.Invocation) -> int:
        inv.progress.writing = True
        raise _Boom(SECRET)

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    _assert_internal(*run(["--json", "send", "--message=a"]), unknown=True, json_mode=True)


def test_progress_starts_false_on_every_invocation(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[cli.Invocation] = []

    def handler(inv: cli.Invocation) -> int:
        seen.append(inv)
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    for _ in range(2):
        assert main(["send", "--message=a"], {}, FakeGateway()) == 0  # type: ignore[arg-type]
    assert [s.progress.writing for s in seen] == [False, False]
    assert seen[0].progress is not seen[1].progress


def test_an_exception_while_parsing_is_exit_1_with_the_envelope(run: Any) -> None:
    gateway = FakeGateway()
    gateway.isatty = _boom  # type: ignore[method-assign]
    argv = ["--json", "validate"]
    _assert_internal(*run(argv, gateway), unknown=False, json_mode=True)


def test_an_exception_in_the_parse_without_json_prints_the_line_only(run: Any) -> None:
    gateway = FakeGateway()
    gateway.isatty = _boom  # type: ignore[method-assign]
    _assert_internal(*run(["validate"], gateway), unknown=False, json_mode=False)


def test_a_failure_while_reporting_still_exits_1(run: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(cli.HANDLERS, "send", _boom)
    monkeypatch.setattr(cli, "fail", _boom)
    code, out, err = run(["send", "--message=a"])
    assert code == 1 and SECRET not in out + err


def test_a_handler_that_returns_a_bad_exit_code_is_internal(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    for value in (None, "0", True, -1, 256, 3.0, 3, 130, 143, 255, 10, 21):
        monkeypatch.setitem(cli.HANDLERS, "send", lambda inv, v=value: v)
        code, out, err = run(["send", "--message=a"])
        assert code == 1 and err == "internal: internal error\n", value


@pytest.mark.parametrize("value", [0, 1, 2, 12, 20, 22])
def test_a_handler_may_return_the_documented_codes_only_those(
    run: Any, monkeypatch: pytest.MonkeyPatch, value: int
) -> None:
    monkeypatch.setitem(cli.HANDLERS, "send", lambda inv: value)
    assert run(["send", "--message=a"])[0] == value


def test_a_handler_that_emits_then_raises_gives_one_envelope(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(inv: cli.Invocation) -> int:
        fail(inv.json, "refused", reason="empty_message")
        raise _Boom(SECRET)

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    code, out, err = run(["--json", "send", "--message=a"])
    assert code == 20 and len(out.splitlines()) == 1
    assert json.loads(out)["error"]["code"] == "refused"
    assert err.count("\n") == 1 and SECRET not in out + err


def test_a_handler_that_emits_then_returns_garbage_gives_one_envelope(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def handler(inv: cli.Invocation) -> Any:
        fail(inv.json, "credential_invalid", env="HA_X")
        return 99

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    code, out, _ = run(["--json", "send", "--message=a"])
    assert code == 12 and len(out.splitlines()) == 1


def test_the_emitted_state_does_not_leak_into_the_next_invocation(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def first(inv: cli.Invocation) -> int:
        return fail(inv.json, "refused", reason="empty_message")

    monkeypatch.setitem(cli.HANDLERS, "send", first)
    assert run(["--json", "send", "--message=a"])[0] == 20
    monkeypatch.setitem(cli.HANDLERS, "send", _boom)
    code, out, err = run(["--json", "send", "--message=a"])
    _assert_internal(code, out, err, unknown=False, json_mode=True)


def test_run_resets_the_emitted_state_itself(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output.reset_emitted()
    fail(True, "refused", reason="empty_message")  # leaks state for a direct _run call
    capsys.readouterr()
    monkeypatch.setitem(cli.HANDLERS, "send", _boom)
    code = cli._run(["--json", "send", "--message=a"], {}, FakeGateway())  # type: ignore[arg-type]
    assert code == 1
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "internal"


def test_the_envelope_is_recorded_only_after_the_stdout_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output.reset_emitted()
    seen: list[int | None] = []
    monkeypatch.setattr(
        output, "write_text", lambda stream, text: seen.append(output.emitted_exit())
    )
    fail(True, "refused", reason="empty_message")
    assert seen[0] is None  # the stdout write happens before the state is recorded
    assert output.emitted_exit() == 20
    output.reset_emitted()


def test_help_and_version_are_not_internal_errors(run: Any) -> None:
    assert run(["--help"])[0] == 0
    assert run(["--version"])[0] == 0


def test_main_flushes_both_streams_at_the_end(monkeypatch: pytest.MonkeyPatch) -> None:
    log: list[str] = []
    monkeypatch.setattr(sys, "stdout", _Recorder("out", log))
    monkeypatch.setattr(sys, "stderr", _Recorder("err", log))
    assert main(["--version"], {}, FakeGateway()) == 0  # type: ignore[arg-type]
    assert log[-2:] == ["out.flush", "err.flush"]


# --- goldens (created by hand) -------------------------------------------------------------


def _golden_text(result: ErrorResult) -> str:
    return output.dumps(result.envelope) + "\n"


@pytest.mark.parametrize(
    ("name", "result"),
    [
        (
            "error-refused-invalid-payload.json",
            ("refused", {"reason": "invalid_payload", "pointer": "/?"}),
        ),
        ("error-rate-limited.json", ("rate_limited", {"http_status": 429, "retry_after_s": 4})),
        ("error-outcome-unknown-tagged.json", ("outcome_unknown", {"tag_sent": True})),
        ("error-config-invalid-key.json", ("config_invalid", {"key": "?"})),
        ("error-internal-after-writing.json", ("internal", {"after_writing": True})),
    ],
)
def test_error_envelope_goldens(
    golden: Golden, name: str, result: tuple[str, dict[str, Any]]
) -> None:
    code, kwargs = result
    golden.check("output", name, _golden_text(build_error(code, **kwargs)), schema="cli/error")


def test_disabled_golden(golden: Golden, capsys: pytest.CaptureFixture[str]) -> None:
    emit_disabled(True)
    golden.check("output", "disabled.json", capsys.readouterr().out, schema="cli/send")


# --- real processes -------------------------------------------------------------------------


def _env(tmp_path: Path) -> dict[str, str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "cfg"),
        "XDG_STATE_HOME": str(home / "state"),
        "LC_ALL": "C",
    }


def _proc(tmp_path: Path, args: list[str], **streams: Any) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "ha_notice", *args],
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
        env=_env(tmp_path),
        **{"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, **streams},
    )


def test_real_process_exit_1_envelope_is_ascii_safe_under_the_c_locale(tmp_path: Path) -> None:
    # The validate stub exits 1 until #28; this checks the whole exit-1 path of a real process.
    proc = _proc(tmp_path, ["--json", "validate"])
    assert proc.returncode == 1
    assert schema_errors("cli/error", json.loads(proc.stdout)) == []
    assert proc.stderr == b"internal: command not implemented\n"


def test_real_process_exit_1_to_dev_full_keeps_the_exit_code(tmp_path: Path) -> None:
    with open("/dev/full", "wb") as full:
        proc = _proc(tmp_path, ["--json", "validate"], stdout=full, stderr=full)
    assert proc.returncode == 1


def test_real_process_exit_1_with_a_closed_pipe_keeps_the_exit_code(tmp_path: Path) -> None:
    read_end, write_end = os.pipe()
    os.close(read_end)
    try:
        proc = _proc(tmp_path, ["--json", "validate"], stdout=write_end, stderr=write_end)
    finally:
        os.close(write_end)
    assert proc.returncode == 1


def test_real_process_exit_1_with_closed_standard_streams(tmp_path: Path) -> None:
    cmd = f"exec {sys.executable} -m ha_notice --json validate 1>&- 2>&-"
    proc = subprocess.run(
        ["/bin/sh", "-c", cmd],
        stdin=subprocess.DEVNULL,
        timeout=60,
        check=False,
        env=_env(tmp_path),
    )
    assert proc.returncode == 1


# --- review round 1 ------------------------------------------------------------------------


def test_unavailable_rejects_any_phase_but_input() -> None:
    assert _valid(build_error("unavailable", phase="input"))["details"] == {"phase": "input"}
    for bad in ("x", "", None, "idle"):
        with pytest.raises(ValueError):
            build_error("unavailable", phase=bad)
    with pytest.raises(ValueError):
        build_error("network_error", phase="input", tls=False, timeout=False)


class _Status(int):
    pass


class _Enum(__import__("enum").IntEnum):
    UNAUTH = 401


def test_http_status_accepts_int_subclasses_but_not_bool() -> None:
    for value in (_Status(401), _Enum.UNAUTH):
        error = _valid(build_error("auth_required", http_status=value))
        assert error["details"] == {"http_status": 401}
        assert type(error["details"]["http_status"]) is int
        assert output.dumps({"v": error["details"]["http_status"]}) == '{"v":401}'
    with pytest.raises(ValueError):
        build_error("auth_required", http_status=True)


def test_a_huge_retry_after_is_a_value_error_not_an_overflow() -> None:
    with pytest.raises(ValueError):
        build_error("rate_limited", http_status=429, retry_after_s=10**400)


@pytest.mark.parametrize("bad", ["a perfectly clean line", "usage", "internal error"])
def test_a_message_override_must_be_from_the_closed_set(bad: str) -> None:
    with pytest.raises(ValueError):
        build_error("usage", message=bad)


def test_every_usage_message_in_cli_is_an_allowed_override() -> None:
    import re

    source = Path(cli.__file__).read_text(encoding="utf-8")
    literals = set(re.findall(r'UsageError\("([^"]+)"\)', source))
    assert literals and literals <= output.OVERRIDE_MESSAGES
    for text in literals | {"command not implemented"}:
        assert build_error("usage", message=text).envelope["error"]["message"] == text


def test_host_rejected_needs_the_fixed_hint_and_status_400() -> None:
    assert _valid(build_error("host_rejected", http_status=400, hint=HINT))
    cases: list[dict[str, Any]] = [
        {"http_status": 400},
        {"http_status": 400, "hint": "check the service"},
        {"http_status": 401, "hint": HINT},
    ]
    for kwargs in cases:
        with pytest.raises(ValueError):
            build_error("host_rejected", **kwargs)


def test_every_accepted_cell_validates_against_the_error_schema() -> None:
    import itertools

    base: dict[str, list[dict[str, Any]]] = {
        "usage": [{}],
        "config_invalid": [{"key": "base_url"}, {"key": "?"}, {"key": "/p/c.yaml"}],
        "internal": [{}, {"after_writing": True}],
        "refused": [{"reason": "invalid_payload", "pointer": p} for p in ("", "/message", "/?")]
        + [{"reason": "link_invalid", "pointer": "/link"}]
        + [{"reason": r} for r in ("empty_message", "command_keyword", "link_scheme")],
        "host_rejected": [{"http_status": 400, "hint": HINT}],
        "auth_required": [{"http_status": s} for s in (401, 403)],
        "credential_invalid": [{"env": "HA_TOKEN"}],
        "rate_limited": [{"http_status": 429, "retry_after_s": r} for r in (0, 2, 4.5)],
        "upstream_error": [{"http_status": s} for s in (500, 502, 599)],
        "network_error": [{"tls": t, "timeout": o} for t in (True, False) for o in (True, False)],
        "outcome_unknown": [{}],
        "wrong_host_response": [{}] + [{"http_status": s} for s in (100, 200, 204, 302, 404, 599)],
        "unavailable": [{}, {"phase": "input"}],
    }
    assert set(base) == set(output.EXIT_CODES)
    accepted = 0
    for code, cells in base.items():
        for details, tag in itertools.product(cells, (False, True)):
            result = build_error(code, tag_sent=tag, **details)
            assert schema_errors("cli/error", result.envelope) == [], (code, details)
            accepted += 1
    assert accepted > 40


def test_wrong_host_response_without_a_status_has_null_details_and_is_unknown() -> None:
    error = _valid(build_error("wrong_host_response"))
    assert (error["details"], error["retryable"], error["unknown_outcome"]) == (None, False, True)


def test_the_schema_requires_a_status_for_wrong_host_response_unless_not_http() -> None:
    def envelope(unknown: bool, details: Any) -> dict[str, Any]:
        error = build_error("wrong_host_response", http_status=404).envelope
        error["error"].update(unknown_outcome=unknown, details=details)
        return error

    def pairs(instance: dict[str, Any]) -> set[Any]:
        return schema_error_pairs("cli/error", instance)

    assert schema_errors("cli/error", envelope(True, None)) == []
    assert schema_errors("cli/error", envelope(True, {"http_status": 200})) == []
    assert schema_errors("cli/error", envelope(False, {"http_status": 404})) == []
    path = ("error", "details")
    assert (path, "type") in pairs(envelope(False, None))
    assert (path, "required") in pairs(envelope(False, {}))
    # an unknown outcome allows null details or a status, nothing else
    assert (path, "required") in pairs(envelope(True, {}))
    assert (path, "required") in pairs(envelope(True, {"tls": False, "timeout": False}))
    missing = envelope(True, None)
    del missing["error"]["details"]
    assert (("error",), "required") in pairs(missing)
    missing_false = envelope(False, None)
    del missing_false["error"]["details"]
    assert (("error",), "required") in pairs(missing_false)
    # the other response codes keep requiring the status
    bad = build_error("auth_required", http_status=401).envelope
    bad["error"]["details"] = None
    assert schema_errors("cli/error", bad) != []
