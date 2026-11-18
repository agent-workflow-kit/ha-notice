"""CLI parser, global flags, output modes and usage errors (issue #6)."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

from ha_notice import cli
from ha_notice.cli import main
from tests.fake_gateway import FakeGateway
from tests.harness import Golden, load_schema, schema_errors

ROOT = Path(__file__).resolve().parent.parent
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]

Result = tuple[int, str, str]


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str]) -> Any:
    def _run(argv: list[str], gateway: FakeGateway | None = None) -> Result:
        code = main(argv, {}, FakeGateway() if gateway is None else gateway)  # type: ignore[arg-type]
        out = capsys.readouterr()
        return code, out.out, out.err

    return _run


def _spy_invocations(monkeypatch: pytest.MonkeyPatch) -> list[cli.Invocation]:
    seen: list[cli.Invocation] = []

    def handler(inv: cli.Invocation) -> int:
        seen.append(inv)
        return 0

    monkeypatch.setitem(cli.HANDLERS, "send", handler)
    monkeypatch.setitem(cli.HANDLERS, "validate", handler)
    return seen


# --- the parser table ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["--vers"],
        ["--ver"],
        ["--conf", "x", "send", "--message=a"],
        ["send", "--conf", "x", "--message=a"],
        ["send", "--stdin", "--message=a"],
        ["send", "--std"],
        ["send", "--mess=a"],
        ["send", "--dry", "--message=a"],
        ["--dry", "send", "--message=a"],
        ["--js", "send", "--message=a"],
        ["se", "--message=a"],
        ["val"],
    ],
)
def test_abbreviations_are_usage_errors(
    run: Any, monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    seen = _spy_invocations(monkeypatch)
    code, out, err = run(argv)
    assert code == 2 and out == "" and err.startswith("usage: ") and not seen


def test_equals_form_is_accepted_for_a_global_flag(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["--config=x", "send", "--message=a"])[0] == 0
    assert seen[0].config == "x"


def test_dedupe_key_equals_form_accepts_a_leading_dash(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["send", "--message=a", "--dedupe-key=-abc"])[0] == 0
    assert seen[0].send is not None and seen[0].send.dedupe_key == "-abc"


@pytest.mark.parametrize("value", ["-abc", "-1", "-1.5", "--x", "-a b", "--"])
def test_dedupe_key_space_form_with_a_leading_dash_exits_2(
    run: Any, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    seen = _spy_invocations(monkeypatch)
    code, _, err = run(["send", "--message=a", "--dedupe-key", value])
    assert code == 2 and err.startswith("usage: ") and not seen


def test_file_dash_is_stdin_in_the_space_form(run: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["send", "--file", "-"], FakeGateway())[0] == 0
    assert seen[0].send is not None and seen[0].send.file == "-"


def test_global_flag_before_the_subcommand_is_honoured(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["--config", "x", "send", "--message=a"])[0] == 0
    assert seen[0].config == "x"


def test_global_flag_after_the_subcommand_is_honoured(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["send", "--config", "y", "--message=a"])[0] == 0
    assert seen[0].config == "y"


def test_every_global_flag_works_on_both_sides(run: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _spy_invocations(monkeypatch)
    for argv in (
        ["--json", "--dry-run", "--verbose", "--actor=auto:x", "send", "--message=a"],
        ["send", "--message=a", "--json", "--dry-run", "--verbose", "--actor=auto:x"],
    ):
        assert run(argv)[0] == 0
    for inv in seen:
        assert (inv.json, inv.dry_run, inv.verbose, inv.quiet) == (True, True, True, False)
        assert inv.actor == "auto:x" and inv.actor_source == "flag"


def test_quiet_is_recorded(run: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["validate", "--quiet"])[0] == 0
    assert seen[0].quiet and not seen[0].verbose


def test_validate_accepts_its_flags(run: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["validate", "--probe", "--test-message"])[0] == 0
    assert seen[0].validate is not None
    assert (seen[0].validate.probe, seen[0].validate.test_message) == (True, True)


@pytest.mark.parametrize(
    "argv",
    [
        ["--config", "a", "send", "--config", "b", "--message=a"],
        ["--config=a", "--config=b", "send", "--message=a"],
        ["send", "--message=a", "--config=a", "--config=b"],
        ["send", "--message=a", "--message=b"],
        ["send", "--message=a", "--dedupe-key=a", "--dedupe-key=b"],
        ["--actor=auto:a", "send", "--message=a", "--actor=auto:b"],
        ["--verbose", "--quiet", "send", "--message=a"],
        ["send", "--message=a", "--verbose", "--quiet"],
        ["send", "--stdin-json=x"],
        ["--config="],
        ["--actor="],
        ["send", "--message=a", "--actor="],
        ["send", "--message=a", "--dedupe-key="],
        ["--"],
        ["--", "send", "--message=a"],
        ["send", "-hx"],
        ["send", "-x"],
        ["-hx"],
        ["send", "--message=a", "-v"],
        ["send", "--", "--message=a"],
        ["send", "--message=a", "--"],
        ["send", "extra", "--message=a"],
        ["bogus"],
        ["send", "--bogus"],
        ["validate", "--message=a"],
        ["--message=a", "send"],
        ["--probe", "validate"],
        ["validate", "--stdin-json"],
        ["validate", "--dedupe-key=a"],
        ["send", "--message"],
        ["send", "--level"],
        ["--config"],
        ["--actor"],
        ["--ACTOR=auto:x", "send", "--message=a"],
        ["SEND"],
        [""],
        ["send", ""],
    ],
)
def test_other_malformed_command_lines_are_usage_errors(
    run: Any, monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    seen = _spy_invocations(monkeypatch)
    code, out, err = run(argv)
    assert code == 2 and out == "" and err.startswith("usage: ") and not seen


def test_repeated_boolean_flags_are_harmless(run: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["--json", "send", "--json", "--message=a", "--json"])[0] == 0
    assert seen[0].json


def test_decision_id_is_repeatable_and_ignored(run: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["send", "--message=a", "--decision-id=1", "--decision-id", "2"])[0] == 0
    assert seen[0].send is not None and seen[0].send.decision_ids == ["1", "2"]


def test_send_flag_values_reach_the_handler(run: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _spy_invocations(monkeypatch)
    argv = ["send", "--title=t", "--message", "m", "--level=warn", "--link=https://a.example/"]
    assert run(argv)[0] == 0
    s = seen[0].send
    assert s is not None
    assert (s.title, s.message, s.level, s.link) == ("t", "m", "warn", "https://a.example/")
    assert (s.stdin_json, s.file, s.dedupe_key) == (False, None, None)


def test_a_level_outside_the_four_is_not_a_usage_error(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An invalid level is exit 20 invalid_payload at step 3 (#11), like the same JSON field.
    seen = _spy_invocations(monkeypatch)
    assert run(["send", "--message=a", "--level=loud"])[0] == 0
    assert seen[0].send is not None and seen[0].send.level == "loud"


# --- flag combinations (step 1) -----------------------------------------------------------


def test_stdin_json_with_file_dash_is_one_source_and_accepted(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _spy_invocations(monkeypatch)
    run(["send", "--stdin-json", "--file=-"], FakeGateway())
    assert seen and seen[0].send is not None and seen[0].send.file == "-"


@pytest.mark.parametrize(
    ("argv", "config", "file"),
    [
        (["--config=", "send", "--message=a"], "", None),
        (["send", "--message=a", "--config", ""], "", None),
        (["send", "--file="], None, ""),
        (["send", "--file", ""], None, ""),
    ],
)
def test_empty_config_and_file_pass_through_to_the_handler(
    run: Any,
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    config: str | None,
    file: str | None,
) -> None:
    seen = _spy_invocations(monkeypatch)
    run(argv, FakeGateway())
    assert seen
    assert seen[0].config == config
    assert seen[0].send is not None
    assert seen[0].send.file == file


def test_dash_h_alone_is_still_help(run: Any) -> None:
    code, out, _ = run(["send", "-h"])
    assert code == 0 and out.startswith("usage: ")


def test_a_stream_that_is_none_is_skipped() -> None:
    cli.write_text(None, "x")  # type: ignore[arg-type]


def test_a_stream_whose_buffer_raises_is_tolerated() -> None:
    class Odd:
        @property
        def buffer(self) -> Any:
            raise RuntimeError("boom")

        def write(self, text: str) -> int:
            raise OSError

        def flush(self) -> None:
            raise OSError

    cli.write_text(Odd(), "x")  # type: ignore[arg-type]


def _tty() -> FakeGateway:
    return FakeGateway(tty_fds={0})


@pytest.mark.parametrize(
    "argv",
    [
        ["send", "--stdin-json", "--message=a"],
        ["send", "--stdin-json", "--title=a"],
        ["send", "--file=x.json", "--level=warn"],
        ["send", "--file=x.json", "--link=https://a.example/"],
        ["send", "--file=x.json", "--message=a"],
        ["send", "--stdin-json", "--file=x.json"],
        ["send", "--title=a"],
        ["send", "--level=info"],
        ["send", "--link=https://a.example/"],
    ],
)
def test_send_flag_combination_errors_exit_2(
    run: Any, monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    seen = _spy_invocations(monkeypatch)
    code, out, err = run(argv, FakeGateway())
    assert code == 2 and out == "" and err.startswith("usage: ") and not seen


@pytest.mark.parametrize(
    "argv",
    [["send", "--stdin-json"], ["send", "--file=-"], ["send"]],
)
def test_stdin_terminal_without_a_usable_source_exits_2(
    run: Any, monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    seen = _spy_invocations(monkeypatch)
    code, _, err = run(argv, _tty())
    assert code == 2 and err.startswith("usage: ") and not seen


@pytest.mark.parametrize(
    "argv",
    [
        ["send", "--message=a"],
        ["send", "--file=x.json"],
        ["send", "--message="],
        ["send", "--stdin-json"],  # not a terminal here
        ["send"],  # stdin is not a terminal: JSON on stdin is the default
    ],
)
def test_valid_send_combinations_reach_the_handler(
    run: Any, monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(argv, FakeGateway())[0] == 0 and len(seen) == 1


def test_message_flag_on_a_terminal_is_fine(run: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["send", "--message=a"], _tty())[0] == 0 and seen


def test_combination_errors_win_over_a_missing_config(run: Any) -> None:
    # Step 1 comes before the config is consulted: no home lookup, no config path is touched.
    code, _, err = run(["--config=/nonexistent/x", "send", "--stdin-json", "--title=a"])
    assert code == 2 and err.startswith("usage: ")


@pytest.mark.parametrize("key", ["a" * 1025, "\ud800", "a\udcff"])
def test_dedupe_key_over_1024_chars_or_invalid_utf8_exits_2(
    run: Any, monkeypatch: pytest.MonkeyPatch, key: str
) -> None:
    seen = _spy_invocations(monkeypatch)
    code, _, err = run(["send", "--message=a", f"--dedupe-key={key}"])
    assert code == 2 and err.startswith("usage: ") and not seen


def test_dedupe_key_of_1024_unicode_chars_is_accepted(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _spy_invocations(monkeypatch)
    key = "é" * 1024
    assert run(["send", "--message=a", f"--dedupe-key={key}"])[0] == 0
    assert seen[0].send is not None and seen[0].send.dedupe_key == key


# --- --actor ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "actor",
    [
        "human:me",
        "auto:a.b",
        "auto:x@y.z/w-1_2",
        "human:" + "a" * 64,
        "auto:A",
    ],
)
def test_actor_in_the_grammar_is_accepted(
    run: Any, monkeypatch: pytest.MonkeyPatch, actor: str
) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run([f"--actor={actor}", "validate"])[0] == 0
    assert (seen[0].actor, seen[0].actor_source) == (actor, "flag")


@pytest.mark.parametrize(
    "actor",
    [
        "human:me\n",
        "human:me\r",
        "\nhuman:me",
        "human:",
        "human:" + "a" * 65,
        "robot:x",
        "human",
        "Human:x",
        "human:a b",
        "human:é",
        "human:a:b",
        "human:a\x00",
        " human:a",
        "human:a ",
        "human:\ud800",
        "",
    ],
)
def test_actor_outside_the_grammar_exits_2(
    run: Any, monkeypatch: pytest.MonkeyPatch, actor: str
) -> None:
    seen = _spy_invocations(monkeypatch)
    code, out, err = run([f"--actor={actor}", "validate"])
    assert code == 2 and out == "" and err.startswith("usage: ") and not seen


def test_actor_pattern_agrees_with_the_schema_pattern() -> None:
    pattern = load_schema("defs")["$defs"]["actor"]["pattern"]
    samples = ["human:me", "auto:a.b", "human:me\n", "\nauto:x", "human:", "x:y", "human:é"]
    for value in samples:
        ours = cli.ACTOR_RE.fullmatch(value) is not None
        assert ours is (re.search(pattern, value) is not None), value


def test_default_actor_is_auto_unknown_without_a_terminal(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _spy_invocations(monkeypatch)
    g = FakeGateway(login="alice")
    assert run(["validate"], g)[0] == 0
    assert (seen[0].actor, seen[0].actor_source) == ("auto:unknown", "default")


def test_default_actor_on_a_terminal_is_the_login_name(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["validate"], FakeGateway(login="alice", tty_fds={0}))[0] == 0
    assert (seen[0].actor, seen[0].actor_source) == ("human:alice", "tty")


@pytest.mark.parametrize(
    ("login", "expected"),
    [
        ("a b/c\nd", "human:a_b_c_d"),
        ("é", "human:_"),
        ("a.b_c@d-e", "human:a.b_c@d-e"),
        ("x" * 100, "human:" + "x" * 64),
        ("a" * 63 + "é" + "zzz", "human:" + "a" * 63 + "_"),
        (None, "human:unknown"),
        ("", "human:unknown"),
        ("\ud800", "human:_"),
    ],
)
def test_login_name_is_sanitized_cut_and_falls_back_to_unknown(login: str | None, expected: str):
    actor, source = cli.resolve_actor(None, FakeGateway(login=login, tty_fds={0}))
    assert (actor, source) == (expected, "tty")
    assert cli.ACTOR_RE.fullmatch(actor)


def test_actor_flag_wins_over_the_terminal_default(
    run: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _spy_invocations(monkeypatch)
    assert run(["--actor=auto:ci", "validate"], FakeGateway(tty_fds={0}))[0] == 0
    assert (seen[0].actor, seen[0].actor_source) == ("auto:ci", "flag")


# --- usage errors and --json --------------------------------------------------------------


def _envelope(out: str) -> dict[str, Any]:
    assert out.endswith("\n") and out.count("\n") == 1
    doc = json.loads(out)
    assert schema_errors("cli/error", doc) == []
    return doc


def test_usage_error_with_json_prints_a_valid_envelope_on_stdout(run: Any) -> None:
    code, out, err = run(["--json", "--bogus"])
    assert code == 2
    error = _envelope(out)["error"]
    assert error["code"] == "usage" and error["reason"] is None and error["details"] is None
    assert error["retryable"] is None and error["unknown_outcome"] is None
    assert err == f"usage: {error['message']}\n"


def test_envelope_key_order_and_serialization(run: Any) -> None:
    _, out, _ = run(["--json", "--bogus"])
    assert list(json.loads(out)["error"]) == [
        "code",
        "message",
        "reason",
        "details",
        "retryable",
        "retry_after_s",
        "unknown_outcome",
    ]
    assert " " not in out.replace("usage", "").split('"message":"')[0]  # compact separators


@pytest.mark.parametrize(
    "argv",
    [
        ["--json"],  # no command
        ["send", "--json", "--bogus"],
        ["--json", "send", "--title=a"],
        ["--json", "--actor=bad", "validate"],
        ["--json", "--config", "a", "--config", "b", "validate"],
        ["send", "--message=a", "--dedupe-key", "-x", "--json"],
        ["--json", "--", "x"],
        ["--json", "se"],
        ["--json", "--vers"],
        ["--json=1"],
        ["--json", "send", "--stdin-json=x"],
        ["--json", "send", "--message"],
    ],
)
def test_every_usage_error_with_json_is_a_schema_valid_envelope(run: Any, argv: list[str]) -> None:
    code, out, err = run(argv)
    assert code == 2
    assert _envelope(out)["error"]["code"] == "usage"
    assert err.count("\n") == 1 and err.startswith("usage: ")


def test_json_is_found_even_when_a_value_flag_is_malformed(run: Any) -> None:
    code, out, _ = run(["send", "--message", "--json"])
    assert code == 2 and _envelope(out)["error"]["code"] == "usage"


def test_json_as_a_value_with_equals_is_not_the_flag(run: Any) -> None:
    code, out, _ = run(["send", "--message=--json", "--bogus"])
    assert code == 2 and out == ""


def test_error_messages_never_contain_input(run: Any) -> None:
    secret = "SECRET-VALUE-é-‮"
    for argv in (
        [f"--{secret}"],
        [secret],
        ["send", f"--bogus={secret}"],
        ["send", "--message=a", f"--dedupe-key={secret}x" + "a" * 1100],
        [f"--actor={secret}", "validate"],
        ["--json", secret],
    ):
        code, out, err = run(argv)
        assert code == 2
        assert "SECRET" not in out + err and "‮" not in out + err


def test_usage_error_without_json_leaves_stdout_empty_and_prints_one_line(run: Any) -> None:
    code, out, err = run(["bogus"])
    assert code == 2 and out == "" and err.count("\n") == 1 and err.startswith("usage: ")


def test_no_command_is_a_usage_error(run: Any) -> None:
    code, out, err = run([])
    assert (code, out) == (2, "") and err.startswith("usage: ")


def test_usage_errors_touch_no_gateway_method() -> None:
    from tests.test_fake_gateway import _Tripwire

    for argv in (["--json"], [], ["send", "--bogus"], ["--actor=x", "validate"], ["send", "-"]):
        assert main(argv, {}, _Tripwire()) == 2  # type: ignore[arg-type]


def test_env_and_gateway_reach_the_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _spy_invocations(monkeypatch)
    gateway = FakeGateway()
    env = {"HA_TOKEN": "x"}
    assert main(["validate"], env, gateway) == 0  # type: ignore[arg-type]
    assert seen[0].env is env and seen[0].gateway is gateway


def test_env_defaults_to_the_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _spy_invocations(monkeypatch)
    monkeypatch.setenv("HA_NOTICE_PROBE", "1")
    assert main(["validate"], None, FakeGateway()) == 0  # type: ignore[arg-type]
    assert seen[0].env["HA_NOTICE_PROBE"] == "1"


def test_commands_not_yet_implemented_fail_closed_as_internal(run: Any) -> None:
    # TODO(#27) send flow and TODO(#28) validate replace these stubs; until then they must never
    # report success.
    code, out, err = run(["--json", "validate"])
    assert code == 1
    assert _envelope(out)["error"]["code"] == "internal"
    assert err.startswith("internal: ")
    assert run(["send", "--message=a"])[0] == 1


# --- --version, --help ---------------------------------------------------------------------


def test_version_prints_the_version_on_stdout_and_returns_0(run: Any) -> None:
    assert run(["--version"]) == (0, f"ha-notice {VERSION}\n", "")


def test_version_after_the_subcommand(run: Any) -> None:
    assert run(["send", "--version"]) == (0, f"ha-notice {VERSION}\n", "")


def test_version_is_exempt_from_the_json_envelope(run: Any) -> None:
    assert run(["--json", "--version"]) == (0, f"ha-notice {VERSION}\n", "")


def test_version_wins_over_later_unknown_arguments(run: Any) -> None:
    assert run(["--version", "--bogus"]) == (0, f"ha-notice {VERSION}\n", "")


def test_help_goes_to_stdout_exit_0_and_is_exempt_from_json(run: Any) -> None:
    for argv in (["--help"], ["--json", "-h"], ["send", "--help"], ["validate", "--help"]):
        code, out, err = run(argv)
        assert code == 0 and out.startswith("usage: ha-notice") and err == ""
        assert "{" not in out.splitlines()[0]
    assert "--dedupe-key" in run(["send", "--help"])[1]


def test_global_flags_are_documented_in_help(run: Any) -> None:
    out = run(["--help"])[1]
    for flag in ("--json", "--config", "--dry-run", "--actor", "--verbose", "--quiet", "--version"):
        assert flag in out


# --- goldens -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "argv"),
    [
        ("usage-no-command.json", ["--json"]),
        ("usage-unknown-flag.json", ["--json", "send", "--bogus"]),
        ("usage-bad-actor.json", ["--json", "--actor=nope", "validate"]),
        ("usage-flag-combination.json", ["--json", "send", "--stdin-json", "--message=a"]),
    ],
)
def test_usage_error_goldens(run: Any, golden: Golden, name: str, argv: list[str]) -> None:
    code, out, _ = run(argv)
    assert code == 2
    golden.check("output", name, out, schema="cli/error")


# --- output encoding -----------------------------------------------------------------------


class _Bytes:
    """A stream with a binary buffer, to see the exact bytes written."""

    def __init__(self) -> None:
        self.buffer = _Buf()

    def write(self, text: str) -> int:  # pragma: no cover - must not be used when a buffer exists
        raise AssertionError("text write on a stream with a buffer")

    def flush(self) -> None:
        pass


class _Buf:
    def __init__(self) -> None:
        self.data = b""

    def write(self, data: bytes) -> int:
        self.data += data
        return len(data)

    def flush(self) -> None:
        pass


def test_streams_are_written_as_utf8_bytes_with_errors_replaced() -> None:
    stream = _Bytes()
    cli.write_text(stream, "é\ud800x\n")  # type: ignore[arg-type]
    assert stream.buffer.data == "é?x\n".encode()


def test_write_errors_are_ignored() -> None:
    class Broken:
        def write(self, text: str) -> int:
            raise BrokenPipeError

        def flush(self) -> None:
            raise OSError

    cli.write_text(Broken(), "x")  # type: ignore[arg-type]


def test_a_closed_stdout_leaves_the_exit_code_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Closed:
        def write(self, text: str) -> int:
            raise BrokenPipeError

        def flush(self) -> None:
            raise BrokenPipeError

    monkeypatch.setattr(sys, "stdout", Closed())
    monkeypatch.setattr(sys, "stderr", Closed())
    assert main(["--json", "--bogus"], {}, FakeGateway()) == 2  # type: ignore[arg-type]
    assert main(["--version"], {}, FakeGateway()) == 0  # type: ignore[arg-type]


# --- a real process ------------------------------------------------------------------------


def test_real_process_usage_error_with_json(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "cfg"),
        "XDG_STATE_HOME": str(home / "state"),
        "LC_ALL": "C",
        "PYTHONIOENCODING": "ascii",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "ha_notice", "--json", "send", "--bogus"],
        capture_output=True,
        timeout=60,
        check=False,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 2
    assert schema_errors("cli/error", json.loads(proc.stdout)) == []
    assert proc.stderr.startswith(b"usage: ") and list(home.iterdir()) == []


# --- real processes with broken standard streams -------------------------------------------


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


def _closed_fd(tmp_path: Path, args: list[str], fd: int) -> subprocess.CompletedProcess[bytes]:
    """Run the tool with one standard fd closed in the child (``N>&-``)."""
    cmd = " ".join(shlex.quote(a) for a in [sys.executable, "-m", "ha_notice", *args])
    return subprocess.run(
        ["/bin/sh", "-c", f"exec {cmd} {fd}>&-"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL if fd != 1 else None,
        stderr=subprocess.DEVNULL if fd != 2 else None,
        capture_output=False,
        timeout=60,
        check=False,
        env=_env(tmp_path),
    )


def test_real_process_closed_stdout_version_exits_0(tmp_path: Path) -> None:
    assert _closed_fd(tmp_path, ["--version"], 1).returncode == 0


def test_real_process_closed_stdout_usage_error_with_json_exits_2(tmp_path: Path) -> None:
    assert _closed_fd(tmp_path, ["--json", "bogus"], 1).returncode == 2


def test_real_process_closed_stderr_usage_error_exits_2(tmp_path: Path) -> None:
    assert _closed_fd(tmp_path, ["bogus"], 2).returncode == 2


def test_real_process_stdout_to_dev_full_keeps_the_exit_code(tmp_path: Path) -> None:
    with open("/dev/full", "wb") as full:
        proc = subprocess.run(
            [sys.executable, "-m", "ha_notice", "--version"],
            stdin=subprocess.DEVNULL,
            stdout=full,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
            env=_env(tmp_path),
        )
    assert proc.returncode == 0


def test_real_process_closed_pipe_keeps_the_exit_code(tmp_path: Path) -> None:
    read_end, write_end = os.pipe()
    os.close(read_end)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "ha_notice", "--json", "bogus"],
            stdin=subprocess.DEVNULL,
            stdout=write_end,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
            env=_env(tmp_path),
        )
    finally:
        os.close(write_end)
    assert proc.returncode == 2
