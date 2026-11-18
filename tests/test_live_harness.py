"""The live suite's own safety net and harness tests (issue #31). None of these is a live test.

They check that the live tests name real checklist items, that nothing under ``tests/live`` is
collected without ``-m live`` (so ``make verify`` and CI never run one), that an unconfigured
live run skips everything with a reason, that the two raw helpers are guarded, and, against the
fake Home Assistant on loopback, that the live tests themselves work (an inner pytest run with
the LIVE_HA_* variables pointing at the fake). Nothing here reaches a real host.
"""

from __future__ import annotations

import ast
import json
import os
import re
import socket
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.fake_ha import FakeHA, Reply
from tests.live import support
from tests.live.checklist import ITEMS, settles
from tests.live.support import (
    CommandsNotAllowed,
    CommandWordRefused,
    LiveConfig,
    NotifyPostRefused,
)

ROOT = Path(__file__).resolve().parent.parent
LIVE_DIR = ROOT / "tests" / "live"
DESIGN = (ROOT / "docs" / "design.md").read_text(encoding="utf-8")
LIVE_SECTION = DESIGN[DESIGN.index("## Live verification") : DESIGN.index("## Modules")]
TOKEN = "HA_LIVE_secret_0123456789abcdef"
SERVICE = "mobile_app_live"


# --- static checks of the live tests ---------------------------------------------------------


def _live_test_functions() -> list[tuple[str, ast.FunctionDef]]:
    found: list[tuple[str, ast.FunctionDef]] = []
    for path in sorted(LIVE_DIR.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                found.append((f"{path.name}::{node.name}", node))
    return found


def _settled_ids(func: ast.FunctionDef) -> list[str]:
    ids: list[str] = []
    for deco in func.decorator_list:
        if isinstance(deco, ast.Call) and getattr(deco.func, "id", None) == "settles":
            ids.extend(str(a.value) for a in deco.args if isinstance(a, ast.Constant))
    return ids


def test_there_are_live_tests() -> None:
    assert len(_live_test_functions()) >= 10


@pytest.mark.parametrize("name,func", _live_test_functions(), ids=lambda v: str(v)[:60])
def test_every_live_test_names_a_known_checklist_item(name: str, func: ast.FunctionDef) -> None:
    ids = _settled_ids(func)
    assert ids, f"{name} has no @settles(...)"
    assert all(i in ITEMS for i in ids), f"{name}: unknown item in {ids}"


@pytest.mark.parametrize("item", sorted(ITEMS))
def test_every_checklist_item_exists_in_design_md(item: str) -> None:
    assert ITEMS[item] in LIVE_SECTION, (
        f"{item}: {ITEMS[item]!r} not in design.md Live verification"
    )


def test_every_checklist_item_is_settled_by_some_live_test() -> None:
    used = {i for _, func in _live_test_functions() for i in _settled_ids(func)}
    assert used == set(ITEMS)


def test_settles_rejects_an_unknown_or_missing_item() -> None:
    with pytest.raises(ValueError):
        settles("V99")
    with pytest.raises(ValueError):
        settles()


def test_live_markers_are_registered() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for name in ("live:", "settles(", "live_commands:"):
        assert name in text
    assert "addopts = \"-m 'not live'\"" in text


def test_src_never_reads_the_live_variables() -> None:
    for path in (ROOT / "src").rglob("*.py"):
        assert "LIVE_HA" not in path.read_text(encoding="utf-8"), path.name


# --- collection and skipping in real pytest processes ----------------------------------------


def _clean_env(tmp: Path, **extra: str) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(tmp),
        "XDG_CONFIG_HOME": str(tmp),
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    env.update(extra)
    return env


def _pytest(tmp: Path, args: list[str], **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider"]
        + [f"--basetemp={tmp / 'bt'}", *args],
        cwd=ROOT,
        env=_clean_env(tmp, **env),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )  # fmt: skip


def test_live_tests_are_not_collected_by_default(tmp_path: Path) -> None:
    done = _pytest(tmp_path, ["--collect-only", "-q"])
    assert done.returncode == 0, done.stdout + done.stderr
    ids = [line for line in done.stdout.splitlines() if "::" in line]
    assert ids and not [i for i in ids if i.startswith("tests/live/")]
    assert "deselected" in done.stdout


def test_dash_m_live_collects_exactly_the_live_tests(tmp_path: Path) -> None:
    done = _pytest(tmp_path, ["-m", "live", "--collect-only", "-q"])
    assert done.returncode == 0, done.stdout + done.stderr
    ids = [line for line in done.stdout.splitlines() if "::" in line]
    assert len(ids) == len(_live_test_functions())
    assert all(i.startswith("tests/live/") for i in ids), ids


def test_without_configuration_every_live_test_skips_with_the_reason(tmp_path: Path) -> None:
    done = _pytest(tmp_path, ["-m", "live", "-s", "-rs", "-q"])
    assert done.returncode == 0, done.stdout + done.stderr
    count = len(_live_test_functions())
    assert f"{count} skipped" in done.stdout and "passed" not in done.stdout.splitlines()[-1]
    assert "set LIVE_HA_BASE_URL, LIVE_HA_SERVICE, LIVE_HA_TOKEN_ENV" in done.stdout


def test_without_dash_s_a_configured_live_test_skips(tmp_path: Path) -> None:
    done = _pytest(
        tmp_path,
        ["-m", "live", "-rs", "-q", "tests/live/test_live_edge.py::test_probe_body_shape"],
        LIVE_HA_BASE_URL="http://127.0.0.1:9",
        LIVE_HA_SERVICE=SERVICE,
        LIVE_HA_TOKEN_ENV="HA_LIVE_TOKEN",
        HA_LIVE_TOKEN=TOKEN,
    )
    assert "1 skipped" in done.stdout and "run with -s" in done.stdout


# --- configuration and the guarded raw helpers -----------------------------------------------


def _env(**extra: str) -> dict[str, str]:
    base = {
        "LIVE_HA_BASE_URL": "https://ha.example.invalid:8123",
        "LIVE_HA_SERVICE": SERVICE,
        "LIVE_HA_TOKEN_ENV": "HA_LIVE_TOKEN",
        "HA_LIVE_TOKEN": TOKEN,
    }
    base.update(extra)
    return base


def test_config_from_a_complete_environment() -> None:
    cfg, reason = LiveConfig.from_env(_env())
    assert cfg is not None and reason == ""
    assert cfg.token == TOKEN and cfg.allow_commands is False and cfg.pause == 5.0


@pytest.mark.parametrize(
    "mutation,fragment",
    [
        ({"LIVE_HA_BASE_URL": ""}, "LIVE_HA_BASE_URL"),
        ({"LIVE_HA_SERVICE": ""}, "LIVE_HA_SERVICE"),
        ({"LIVE_HA_TOKEN_ENV": ""}, "LIVE_HA_TOKEN_ENV"),
        ({"LIVE_HA_TOKEN_ENV": "TOKEN"}, "HA_"),
        ({"LIVE_HA_TOKEN_ENV": "HA_lower"}, "HA_"),
        ({"HA_LIVE_TOKEN": ""}, "holds no token"),
        ({"HA_LIVE_TOKEN": "has space"}, "holds no token"),
        ({"HA_LIVE_TOKEN": "tokén"}, "holds no token"),
        ({"LIVE_HA_PAUSE": "soon"}, "LIVE_HA_PAUSE"),
        ({"LIVE_HA_PAUSE": "-1"}, "LIVE_HA_PAUSE"),
        ({"LIVE_HA_PAUSE": "9999"}, "LIVE_HA_PAUSE"),
        ({"LIVE_HA_COUNTDOWN": "soon"}, "LIVE_HA_COUNTDOWN"),
        ({"LIVE_HA_COUNTDOWN": "61"}, "LIVE_HA_COUNTDOWN"),
        ({"LIVE_HA_TIMEOUT": "soon"}, "LIVE_HA_TIMEOUT"),
        ({"LIVE_HA_TIMEOUT": "500ms"}, "LIVE_HA_TIMEOUT"),
        ({"LIVE_HA_TIMEOUT": "121"}, "LIVE_HA_TIMEOUT"),
        ({"LIVE_HA_TIMEOUT": "010"}, "LIVE_HA_TIMEOUT"),
        ({"LIVE_HA_TIMEOUT": "1e3"}, "LIVE_HA_TIMEOUT"),
        ({"LIVE_HA_BLACKHOLE_URL": "https://ha.example.invalid:8123"}, "LIVE_HA_BLACKHOLE_URL"),
        ({"LIVE_HA_BLACKHOLE_URL": "https://ha.example.invalid:8123/"}, "LIVE_HA_BLACKHOLE_URL"),
    ],
)
def test_config_refuses_a_bad_environment(mutation: dict[str, str], fragment: str) -> None:
    cfg, reason = LiveConfig.from_env(_env(**mutation))
    assert cfg is None and fragment in reason
    assert TOKEN not in reason


def test_blackhole_may_not_equal_the_prefix_url() -> None:
    cfg, reason = LiveConfig.from_env(
        _env(
            LIVE_HA_PREFIX_BASE_URL="https://proxy.example.invalid/ha",
            LIVE_HA_BLACKHOLE_URL="https://proxy.example.invalid/ha",
        )
    )
    assert cfg is None and "LIVE_HA_BLACKHOLE_URL" in reason


@pytest.mark.parametrize(
    "value,seconds",
    [("10s", 10.0), ("1m", 60.0), ("10", 10.0), ("1.5s", 1.5), ("1500ms", 1.5), ("120", 120.0)],
)
def test_timeout_is_parsed_with_the_interface_duration_grammar(value: str, seconds: float) -> None:
    cfg, reason = LiveConfig.from_env(_env(LIVE_HA_TIMEOUT=value))
    assert cfg is not None, reason
    assert cfg.timeout == value and cfg.timeout_seconds == seconds


def test_the_default_timeout_and_countdown() -> None:
    cfg, _ = LiveConfig.from_env(_env())
    assert cfg is not None
    assert cfg.timeout_seconds == 10.0 and cfg.countdown == 10.0


def test_any_live_variable_is_detected_even_when_empty() -> None:
    assert not support.any_live_variable({"HA_LIVE_TOKEN": TOKEN, "PATH": "/bin"})
    assert support.any_live_variable({"LIVE_HA_PAUSE": ""})


def test_countdown_announces_ctrl_c_and_waits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg, _ = LiveConfig.from_env(_env(LIVE_HA_COUNTDOWN="2.5"))
    assert cfg is not None
    slept: list[float] = []
    monkeypatch.setattr(support.time, "sleep", slept.append)
    support.countdown(cfg)
    assert "Ctrl-C aborts" in capsys.readouterr().out
    assert sum(slept) == pytest.approx(2.5)


def test_config_never_shows_the_token_or_the_host() -> None:
    cfg, _ = LiveConfig.from_env(_env())
    assert cfg is not None
    for text in (repr(cfg), str(cfg)):
        assert TOKEN not in text and "example.invalid" not in text


def test_the_command_opt_in_needs_exactly_one() -> None:
    assert LiveConfig.from_env(_env(LIVE_HA_ALLOW_COMMANDS="1"))[0].allow_commands is True  # type: ignore[union-attr]
    for value in ("", "0", "yes", "true", "11"):
        cfg, _ = LiveConfig.from_env(_env(LIVE_HA_ALLOW_COMMANDS=value))
        assert cfg is not None and cfg.allow_commands is False


def _config(url: str, **extra: str) -> LiveConfig:
    cfg, reason = LiveConfig.from_env(
        _env(LIVE_HA_BASE_URL=url, LIVE_HA_ALLOW_INSECURE_HTTP="1", **extra)
    )
    assert cfg is not None, reason
    return cfg


def test_write_config_has_no_token_and_refuses_http_without_the_switch(tmp_path: Path) -> None:
    with FakeHA(token=TOKEN) as ha:
        path = support.write_config(tmp_path, _config(ha.base_url))
        text = path.read_text(encoding="utf-8")
        assert TOKEN not in text and "token_env" in text and "log: false" in text
        plain, _ = LiveConfig.from_env(_env(LIVE_HA_BASE_URL=ha.base_url))
        assert plain is not None
        with pytest.raises(ValueError):
            support.write_config(tmp_path, plain)


@pytest.mark.parametrize(
    "word", ["tts", "TTS", " update_widgets ", "clear_notification", "command_x", "kiosk_mode"]
)
def test_raw_post_notify_refuses_command_words_and_sends_nothing(word: str) -> None:
    with FakeHA(token=TOKEN) as ha:
        cfg = _config(ha.base_url, LIVE_HA_ALLOW_COMMANDS="1")  # even with the opt-in
        with pytest.raises(CommandWordRefused):
            support.raw_post_notify(cfg, {"message": word})
        assert ha.requests == [] and ha.connections == 0


OBFUSCATED = [
    "tts\x00",
    "t\x00ts",
    "tts\u200b",
    "\u200btts",
    "tts\ufeff",
    "tts\xad",
    "clear_\u200bnotification",
    "TTS\u200b",
]


@pytest.mark.parametrize("word", OBFUSCATED, ids=lambda w: ascii(w))
def test_raw_post_notify_refuses_words_the_tool_would_see_after_sanitizing(word: str) -> None:
    with FakeHA(token=TOKEN) as ha:
        cfg = _config(ha.base_url)
        for body in ({"message": word}, {"title": word, "message": "x"}):
            with pytest.raises(CommandWordRefused):
                support.raw_post_notify(cfg, body)
        assert ha.requests == [] and ha.connections == 0


@pytest.mark.parametrize(
    "body",
    [
        {"message": "x", "tts_text": "hello"},
        {"message": "x", "command": "tts"},
        {"message": "x", "target": ["a"]},
        {"message": "x", "data": {"tts_text": "hello"}},
        {"message": "x", "data": {"url": "https://a.example", "actions": []}},
        {"message": "x", "data": "tts"},
        {"message": "x", "data": {"tag": ["a"]}},
        {"title": "t"},
    ],
    ids=lambda b: ",".join(b),
)
def test_raw_post_notify_allows_only_the_known_body_and_data_keys(body: dict[str, object]) -> None:
    with FakeHA(token=TOKEN) as ha:
        with pytest.raises(CommandWordRefused):
            support.raw_post_notify(_config(ha.base_url), body)
        assert ha.connections == 0


def test_raw_post_notify_sends_title_message_and_the_three_data_keys() -> None:
    body = {"title": "t", "message": "m", "data": {"tag": "a", "url": "u", "clickAction": "c"}}
    with FakeHA(token=TOKEN) as ha:
        assert support.raw_post_notify(_config(ha.base_url), body).status == 200
        assert json.loads(ha.requests[0].body) == body


def test_raw_request_refuses_a_post_to_a_notify_service_and_allows_a_get() -> None:
    with FakeHA(token=TOKEN) as ha:
        cfg = _config(ha.base_url)
        for path in (f"/api/services/notify/{SERVICE}", "/api/services/NOTIFY/x"):
            with pytest.raises(NotifyPostRefused):
                support._raw_request(cfg, "POST", path, body={"message": "tts"})  # pyright: ignore[reportPrivateUsage]
        assert ha.connections == 0
        assert support.raw_get(cfg, "/api/").status == 200
        assert not hasattr(support, "raw_request")


def test_every_family_word_is_flagged_and_every_family_has_a_word() -> None:
    from ha_notice.payload import check_command_keyword
    from tests.live.test_live_commands import FAMILY_WORDS

    assert all(check_command_keyword(word) for word in FAMILY_WORDS)
    for family in ("tts", "command_", "kiosk_", "update_", "clear_", "remove_", "request_"):
        assert any(w.startswith(family) for w in FAMILY_WORDS), family


def test_trust_location_state(tmp_path: Path, self_signed_cert: tuple[Path, Path]) -> None:
    cert, _ = self_signed_cert
    junk = tmp_path / "junk.pem"
    junk.write_text("not a certificate\n", encoding="utf-8")
    state = support.trust_location_state
    assert state("", directory=False) == "unset"
    assert state(str(tmp_path / "missing"), directory=False) == "missing"
    assert state(str(cert), directory=False) == "exists, loads"
    assert state(str(junk), directory=False) == "exists, does not load"
    assert state(str(tmp_path), directory=True) == "exists, loads"


def test_raw_post_notify_refuses_a_non_string_message() -> None:
    with FakeHA(token=TOKEN) as ha:
        with pytest.raises(CommandWordRefused):
            support.raw_post_notify(_config(ha.base_url), {"message": ["tts"]})
        assert ha.connections == 0


def test_send_command_word_needs_the_opt_in() -> None:
    with FakeHA(token=TOKEN) as ha:
        with pytest.raises(CommandsNotAllowed):
            support.send_command_word(_config(ha.base_url), "tts", "t")
        assert ha.connections == 0
        reply = support.send_command_word(
            _config(ha.base_url, LIVE_HA_ALLOW_COMMANDS="1"), "tts", "t"
        )
        assert reply.status == 200
        (request,) = ha.requests
        assert json.loads(request.body) == {"title": "t", "message": "tts"}


def test_raw_notify_sends_the_token_only_in_the_authorization_header() -> None:
    with FakeHA(token=TOKEN) as ha:
        cfg = _config(ha.base_url)
        assert support.raw_post_notify(cfg, {"message": "hello"}).status == 200
        (request,) = ha.requests
        assert request.header("Authorization") == f"Bearer {TOKEN}"
        assert TOKEN not in request.path and TOKEN.encode() not in request.body


def test_raw_post_notify_can_send_a_chosen_token() -> None:
    with FakeHA(token=TOKEN) as ha:
        reply = support.raw_post_notify(_config(ha.base_url), {"message": "x"}, token="wrong")
        assert reply.status == 401
        assert ha.requests[0].header("Authorization") == "Bearer wrong"


def test_position_text_has_the_exact_length_and_readable_positions() -> None:
    for size in (1, 6, 7, 1000, 100000):
        assert len(support.position_text(size)) == size
    assert support.position_text(30).startswith("000000 000007 000014 ")


def test_run_tool_environment_holds_only_the_token_variable(tmp_path: Path) -> None:
    with FakeHA(token=TOKEN) as ha:
        cfg = _config(ha.base_url)
        config = support.write_config(tmp_path, cfg)
        run = support.validate(config, cfg, "--probe")
        assert run.code == 0 and run.error() == {}
        assert [r.path for r in ha.requests] == ["/api/"]


# --- the live tests themselves, run against the fake Home Assistant --------------------------


def _inner(
    tmp: Path, args: list[str], env: dict[str, str], markexpr: str = "live"
) -> subprocess.CompletedProcess[str]:
    full = {
        "LIVE_HA_PAUSE": "0",
        "LIVE_HA_COUNTDOWN": "0",
        "LIVE_HA_TIMEOUT": "2s",
        "HA_LIVE_TOKEN": TOKEN,
    }
    full.update(env)
    full["LIVE_HA_TOKEN_ENV"] = "HA_LIVE_TOKEN"
    full["LIVE_HA_SERVICE"] = SERVICE
    return _pytest(tmp, ["-m", markexpr, "-s", "-rs", "-q", *args], **full)


@contextmanager
def _blackhole() -> Iterator[str]:
    """A loopback address whose connect never completes: a listener with a full accept queue."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(0)
        port = listener.getsockname()[1]
        fillers: list[socket.socket] = []
        try:
            for _ in range(4):
                filler = socket.socket()
                filler.setblocking(False)
                fillers.append(filler)
                try:
                    filler.connect(("127.0.0.1", port))
                except BlockingIOError:
                    pass
            yield f"http://127.0.0.1:{port}"
        finally:
            for filler in fillers:
                filler.close()


def _titles(ha: FakeHA) -> list[str]:
    out: list[str] = []
    for request in ha.requests:
        if request.method == "POST" and request.header("Authorization") == f"Bearer {TOKEN}":
            body = json.loads(request.body)
            out.append(str(body.get("title", "")))
    return out


def _message_lengths(ha: FakeHA) -> dict[str, int]:
    """The message length of every authorized POST, keyed by the end of its title."""
    lengths: dict[str, int] = {}
    for request in ha.requests:
        if request.method == "POST" and request.header("Authorization") == f"Bearer {TOKEN}":
            body = json.loads(request.body)
            lengths[str(body.get("title", "")).split(" ", 4)[-1]] = len(body["message"])
    return lengths


@pytest.mark.long_alarm
def test_live_tests_run_against_the_fake_home_assistant(tmp_path: Path) -> None:
    from tests.live.test_live_commands import FAMILY_WORDS

    with (
        FakeHA(token=TOKEN, services={SERVICE, "other"}) as ha,
        FakeHA(token=TOKEN, prefix="p", services={SERVICE}) as prefixed,
        _blackhole() as blackhole,
    ):
        done = _inner(
            tmp_path,
            ["tests/live"],
            {
                "LIVE_HA_BASE_URL": ha.base_url,
                "LIVE_HA_ALLOW_INSECURE_HTTP": "1",
                "LIVE_HA_PREFIX_BASE_URL": prefixed.base_url + "/p",
                "LIVE_HA_OTHER_SERVICE": "other",
                "LIVE_HA_BLACKHOLE_URL": blackhole,
            },
        )
        report = done.stdout + done.stderr
        assert done.returncode == 0, report
        assert "13 passed, 3 skipped" in report, report
        assert "opt-in only" in report and "needs an https LIVE_HA_BASE_URL" in report
        assert "no TLS chain to verify" in report
        assert TOKEN not in report
        # instructions are printed, numbered, with the item and the run marker
        assert "WHAT YOU SHOULD SEE ON THE PHONE:" in report and "  1. " in report
        assert "[settles V20]" in report and "ha-notice live test " in report
        # the wrong token was answered 401 for both raw requests
        assert "raw GET /api/ with a wrong token: HTTP 401" in report
        assert "raw POST notify with a wrong token: HTTP 401" in report
        # no command word reached the fake without the opt-in
        sent = [json.loads(r.body).get("message") for r in ha.requests if r.method == "POST"]
        # (the one `clear_notification` is the tool's own `clear`: a body of message and tag only)
        assert not [m for m in sent if m in FAMILY_WORDS and m != "clear_notification"]
        everything = [json.loads(r.body) for r in ha.requests if r.method == "POST"]
        clears = [b for b in everything if b.get("message") == "clear_notification"]
        assert len(clears) == 1 and set(clears[0]) == {"message", "data"}
        assert set(clears[0]["data"]) == {"tag"}
        # the clear test: one send, then a clear with its tag; the tag test: two sends, one tag
        tagged = [b for b in everything if b not in clears]
        tags = [b["data"]["tag"] for b in tagged if "data" in b and "tag" in b["data"]]
        assert len(tags) == 3 and tags[1] == tags[2] != tags[0]  # (files run in name order)
        assert tags[0] == clears[0]["data"]["tag"]
        # the link test: both keys from the tool, then each key alone from the raw sender
        datas = [
            b["data"]
            for b in tagged
            if "data" in b and ("url" in b["data"] or "clickAction" in b["data"])
        ]
        assert len(datas) == 3
        assert datas[0]["clickAction"] == datas[0]["url"]
        assert set(datas[1]) == {"url"} and set(datas[2]) == {"clickAction"}
        # sizes: raw 1000/10000/100000; the tool cut 100000 characters to its two caps
        lengths = _message_lengths(ha)
        assert lengths["raw 1000"] == 1000
        assert lengths["raw 10000"] == 10000
        assert lengths["raw 100000"] == 100000
        assert lengths["tool max_chars 1000"] == 1000
        assert lengths["tool max_chars 2000"] == 1998
        # markup sent literally; every title carries the unique marker except the test message
        assert any(
            b.get("message") == '<b>x</b> <a href="https://example.org">y</a>' for b in tagged
        )
        # (the clear has no title: ``_titles`` reads it as an empty one)
        assert all(
            t.startswith("ha-notice live test ") or t in ("ha-notice", "") for t in _titles(ha)
        ), _titles(ha)
        # the prefixed fake got the probe and one send
        assert [r.method for r in prefixed.requests] == ["GET", "POST"]
        assert "tool result after" in report and "network_error" in report


def test_self_signed_and_default_ca_tests_run_against_a_tls_fake(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    cert, key = self_signed_cert
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key, services={SERVICE}) as ha:
        done = _inner(
            tmp_path,
            ["tests/live", "-k", "self_signed or default_ca"],
            {"LIVE_HA_BASE_URL": ha.base_url, "LIVE_HA_CA_FILE": str(cert)},
        )
        report = done.stdout + done.stderr
        assert done.returncode == 0, report
        assert "2 passed" in report and TOKEN not in report
        assert "fallback " in report and "probe with system trust only" in report


def _command_env(ha: FakeHA, cert: Path) -> dict[str, str]:
    return {
        "LIVE_HA_BASE_URL": ha.base_url,
        "LIVE_HA_CA_FILE": str(cert),
        "LIVE_HA_ALLOW_COMMANDS": "1",
    }


def test_command_words_are_sent_only_under_dash_m_live_commands(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    from tests.live.test_live_commands import FAMILY_WORDS

    cert, key = self_signed_cert
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key, services={SERVICE}) as ha:
        done = _inner(tmp_path, ["tests/live"], _command_env(ha, cert), markexpr="live_commands")
        report = done.stdout + done.stderr
        assert done.returncode == 0, report
        assert "1 passed" in report and TOKEN not in report
        assert "SENDING COMPANION-APP COMMAND WORDS" in report
        assert "Ctrl-C aborts" in report and "unverified" in report
        assert report.index("Ctrl-C aborts") < report.index("sending 1/")
        for word in ("request_location_update", "command_screen_on", "tts"):
            assert word in report
        messages = [json.loads(r.body).get("message") for r in ha.requests if r.method == "POST"]
        assert [m for m in messages if m in FAMILY_WORDS] == list(FAMILY_WORDS)
        assert re.fullmatch(r"[0-9a-f]{6}: update_widgets", str(messages[-1]))


def test_command_words_are_not_sent_by_the_plain_live_run_even_with_the_opt_in(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    cert, key = self_signed_cert
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key, services={SERVICE}) as ha:
        done = _inner(tmp_path, ["tests/live", "-k", "command_word"], _command_env(ha, cert))
        report = done.stdout + done.stderr
        assert done.returncode == 0, report
        assert "1 skipped" in report and "-m live_commands" in report
        assert ha.requests == []


# --- the token and the configuration in a failing live run -----------------------------------

CANARY = "HA_canary_0123456789_zzz"
LEAK_TESTS = """
import os
import subprocess

from tests.live import support


def _cfg():
    env = {
        "LIVE_HA_BASE_URL": os.environ["CANARY_URL"],
        "LIVE_HA_SERVICE": "canary_service_x",
        "LIVE_HA_TOKEN_ENV": "HA_CANARY",
        "HA_CANARY": os.environ["HA_CANARY"],
        "LIVE_HA_ALLOW_INSECURE_HTTP": "1",
    }
    cfg, reason = support.LiveConfig.from_env(env)
    assert cfg is not None, reason
    return cfg


def test_raw_error():
    cfg = _cfg()
    support.raw_get(cfg, "/api/")


def test_tool_timeout(tmp_path):
    cfg = _cfg()
    support.run_tool(tmp_path / "c.yaml", ["validate"], cfg, limit_s=0.0001)


def test_tool_prints_the_token(tmp_path, monkeypatch):
    cfg = _cfg()
    leaked = subprocess.CompletedProcess([], 0, os.environ["HA_CANARY"].encode(), b"")
    monkeypatch.setattr(support, "_spawn", lambda *args: leaked)
    support.run_tool(tmp_path / "c.yaml", ["validate"], cfg)


def test_spawn_fails_to_start(tmp_path, monkeypatch):
    cfg = _cfg()

    def refuse(*args, **kwargs):
        raise OSError("cannot start")

    monkeypatch.setattr(subprocess, "run", refuse)
    support.run_tool(tmp_path / "c.yaml", ["validate"], cfg)
"""


def test_failures_with_showlocals_never_print_the_token(tmp_path: Path) -> None:
    with socket.socket() as sock:  # a loopback port with nothing listening
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    (tmp_path / "test_leak.py").write_text(LEAK_TESTS, encoding="utf-8")
    done = _pytest(
        tmp_path,
        ["-o", "addopts=", "-l", "--showlocals", "--tb=long", "-q", str(tmp_path / "test_leak.py")],
        CANARY_URL=f"http://127.0.0.1:{port}",
        HA_CANARY=CANARY,
    )
    report = done.stdout + done.stderr
    assert done.returncode == 1 and "4 failed" in report, report
    assert "RawRequestError: ConnectionRefusedError" in report
    assert "RuntimeError: the tool could not be started: OSError" in report
    assert "ToolTimeout" in report and "the tool printed the token" in report
    for secret in (CANARY, "canary_service_x", f"127.0.0.1:{port}", "Bearer"):
        assert secret not in report, secret


def test_a_partly_set_or_invalid_configuration_fails_with_the_reason(tmp_path: Path) -> None:
    target = "tests/live/test_live_edge.py::test_probe_body_shape"
    cases = [
        ({"LIVE_HA_BASE_URL": "http://127.0.0.1:9"}, "LIVE_HA_SERVICE"),
        (
            {
                "LIVE_HA_BASE_URL": "http://127.0.0.1:9",
                "LIVE_HA_SERVICE": SERVICE,
                "LIVE_HA_TOKEN_ENV": "HA_LIVE_TOKEN",
                "LIVE_HA_PAUSE": "soon",
                "HA_LIVE_TOKEN": TOKEN,
            },
            "LIVE_HA_PAUSE",
        ),
        (
            {
                "LIVE_HA_BASE_URL": "http://127.0.0.1:9",
                "LIVE_HA_SERVICE": SERVICE,
                "LIVE_HA_TOKEN_ENV": "NOT_HA",
                "NOT_HA": TOKEN,
            },
            "HA_[A-Z0-9_]",
        ),
    ]
    for env, fragment in cases:
        done = _pytest(tmp_path, ["-m", "live", "-s", "-rs", "-q", target], **env)
        report = done.stdout + done.stderr
        assert done.returncode == 1 and "1 error" in report, report
        assert "configuration is invalid" in report and fragment in report
        assert TOKEN not in report and "127.0.0.1" not in report


# --- mutations: the inner run must fail when the live assertions are not met -----------------


def _inner_fails(tmp: Path, keyword: str, base_url: str, extra: dict[str, str]) -> str:
    done = _inner(
        tmp,
        ["tests/live", "-k", keyword],
        {"LIVE_HA_BASE_URL": base_url, "LIVE_HA_ALLOW_INSECURE_HTTP": "1", **extra},
    )
    report = done.stdout + done.stderr
    assert done.returncode == 1 and "1 failed" in report, report
    assert TOKEN not in report
    return report


def test_a_healthy_host_as_the_blackhole_fails_the_unreachable_test(tmp_path: Path) -> None:
    with FakeHA(token=TOKEN, services={SERVICE}) as ha, FakeHA(token=TOKEN) as healthy:
        report = _inner_fails(
            tmp_path, "unreachable", ha.base_url, {"LIVE_HA_BLACKHOLE_URL": healthy.base_url}
        )
        assert "auth_required" in report


def test_a_wrong_token_answered_500_fails_the_wrong_token_test(tmp_path: Path) -> None:
    with FakeHA(token=TOKEN, script=[Reply(status=500)] * 20) as ha:
        _inner_fails(tmp_path, "wrong_token", ha.base_url, {})


def test_a_wrong_token_probe_that_is_not_auth_required_fails_the_test(tmp_path: Path) -> None:
    script = [Reply(status=401)] * 2 + [Reply(status=500)] * 20  # raw GET, raw POST, then tool
    with FakeHA(token=TOKEN, script=script) as ha:
        report = _inner_fails(tmp_path, "wrong_token", ha.base_url, {})
        assert "upstream_error" in report
