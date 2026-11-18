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
import subprocess
import sys
from pathlib import Path

import pytest

from tests.fake_ha import FakeHA, Reply
from tests.live import support
from tests.live.checklist import ITEMS, settles
from tests.live.support import CommandsNotAllowed, CommandWordRefused, LiveConfig

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
    assert ITEMS[item] in LIVE_SECTION, f"{item}: {ITEMS[item]!r} not in design.md Live verification"


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
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", f"--basetemp={tmp / 'bt'}", *args],
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
    ],
)
def test_config_refuses_a_bad_environment(mutation: dict[str, str], fragment: str) -> None:
    cfg, reason = LiveConfig.from_env(_env(**mutation))
    assert cfg is None and fragment in reason
    assert TOKEN not in reason


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
        reply = support.send_command_word(_config(ha.base_url, LIVE_HA_ALLOW_COMMANDS="1"), "tts", "t")
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


def _inner(tmp: Path, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    full = {"LIVE_HA_PAUSE": "0", "LIVE_HA_TIMEOUT": "2s", "HA_LIVE_TOKEN": TOKEN}
    full.update(env)
    full["LIVE_HA_TOKEN_ENV"] = "HA_LIVE_TOKEN"
    full["LIVE_HA_SERVICE"] = SERVICE
    return _pytest(tmp, ["-m", "live", "-s", "-rs", "-q", *args], **full)


def _titles(ha: FakeHA) -> list[str]:
    out: list[str] = []
    for request in ha.requests:
        if request.method == "POST":
            body = json.loads(request.body)
            out.append(str(body.get("title", "")))
    return out


def test_live_tests_run_against_the_fake_home_assistant(tmp_path: Path) -> None:
    from tests.live.test_live_commands import FAMILY_WORDS

    with (
        FakeHA(token=TOKEN, services={SERVICE, "other"}) as ha,
        FakeHA(token=TOKEN, prefix="p", services={SERVICE}) as prefixed,
        FakeHA(script=[Reply(stall_before_read=True)]) as stalled,
    ):
        done = _inner(
            tmp_path,
            ["tests/live"],
            {
                "LIVE_HA_BASE_URL": ha.base_url,
                "LIVE_HA_ALLOW_INSECURE_HTTP": "1",
                "LIVE_HA_PREFIX_BASE_URL": prefixed.base_url + "/p",
                "LIVE_HA_OTHER_SERVICE": "other",
                "LIVE_HA_BLACKHOLE_URL": stalled.base_url,
            },
        )
        report = done.stdout + done.stderr
        assert done.returncode == 0, report
        assert "13 passed, 2 skipped" in report, report
        assert "opt-in only" in report and "needs an https LIVE_HA_BASE_URL" in report
        assert TOKEN not in report
        # instructions are printed, numbered, with the item and the run marker
        assert "WHAT YOU SHOULD SEE ON THE PHONE:" in report and "  1. " in report
        assert "[settles V20]" in report and "ha-notice live test " in report
        # no command word reached the fake without the opt-in
        sent = [json.loads(r.body).get("message") for r in ha.requests if r.method == "POST"]
        assert not [m for m in sent if m in FAMILY_WORDS]
        # the tag test: two sends, one tag
        tagged = [json.loads(r.body) for r in ha.requests if r.method == "POST"]
        tags = [b["data"]["tag"] for b in tagged if "data" in b and "tag" in b["data"]]
        assert len(tags) == 2 and tags[0] == tags[1]
        # the link test: url and clickAction both
        links = [b["data"] for b in tagged if "data" in b and "url" in b["data"]]
        assert len(links) == 1 and links[0]["clickAction"] == links[0]["url"]
        # markup sent literally; every title carries the unique marker except the test message
        assert any(b.get("message") == '<b>x</b> <a href="https://example.org">y</a>' for b in tagged)
        assert all(
            t.startswith("ha-notice live test ") or t == "ha-notice" for t in _titles(ha)
        ), _titles(ha)
        # the prefixed fake got the probe and one send; the stalled one got the dummy token only
        assert [r.method for r in prefixed.requests] == ["GET", "POST"]
        assert all(TOKEN.encode() not in raw for raw in stalled.received)


def test_self_signed_and_command_tests_run_against_a_tls_fake(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    from tests.live.test_live_commands import FAMILY_WORDS

    cert, key = self_signed_cert
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key, services={SERVICE}) as ha:
        done = _inner(
            tmp_path,
            ["tests/live", "-k", "self_signed or command_word"],
            {
                "LIVE_HA_BASE_URL": ha.base_url,
                "LIVE_HA_CA_FILE": str(cert),
                "LIVE_HA_ALLOW_COMMANDS": "1",
            },
        )
        report = done.stdout + done.stderr
        assert done.returncode == 0, report
        assert "2 passed" in report and TOKEN not in report
        assert "SENDING COMPANION-APP COMMAND WORDS" in report
        messages = [json.loads(r.body).get("message") for r in ha.requests if r.method == "POST"]
        assert [m for m in messages if m in FAMILY_WORDS] == list(FAMILY_WORDS)
        assert re.fullmatch(r"[0-9a-f]{6}: update_widgets", str(messages[-1]))
