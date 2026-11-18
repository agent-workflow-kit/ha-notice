"""An unknown config key is never printed (issue #74).

``details.key`` is ``?`` for an unknown key, whatever its name; the name reaches no envelope, no
stdout, no stderr, no log record and no exception text. Known keys keep naming themselves.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ha_notice import config
from ha_notice.cli import main
from ha_notice.config import KNOWN_KEYS, ConfigError
from tests.fake_gateway import FakeGateway, private_home
from tests.harness import schema_errors

FAKE = "HA_FAKE_TOKEN_abcdef123456"
BASE = "base_url: https://ha.example\nservice: mobile_app_x\n"
WRAPPER = """
import os, sys
from ha_notice.cli import main
from ha_notice.gateway import RealGateway

class Gateway(RealGateway):
    def home_dir(self):
        return os.environ["HA_NOTICE_TEST_HOME"]

sys.exit(main(None, None, Gateway()))
"""


def dq(text: str) -> str:
    return '"' + "".join(f"\\U{ord(c):08x}" for c in text) + '"'


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = Path(private_home(tmp_path))
    (path / ".config" / "ha-notice" / "config.d").mkdir(parents=True)
    return path


def main_file(home: Path) -> Path:
    return home / ".config" / "ha-notice" / "config.yaml"


def fail(home: Path) -> ConfigError:
    with pytest.raises(ConfigError) as info:
        config.load(FakeGateway(home=str(home)), None)
    return info.value


def tree_text(home: Path) -> bytes:
    """Every byte under the home (config files excluded): the state directory and its log."""
    chunks = []
    for path in home.rglob("*"):
        if path.is_file() and ".config" not in path.parts:
            chunks.append(path.read_bytes())
    return b"".join(chunks)


# --- the key never reaches a result ----------------------------------------------------------

HOSTILE = [
    pytest.param(FAKE, id="token-shaped"),
    pytest.param("k" * 5000, id="5000-chars"),
    pytest.param("a" * 64, id="64-chars"),
    pytest.param("x_ünï", id="unicode"),
]


@pytest.mark.parametrize("name", [n for n in (FAKE, "k" * 64, "plain_unknown", "level")])
def test_an_unknown_key_is_a_question_mark(home: Path, name: str) -> None:
    main_file(home).write_text(f"{BASE}{name}: 1\n", encoding="utf-8")
    err = fail(home)
    assert err.key == "?"
    assert err.error.envelope["error"]["details"] == {"key": "?"}


@pytest.mark.parametrize("name", ["k" * 5000, "a\u0007b", "a\nb", "a\x1b[31mb", "é", "", " "])
def test_a_hostile_unknown_key_is_a_question_mark(home: Path, name: str) -> None:
    # An explicit key (``? key``): an implicit key of over 1024 characters is a YAML error.
    main_file(home).write_text(f"{BASE}? {dq(name)}\n: 1\n", encoding="utf-8")
    assert fail(home).key == "?"


def test_an_implicit_5000_character_key_is_a_file_error_not_the_name(home: Path) -> None:
    path = main_file(home)
    path.write_text(f"{BASE}{'k' * 5000}: 1\n", encoding="utf-8")
    assert fail(home).key == str(path)


def test_a_non_string_unknown_key_is_a_question_mark(home: Path) -> None:
    main_file(home).write_text(f"{BASE}5: 1\n", encoding="utf-8")
    assert fail(home).key == "?"


def test_an_unknown_key_in_a_drop_in_is_a_question_mark(home: Path) -> None:
    main_file(home).write_text(BASE, encoding="utf-8")
    drop = home / ".config" / "ha-notice" / "config.d" / "10-extra.yaml"
    drop.write_text(f"{FAKE}: secret-value\n", encoding="utf-8")
    err = fail(home)
    assert err.key == "?"


def test_an_unknown_level_prefix_member_names_level_prefix_only(home: Path) -> None:
    main_file(home).write_text(f"{BASE}level_prefix:\n  {FAKE}: 'x'\n", encoding="utf-8")
    assert fail(home).key == "level_prefix"


def test_an_unknown_key_is_refused_before_a_known_key_problem(home: Path) -> None:
    main_file(home).write_text(f"{BASE}timeout: nope\n{FAKE}: 1\n", encoding="utf-8")
    assert fail(home).key == "?"


BAD_VALUES = {
    "enabled": "5",
    "base_url": "5",
    "service": "5",
    "token_env": "5",
    "allow_insecure_http": "5",
    "ca_file": "5",
    "link_hosts": "5",
    "level_prefix": "5",
    "default_group": "5",
    "max_chars": "x",
    "timeout": "[]",
    "connect_timeout": "[]",
    "log": "5",
}


def test_the_bad_value_table_covers_every_known_key() -> None:
    assert set(BAD_VALUES) == set(KNOWN_KEYS)


@pytest.mark.parametrize("name", KNOWN_KEYS)
def test_a_known_key_still_names_itself(home: Path, name: str) -> None:
    main_file(home).write_text(f"{name}: {BAD_VALUES[name]}\n", encoding="utf-8")
    assert fail(home).key == name


def test_a_file_path_key_is_kept(home: Path) -> None:
    path = main_file(home)
    path.write_text("a: [\n", encoding="utf-8")
    assert fail(home).key == str(path)


@pytest.mark.parametrize("name", [FAKE, "k" * 5000, "a\u0007b"])
def test_the_exception_carries_no_key_name(home: Path, name: str) -> None:
    main_file(home).write_text(f"{BASE}{dq(name)}: 1\n", encoding="utf-8")
    err = fail(home)
    seen = [str(err), repr(err), repr(err.args), repr(err.error), repr(err.__dict__)]
    seen += [repr(err.__cause__), repr(err.__context__)]
    assert err.__cause__ is None and err.__context__ is None
    for text in seen:
        assert name not in text and FAKE not in text


# --- the key reaches no output ---------------------------------------------------------------


@pytest.mark.parametrize("command", [["send", "--message", "hi"], ["validate"], ["send", "--dry-run", "--message", "hi"]])
@pytest.mark.parametrize("as_json", [True, False])
def test_the_name_is_in_no_stream_or_log(
    home: Path, capsys: pytest.CaptureFixture[str], command: list[str], as_json: bool
) -> None:
    path = main_file(home)
    path.write_text(f"{BASE}{FAKE}: 1\n", encoding="utf-8")
    argv = (["--json"] if as_json else []) + ["--config", str(path), *command]
    code = main(argv, {"HA_TOKEN": "HA_SECRET_x"}, FakeGateway(home=str(home)))
    out = capsys.readouterr()
    assert code == 2
    assert FAKE not in out.out and FAKE not in out.err
    assert FAKE.encode() not in tree_text(home)
    if as_json:
        body = json.loads(out.out)
        assert schema_errors("cli/error", body) == []
        assert body["error"]["code"] == "config_invalid"
        assert body["error"]["details"] == {"key": "?"}


def test_the_name_in_a_drop_in_is_in_no_stream(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    main_file(home).write_text(BASE, encoding="utf-8")
    drop = home / ".config" / "ha-notice" / "config.d" / "10-extra.yaml"
    drop.write_text(f"{FAKE}: 1\n", encoding="utf-8")
    code = main(["--json", "send", "--message", "hi"], {}, FakeGateway(home=str(home)))
    out = capsys.readouterr()
    assert code == 2 and FAKE not in out.out + out.err
    assert json.loads(out.out)["error"]["details"] == {"key": "?"}


@pytest.mark.parametrize("args", [["--json", "send", "--message", "hi"], ["validate"]])
def test_a_real_process_never_prints_the_name(home: Path, args: list[str]) -> None:
    path = main_file(home)
    path.write_text(f"{BASE}{FAKE}: 1\n", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HA_NOTICE_TEST_HOME": str(home),
        "HOME": str(home),
        "LC_ALL": "C",
    }
    proc = subprocess.run(
        [sys.executable, "-c", WRAPPER, "--config", str(path), *args],
        capture_output=True,
        timeout=60,
        check=False,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 2
    assert FAKE.encode() not in proc.stdout + proc.stderr
    assert FAKE.encode() not in tree_text(home)
    if "--json" in args:
        assert json.loads(proc.stdout)["error"]["details"] == {"key": "?"}
