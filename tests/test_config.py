"""Config loading (issue #8): home lookup, drop-ins and strict YAML.

Process-level behaviour (exit codes of ``send``) belongs to #27; here ``config.load`` is called
with a fake gateway whose home is a private temporary directory and whose config file methods
reach the real file system (the same pattern the state directory tests use).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

from ha_notice import config
from ha_notice.config import Config, ConfigError
from ha_notice.gateway import Gateway, HomeLookupError, RealGateway
from ha_notice.output import build_error
from tests.fake_gateway import FakeGateway

FAKE_SECRET = "sk-FAKE-SECRET-0123456789"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    (path / ".config" / "ha-notice").mkdir(parents=True)
    return path


@pytest.fixture
def gw(home: Path) -> FakeGateway:
    return FakeGateway(home=str(home))


def cfg_dir(home: Path) -> Path:
    return home / ".config" / "ha-notice"


def write_main(home: Path, text: str) -> Path:
    path = cfg_dir(home) / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def write_dropin(home: Path, name: str, text: str) -> Path:
    d = cfg_dir(home) / "config.d"
    d.mkdir(exist_ok=True)
    path = d / name
    path.write_text(text, encoding="utf-8")
    return path


def fails(gw: Gateway, path: str | None = None) -> ConfigError:
    with pytest.raises(ConfigError) as info:
        config.load(gw, path)
    return info.value


# --- home lookup -----------------------------------------------------------------------------


def test_default_config_comes_from_the_gateway_home(gw: FakeGateway, home: Path) -> None:
    write_main(home, "service: mobile_app_x\n")
    result = config.load(gw, None)
    assert result.values == {"service": "mobile_app_x"}
    assert result.home == str(home)


def test_a_missing_default_config_means_defaults(gw: FakeGateway) -> None:
    assert config.load(gw, None).values == {}


def test_environment_home_and_xdg_are_not_read(
    gw: FakeGateway, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = tmp_path / "hostile"
    (hostile / "ha-notice").mkdir(parents=True)
    (hostile / "ha-notice" / "config.yaml").write_text("service: hostile\n")
    (hostile / ".config" / "ha-notice").mkdir(parents=True)
    (hostile / ".config" / "ha-notice" / "config.yaml").write_text("service: hostile\n")
    monkeypatch.setenv("HOME", str(hostile))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(hostile))
    write_main(home, "service: from_gateway\n")
    assert config.load(gw, None).values == {"service": "from_gateway"}
    monkeypatch.delenv("HOME")
    monkeypatch.delenv("XDG_CONFIG_HOME")
    assert config.load(gw, None).values == {"service": "from_gateway"}


@pytest.mark.parametrize("path", [None, "", "/nonexistent/config.yaml"])
def test_a_failed_home_lookup_is_key_home_even_with_config(path: str | None) -> None:
    gateway = FakeGateway(home=HomeLookupError("home directory lookup failed"))
    err = fails(gateway, path)
    assert err.key == "home"
    assert err.error.exit_code == 2
    assert err.error.envelope["error"]["details"] == {"key": "home"}


def test_home_lookup_failure_on_the_real_gateway_is_key_home(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pwd

    def missing(uid: int) -> Any:
        raise KeyError(uid)

    monkeypatch.setattr(pwd, "getpwuid", missing)
    assert fails(RealGateway(), None).key == "home"


@pytest.mark.parametrize("bad", ["", "relative/dir", "/nonexistent/home/dir"])
def test_empty_relative_or_missing_real_home_is_key_home(
    bad: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pwd

    class Entry:
        pw_dir = bad

    monkeypatch.setattr(pwd, "getpwuid", lambda uid: Entry())
    assert fails(RealGateway(), None).key == "home"


# --- --config and drop-ins -------------------------------------------------------------------


def test_config_option_reads_that_file_and_its_drop_ins(gw: FakeGateway, tmp_path: Path) -> None:
    other = tmp_path / "elsewhere"
    (other / "config.d").mkdir(parents=True)
    (other / "c.yaml").write_text("service: a\nmax_chars: 200\n")
    (other / "config.d" / "10.yaml").write_text("max_chars: 300\n")
    result = config.load(gw, str(other / "c.yaml"))
    assert result.values == {"service": "a", "max_chars": 300}


def test_default_drop_ins_are_not_read_with_config_option(
    gw: FakeGateway, home: Path, tmp_path: Path
) -> None:
    write_dropin(home, "10.yaml", "service: from_default_dropin\n")
    (tmp_path / "c.yaml").write_text("max_chars: 200\n")
    assert config.load(gw, str(tmp_path / "c.yaml")).values == {"max_chars": 200}


def test_relative_config_option_reads_config_d_beside_it(
    gw: FakeGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "config.d").mkdir()
    (tmp_path / "c.yaml").write_text("max_chars: 200\n")
    (tmp_path / "config.d" / "a.yaml").write_text("log: false\n")
    monkeypatch.chdir(tmp_path)
    assert config.load(gw, "c.yaml").values == {"max_chars": 200, "log": False}


@pytest.mark.parametrize("path", ["", "/nonexistent/dir/c.yaml"])
def test_empty_or_missing_config_option_is_key_dash_dash_config(gw: FakeGateway, path: str) -> None:
    err = fails(gw, path)
    assert err.key == "--config"
    assert err.error.envelope["error"]["details"] == {"key": "--config"}


def test_empty_string_is_not_treated_as_unset(gw: FakeGateway, home: Path) -> None:
    write_main(home, "service: from_default\n")
    assert fails(gw, "").key == "--config"


def test_a_dangling_symlink_config_option_is_missing(gw: FakeGateway, tmp_path: Path) -> None:
    link = tmp_path / "link.yaml"
    link.symlink_to(tmp_path / "gone.yaml")
    assert fails(gw, str(link)).key == "--config"


def test_drop_ins_apply_in_lexical_order_and_maps_merge(gw: FakeGateway, home: Path) -> None:
    write_main(home, "max_chars: 200\nlevel_prefix:\n  warn: 'W:'\n  error: 'E:'\n")
    write_dropin(home, "20-b.yaml", "max_chars: 400\nlevel_prefix:\n  error: 'EE:'\n")
    write_dropin(home, "10-a.yaml", "max_chars: 300\nlog: false\nlevel_prefix:\n  info: 'I:'\n")
    assert config.load(gw, None).values == {
        "max_chars": 400,
        "log": False,
        "level_prefix": {"warn": "W:", "error": "EE:", "info": "I:"},
    }


def test_order_is_by_name_not_by_creation(gw: FakeGateway, home: Path) -> None:
    write_dropin(home, "b.yaml", "max_chars: 111\n")
    write_dropin(home, "a.yaml", "max_chars: 222\n")
    write_dropin(home, "B.yaml", "max_chars: 333\n")  # uppercase sorts before lowercase
    assert config.load(gw, None).values == {"max_chars": 111}


def test_only_yaml_files_not_dot_files_are_drop_ins(gw: FakeGateway, home: Path) -> None:
    write_dropin(home, "a.yaml", "max_chars: 222\n")
    write_dropin(home, "b.yml", "max_chars: 111\n")
    write_dropin(home, "c.yaml.bak", "max_chars: 111\n")
    write_dropin(home, ".hidden.yaml", "max_chars: 111\n")
    write_dropin(home, "notes.txt", "this is { not yaml\n")
    assert config.load(gw, None).values == {"max_chars": 222}


def test_a_drop_in_without_a_main_file(gw: FakeGateway, home: Path) -> None:
    write_dropin(home, "a.yaml", "service: only_dropin\n")
    assert config.load(gw, None).values == {"service": "only_dropin"}


def test_a_drop_in_that_is_a_directory_is_config_invalid_naming_the_path(
    gw: FakeGateway, home: Path
) -> None:
    (cfg_dir(home) / "config.d").mkdir()
    (cfg_dir(home) / "config.d" / "dir.yaml").mkdir()
    assert fails(gw).key == str(cfg_dir(home) / "config.d" / "dir.yaml")


def test_a_dangling_drop_in_symlink_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    d = cfg_dir(home) / "config.d"
    d.mkdir()
    (d / "x.yaml").symlink_to(home / "nowhere")
    assert fails(gw).key == str(d / "x.yaml")


def test_symlinks_to_regular_files_are_followed(
    gw: FakeGateway, home: Path, tmp_path: Path
) -> None:
    target = tmp_path / "real.yaml"
    target.write_text("max_chars: 250\n")
    (cfg_dir(home) / "config.yaml").symlink_to(target)
    d = cfg_dir(home) / "config.d"
    d.mkdir()
    (d / "a.yaml").symlink_to(target)
    assert config.load(gw, None).values == {"max_chars": 250}


def test_config_d_that_is_a_file_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    (cfg_dir(home) / "config.d").write_text("x")
    assert fails(gw).key == str(cfg_dir(home) / "config.d")


def test_too_many_drop_ins_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    d = cfg_dir(home) / "config.d"
    d.mkdir()
    for i in range(300):
        (d / f"{i:04}.yaml").write_text("log: true\n")
    assert fails(gw).key == str(d)


def test_the_error_names_the_file_that_failed(gw: FakeGateway, home: Path) -> None:
    write_main(home, "log: true\n")
    bad = write_dropin(home, "20.yaml", "log: [\n")
    write_dropin(home, "10.yaml", "log: false\n")
    assert fails(gw).key == str(bad)


# --- size, file type -------------------------------------------------------------------------


def test_a_file_of_exactly_65536_bytes_loads(gw: FakeGateway, home: Path) -> None:
    body = "service: a\n"
    write_main(home, body + "#" * (65536 - len(body) - 1) + "\n")
    assert (cfg_dir(home) / "config.yaml").stat().st_size == 65536
    assert config.load(gw, None).values == {"service": "a"}


def test_a_file_of_65537_bytes_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    body = "service: a\n"
    path = write_main(home, body + "#" * (65537 - len(body) - 1) + "\n")
    assert path.stat().st_size == 65537
    assert fails(gw).key == str(path)


def test_a_fifo_config_returns_at_once(gw: FakeGateway, home: Path) -> None:
    fifo = cfg_dir(home) / "config.yaml"
    os.mkfifo(fifo)
    start = time.monotonic()
    err = fails(gw)
    assert time.monotonic() - start < 5
    assert err.key == str(fifo)


def test_a_fifo_config_option_returns_at_once(gw: FakeGateway, tmp_path: Path) -> None:
    fifo = tmp_path / "f.yaml"
    os.mkfifo(fifo)
    assert fails(gw, str(fifo)).key == str(fifo)


def test_a_device_config_is_config_invalid(gw: FakeGateway) -> None:
    assert fails(gw, "/dev/zero").key == "/dev/zero"


def test_a_directory_config_option_is_config_invalid(gw: FakeGateway, tmp_path: Path) -> None:
    assert fails(gw, str(tmp_path)).key == str(tmp_path)


def test_an_unreadable_file_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    path = write_main(home, "log: true\n")
    path.chmod(0)
    if os.access(path, os.R_OK):  # running as root
        pytest.skip("permissions are not enforced")
    assert fails(gw).key == str(path)


def test_a_path_with_a_nul_byte_is_config_invalid(gw: FakeGateway) -> None:
    err = fails(gw, "a\x00b")
    assert err.key == "?"
    assert err.error.envelope["error"]["details"]["key"] in ("--config", "?")


def test_a_non_utf8_file_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    path = cfg_dir(home) / "config.yaml"
    path.write_bytes(b"service: \xff\xfe\n")
    assert fails(gw).key == str(path)


def test_utf16_is_not_sniffed(gw: FakeGateway, home: Path) -> None:
    path = cfg_dir(home) / "config.yaml"
    path.write_bytes("service: a\n".encode("utf-16"))
    assert fails(gw).key == str(path)


# --- strict YAML: the loader table -----------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "enabled: no\n",
        "enabled: off\n",
        "enabled: yes\n",
        "enabled: on\n",
        "enabled: True\n",
        "enabled: TRUE\n",
        "enabled: 1\n",
        "enabled: 'true'\n",
        "enabled:\n",
        "enabled: ~\n",
        "log: no\n",
        "allow_insecure_http: yes\n",
        "max_chars: 010\n",
        "max_chars: 0x10\n",
        "max_chars: 0o10\n",
        "max_chars: 1_0\n",
        "max_chars: 1:30\n",
        "max_chars: 1e3\n",
        "max_chars: 150.0\n",
        "max_chars: .inf\n",
        "max_chars: -.inf\n",
        "max_chars: .nan\n",
        "max_chars: true\n",
        "max_chars: '300'\n",
        "max_chars: +300\n",
        "max_chars: 300.\n",
        "max_chars: .5\n",
        "timeout: true\n",
        "timeout: [1]\n",
        "timeout: {a: 1}\n",
        "timeout: " + "9" * 400 + ".5\n",
        "service: 5\n",
        "service: [a]\n",
        "service: true\n",
        "token_env: 5\n",
        "base_url: 1.5\n",
        "ca_file: [a]\n",
        "default_group: 7\n",
        "link_hosts: a.example.com\n",
        "link_hosts: [1]\n",
        "link_hosts: [[a]]\n",
        "link_hosts: [{a: b}]\n",
        "level_prefix: x\n",
        "level_prefix: [a]\n",
        "level_prefix: {info: 1}\n",
        "level_prefix: {info: [a]}\n",
        "level_prefix: {nope: 'x'}\n",
        "level_prefix: {info: ''}\nlevel_prefix: {warn: ''}\n",  # duplicate key
        "- a\n- b\n",
        "scalar\n",
        "5\n",
        "null\n",
        "",
        "# only a comment\n",
        "---\n",
        "a: 1\n---\nb: 2\n",
    ],
)
def test_strict_loader_table_is_config_invalid(gw: FakeGateway, home: Path, text: str) -> None:
    path = write_main(home, text)
    err = fails(gw)
    assert err.key in (str(path), *config.KNOWN_KEYS)
    assert err.error.exit_code == 2


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("enabled: true\n", {"enabled": True}),
        ("enabled: false\n", {"enabled": False}),
        ("timeout: 10\n", {"timeout": 10}),
        ("timeout: 1.5\n", {"timeout": 1.5}),
        ("timeout: 0\n", {"timeout": 0}),
        ("timeout: -1\n", {"timeout": -1}),
        ("timeout: 2s\n", {"timeout": "2s"}),
        ("timeout: '500ms'\n", {"timeout": "500ms"}),
        ("max_chars: 1000\n", {"max_chars": 1000}),
        ("service: mobile_app_x\n", {"service": "mobile_app_x"}),
        ("service: 'true'\n", {"service": "true"}),
        ("service: no\n", {"service": "no"}),  # stays the string "no"
        ("service: 010\n", {"service": "010"}),
        ("service: 2001-01-01\n", {"service": "2001-01-01"}),
        ("base_url: https://h.example:8123\n", {"base_url": "https://h.example:8123"}),
        (
            "link_hosts: [a.example.org, b.example.org]\n",
            {"link_hosts": ["a.example.org", "b.example.org"]},
        ),
        ("level_prefix: {info: '', warn: 'W:'}\n", {"level_prefix": {"info": "", "warn": "W:"}}),
        ("level_prefix:\n  info: ''\n", {"level_prefix": {"info": ""}}),
        ("# comment\nlog: false # trailing\n", {"log": False}),
        ("﻿log: false\n", {"log": False}),
        ("service: &a x\n", {"service": "x"}),  # an anchor without an alias is harmless
        ('service: "café"\n', {"service": "café"}),
    ],
)
def test_strict_loader_accepts(
    gw: FakeGateway, home: Path, text: str, expected: dict[str, Any]
) -> None:
    write_main(home, text)
    values = config.load(gw, None).values
    assert values == expected
    assert [type(v) for v in values.values()] == [type(v) for v in expected.values()]


@pytest.mark.parametrize(
    "value", ["1:30", "010", "0x10", "1_0", ".inf", "-.inf", ".nan", "1e3", "no", "2001-01-01"]
)
@pytest.mark.parametrize("key", ["timeout", "connect_timeout"])
def test_non_decimal_duration_spellings_stay_strings(
    gw: FakeGateway, home: Path, key: str, value: str
) -> None:
    # The loader leaves them strings; the duration grammar (TODO(#9)) is what refuses them.
    write_main(home, f"{key}: {value}\n")
    assert config.load(gw, None).values == {key: value}


def test_booleans_are_never_numbers(gw: FakeGateway, home: Path) -> None:
    write_main(home, "max_chars: true\n")
    assert fails(gw).key == "max_chars"


def test_a_number_key_given_a_string_names_the_key(gw: FakeGateway, home: Path) -> None:
    write_main(home, "max_chars: '300'\n")
    assert fails(gw).key == "max_chars"


def test_duplicate_yaml_key_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    path = write_main(home, "log: true\nlog: false\n")
    assert fails(gw).key == str(path)


def test_duplicate_key_across_files_is_not_a_duplicate(gw: FakeGateway, home: Path) -> None:
    write_main(home, "log: true\n")
    write_dropin(home, "a.yaml", "log: false\n")
    assert config.load(gw, None).values == {"log": False}


def test_a_duplicate_unknown_key_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    path = write_main(home, "x: 1\nx: 2\n")
    assert fails(gw).key == str(path)


def test_merge_keys_are_not_supported(gw: FakeGateway, home: Path) -> None:
    path = write_main(home, "base: &b {log: false}\n<<: *b\n")
    assert fails(gw).key == str(path)  # the alias is refused
    write_main(home, "<<: {log: false}\n")
    assert fails(gw).key == "?"  # "<<" is an ordinary unknown key


@pytest.mark.parametrize(
    "text",
    [
        "log: !!python/object/apply:os.system ['echo x']\n",
        "log: !!python/name:os.system\n",
        "service: !!binary YQ==\n",
        "service: !!set {a}\n",
        "service: !!omap [a: 1]\n",
        "service: !!timestamp 2001-01-01\n",
        "log: !!bool yes\n",
        "max_chars: !!int 0x10\n",
        "max_chars: !!int 010\n",
        "max_chars: !!float 1e3\n",
        "timeout: !!float .inf\n",
        "log: !custom x\n",
        "? [a]\n: b\n",
        "? {a: b}\n: c\n",
        "? !!set {a}\n: c\n",
        "x: *missing\n",
        "service: *a\n",
        "&a log: false\n*a : true\n",
    ],
)
def test_tags_and_hostile_constructs_are_config_invalid(
    gw: FakeGateway, home: Path, text: str
) -> None:
    write_main(home, text)
    assert fails(gw).error.exit_code == 2


def test_tags_do_not_run_code(gw: FakeGateway, home: Path, tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    write_main(
        home,
        "log: !!python/object/apply:pathlib.Path.touch "
        f"[!!python/object/apply:pathlib.Path [{marker}]]\n",
    )
    fails(gw)
    assert not marker.exists()


def test_anchors_with_aliases_are_refused(gw: FakeGateway, home: Path) -> None:
    write_main(home, "level_prefix: &p {info: ''}\nx: *p\n")
    assert fails(gw).error.exit_code == 2


def test_empty_values_and_nulls_for_known_keys_are_refused(gw: FakeGateway, home: Path) -> None:
    write_main(home, "service:\n")
    assert fails(gw).key == "service"


# --- hostile inputs --------------------------------------------------------------------------


def test_deeply_nested_brackets_are_config_invalid(gw: FakeGateway, home: Path) -> None:
    path = write_main(home, "[" * 1000 + "\n")
    start = time.monotonic()
    assert fails(gw).key == str(path)
    assert time.monotonic() - start < 10


@pytest.mark.parametrize("depth", [100, 5000, 30000])
def test_deep_nesting_under_a_key_is_config_invalid(
    gw: FakeGateway, home: Path, depth: int
) -> None:
    write_main(home, "x: " + "[" * depth + "]" * depth + "\n")
    # an unknown key: refused, whether or not the parser could go that deep
    assert fails(gw).error.exit_code == 2


def test_deep_flow_mapping_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    write_main(home, "{a: " * 2000 + "1" + "}" * 2000 + "\n")
    assert fails(gw).error.exit_code == 2


def test_an_alias_bomb_is_config_invalid_and_fast(gw: FakeGateway, home: Path) -> None:
    lines = ['a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]']
    prev = "a"
    for letter in "bcdefgh":
        lines.append(f"{letter}: &{letter} [" + ",".join(f"*{prev}" for _ in range(9)) + "]")
        prev = letter
    text = "\n".join(lines) + "\n"
    assert len(text.encode()) < 700
    write_main(home, text)
    start = time.monotonic()
    fails(gw)
    assert time.monotonic() - start < 5


def test_the_documented_413_byte_alias_bomb(gw: FakeGateway, home: Path) -> None:
    text = (
        "a: &a [x,x,x,x,x,x,x,x,x]\n"
        + "".join(
            f"{n}: &{n} [{','.join('*' + p for _ in range(9))}]\n"
            for n, p in zip("bcdefgh", "abcdefg", strict=True)
        )
        + "i: *h\n"
    )
    write_main(home, text)
    start = time.monotonic()
    fails(gw)
    assert time.monotonic() - start < 5


def test_a_recursive_alias_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    write_main(home, "&a [*a]\n")
    assert fails(gw).error.exit_code == 2


def test_a_huge_integer_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    write_main(home, "max_chars: " + "9" * 5000 + "\n")
    assert fails(gw).error.exit_code == 2


def test_recursion_error_and_memory_error_from_the_parser_are_config_invalid(
    gw: FakeGateway, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yaml

    path = write_main(home, "log: true\n")
    for exc in (RecursionError, MemoryError, ValueError, OverflowError, RuntimeError):

        def boom(self: Any, exc: type[BaseException] = exc) -> Any:
            raise exc("secret " + FAKE_SECRET)

        monkeypatch.setattr(yaml.SafeLoader, "get_single_node", boom)
        monkeypatch.setattr(config._StrictLoader, "get_single_node", boom)  # pyright: ignore
        err = fails(gw)
        assert err.key == str(path)
        assert FAKE_SECRET not in repr(err) + str(err)


def test_a_yaml_error_that_would_quote_a_secret_never_surfaces(
    gw: FakeGateway, home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for text in (
        f'token: "{FAKE_SECRET}\n',
        f"token: {FAKE_SECRET}: {FAKE_SECRET}: x\n",
        f"a: [{FAKE_SECRET}\n",
        f"{FAKE_SECRET}\t: 1\n",
        f"- {FAKE_SECRET}\nx: 1\n",
        f"? {FAKE_SECRET}\n: [\n",
        f"log: !!{FAKE_SECRET} x\n",
        f"a: {FAKE_SECRET}\n\x00",
    ):
        write_main(home, text)
        err = fails(gw)
        shown = [
            str(err),
            repr(err),
            json.dumps(err.error.envelope),
            repr(err.args),
            repr(err.__cause__),
            repr(err.__context__),
        ]
        assert not any(FAKE_SECRET in s for s in shown), text
        assert err.__cause__ is None
        assert err.__context__ is None
    out = capsys.readouterr()
    assert FAKE_SECRET not in out.out + out.err


def test_a_secret_in_a_bad_value_of_a_known_key_is_not_echoed(gw: FakeGateway, home: Path) -> None:
    write_main(home, f"max_chars: {FAKE_SECRET}\n")
    err = fails(gw)
    assert err.key == "max_chars"
    assert FAKE_SECRET not in json.dumps(err.error.envelope) + str(err) + repr(err)


# --- unknown keys ----------------------------------------------------------------------------


def test_an_unknown_key_is_refused_by_name(gw: FakeGateway, home: Path) -> None:
    write_main(home, "servce: x\n")
    err = fails(gw)
    assert err.key == "servce"
    assert err.error.envelope["error"]["details"] == {"key": "servce"}


def test_an_unknown_key_of_5000_characters_is_question_mark(gw: FakeGateway, home: Path) -> None:
    write_main(home, "? " + "a" * 5000 + "\n: 1\n")
    err = fails(gw)
    assert err.key == "?"
    assert err.error.envelope["error"]["details"] == {"key": "?"}


@pytest.mark.parametrize(
    "key",
    [
        "has space",
        "https://h.example/?t=" + FAKE_SECRET,
        "café",
        "a-b",
        "a" * 65,
        "line\\nbreak",
        "'multi\\nline'",
        "'tab\\there'",
        "1",
        "true",
        "~",
        "<<",
        "'\\u202e'",
    ],
)
def test_an_unusual_unknown_key_is_never_echoed(gw: FakeGateway, home: Path, key: str) -> None:
    write_main(home, f"{key}: 1\n")
    err = fails(gw)
    assert err.key == "?"
    assert FAKE_SECRET not in json.dumps(err.error.envelope)


def test_a_64_character_plain_unknown_key_is_named(gw: FakeGateway, home: Path) -> None:
    write_main(home, "k" * 64 + ": 1\n")
    assert fails(gw).key == "k" * 64


def test_an_unknown_key_is_refused_before_its_value_is_examined(
    gw: FakeGateway, home: Path
) -> None:
    write_main(home, "zzz: " + "[" * 50 + "]" * 50 + "\n")
    assert fails(gw).key == "zzz"
    write_main(home, f"zzz: {FAKE_SECRET}\nmax_chars: oops\n")
    assert fails(gw).key == "zzz"


def test_an_unknown_key_in_a_drop_in_is_refused(gw: FakeGateway, home: Path) -> None:
    write_main(home, "log: true\n")
    write_dropin(home, "a.yaml", "nope: 1\n")
    assert fails(gw).key == "nope"


def test_unknown_level_prefix_member_names_level_prefix(gw: FakeGateway, home: Path) -> None:
    write_main(home, "level_prefix: {debug: 'D:'}\n")
    assert fails(gw).key == "level_prefix"


def test_a_non_string_unknown_key_is_question_mark(gw: FakeGateway, home: Path) -> None:
    write_main(home, "5: x\n")
    assert fails(gw).key == "?"


def test_the_known_keys_are_exactly_the_documented_ones() -> None:
    assert set(config.KNOWN_KEYS) == {
        "enabled",
        "base_url",
        "service",
        "token_env",
        "allow_insecure_http",
        "ca_file",
        "link_hosts",
        "level_prefix",
        "default_group",
        "max_chars",
        "timeout",
        "connect_timeout",
        "log",
    }


def test_known_keys_match_the_schema() -> None:
    schema = json.loads(
        (Path(__file__).resolve().parent.parent / "schemas" / "config.json").read_text()
    )
    assert set(config.KNOWN_KEYS) == set(schema["properties"])


# --- the shipped example ---------------------------------------------------------------------


def test_the_example_config_loads(gw: FakeGateway, home: Path) -> None:
    example = Path(__file__).resolve().parent.parent / "config.example.yaml"
    write_main(home, example.read_text(encoding="utf-8"))
    values = config.load(gw, None).values
    assert values["enabled"] is True
    assert values["timeout"] == "10s"
    assert values["max_chars"] == 1000
    assert values["level_prefix"]["warn"] == "WARN:"


# --- result and error objects ----------------------------------------------------------------


def test_load_does_not_read_the_environment_or_the_token(
    gw: FakeGateway, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HA_TOKEN", FAKE_SECRET)
    write_main(home, "token_env: HA_TOKEN\n")
    result = config.load(gw, None)
    assert FAKE_SECRET not in repr(result)


def test_config_error_builds_the_standard_envelope(gw: FakeGateway, home: Path) -> None:
    write_main(home, "nope: 1\n")
    err = fails(gw)
    expected = build_error("config_invalid", key="nope")
    assert err.error == expected
    assert err.error.envelope["error"]["code"] == "config_invalid"


def test_the_loaded_values_are_not_shared_with_the_files(gw: FakeGateway, home: Path) -> None:
    write_main(home, "level_prefix: {info: 'I:'}\n")
    first = config.load(gw, None)
    assert isinstance(first, Config)
    first.values["level_prefix"]["info"] = "changed"
    assert config.load(gw, None).values["level_prefix"]["info"] == "I:"


def test_the_two_levels_of_a_merge_do_not_alias_between_files(gw: FakeGateway, home: Path) -> None:
    write_main(home, "level_prefix: {info: 'I:'}\n")
    write_dropin(home, "a.yaml", "level_prefix: {warn: 'W:'}\n")
    assert config.load(gw, None).values == {"level_prefix": {"info": "I:", "warn": "W:"}}


# --- gateway file methods --------------------------------------------------------------------


def test_real_read_config_returns_none_only_for_a_missing_file(tmp_path: Path) -> None:
    real = RealGateway()
    assert real.read_config(str(tmp_path / "nope"), 100) is None
    (tmp_path / "f").write_bytes(b"abc")
    assert real.read_config(str(tmp_path / "f"), 100) == b"abc"
    assert real.read_config(str(tmp_path / "f"), 3) == b"abc"


def test_real_read_config_rejects_over_cap_and_irregular(tmp_path: Path) -> None:
    from ha_notice.gateway import SourceError

    real = RealGateway()
    (tmp_path / "f").write_bytes(b"abcd")
    with pytest.raises(SourceError):
        real.read_config(str(tmp_path / "f"), 3)
    with pytest.raises(SourceError):
        real.read_config(str(tmp_path), 100)
    with pytest.raises(SourceError):
        real.read_config("/dev/zero", 100)


def test_real_list_config_dir(tmp_path: Path) -> None:
    from ha_notice.gateway import SourceError

    real = RealGateway()
    assert real.list_config_dir(str(tmp_path / "missing")) == []
    (tmp_path / "b.yaml").write_text("")
    (tmp_path / "a.yaml").write_text("")
    (tmp_path / ".c.yaml").write_text("")
    (tmp_path / "d.txt").write_text("")
    assert real.list_config_dir(str(tmp_path)) == ["a.yaml", "b.yaml"]
    with pytest.raises(SourceError):
        real.list_config_dir(str(tmp_path / "a.yaml"))
