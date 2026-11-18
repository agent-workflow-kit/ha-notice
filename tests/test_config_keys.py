"""Config keys (issue #9): durations, level_prefix, default_group, max_chars and defaults.

Every case goes through ``config.load`` on a real file, like the loader tests in test_config.py.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

import pytest
import yaml

from ha_notice import config
from ha_notice.config import ConfigError
from ha_notice.gateway import Gateway
from tests.fake_gateway import FakeGateway
from tests.harness import schema_errors

ROOT = Path(__file__).resolve().parent.parent
FAKE_SECRET = "sk-FAKE-SECRET-0123456789"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    (path / ".config" / "ha-notice").mkdir(parents=True)
    return path


@pytest.fixture
def gw(home: Path) -> FakeGateway:
    return FakeGateway(home=str(home))


def write(home: Path, text: str) -> Path:
    path = home / ".config" / "ha-notice" / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def dq(value: str) -> str:
    """A YAML double-quoted scalar with every character escaped (``\\U0000XXXX``), so control and
    noncharacter code points reach the key checks instead of the YAML reader's own refusal."""
    return '"' + "".join(f"\\U{ord(c):08x}" for c in value) + '"'


def fails(gw: Gateway) -> ConfigError:
    with pytest.raises(ConfigError) as info:
        config.load(gw, None)
    return info.value


def loads(gw: Gateway, home: Path, text: str) -> config.Config:
    write(home, text)
    return config.load(gw, None)


# --- durations -------------------------------------------------------------------------------

TIMEOUT_GOOD = [
    ("10", 10),
    ("1", 1),
    ("120", 120),
    ("1.5", 1.5),
    ("119.999", 119.999),
    ("120.0", 120),
    ("10s", 10),
    ("'10s'", 10),
    ("1m", 60),
    ("2m", 120),
    ("0.5m", 30),
    ("1000ms", 1),
    ("1500ms", 1.5),
    ("120000ms", 120),
    ("1.0s", 1),
    ("1.0", 1),
]
TIMEOUT_BAD = [
    "0",
    "0s",
    "-1",
    "-0",
    "-1.5",
    "0.999",
    "'0.9999999999999999999999'",  # a float would round this up to 1
    "500ms",
    "999ms",
    "'500ms'",
    "121",
    "120.001",
    "'120.0000000000000000001'",
    "1h",
    "'1h'",
    "2m1s",
    "1e3",
    "'1e3'",
    "1:30",
    "010",
    "'010'",  # a leading zero: refused even quoted (the tool is narrower than the schema)
    "'00010s'",
    "'01.5s'",
    "0x10",
    "1_0",
    ".inf",
    "-.inf",
    ".nan",
    "true",
    "false",
    "'true'",
    "null",
    "~",
    "''",
    "' '",
    "' 10s'",
    "'10s '",
    "'10 s'",
    "'10S'",
    "'10M'",
    "'10MS'",
    "'+10s'",
    "'-10s'",
    "'.5s'",
    "'5.s'",
    "'5.'",
    "'1,5s'",
    "'1\\n'",
    "'10s\\n'",
    "'\\n10s'",
    "'１０s'",  # fullwidth digits
    "'١٠s'",  # Arabic-Indic digits
    "'²'",
    "'10sec'",
    "'ms'",
    "'s'",
    "[10]",
    "{a: 1}",
    "'" + "9" * 400 + "'",
    "'1" + "0" * 5000 + "s'",
    "9" * 400,  # a huge int
    "-" + "9" * 400,
    "1e400",
    "2001-01-01",
]


@pytest.mark.parametrize("key", ["timeout", "connect_timeout"])
@pytest.mark.parametrize("text", ["1:30", "010", "0x10", "1_0", "1e3", ".inf", ".nan"])
def test_non_decimal_duration_spellings_are_config_invalid(
    gw: FakeGateway, home: Path, key: str, text: str
) -> None:
    # The acceptance note from #8: the loader leaves these strings, the grammar refuses them.
    write(home, f"{key}: {text}\n")
    err = fails(gw)
    assert err.key == key
    assert err.error.exit_code == 2


@pytest.mark.parametrize(("text", "seconds"), TIMEOUT_GOOD)
def test_timeout_accepts(gw: FakeGateway, home: Path, text: str, seconds: float) -> None:
    cfg = loads(gw, home, f"timeout: {text}\n")
    assert cfg.timeout == pytest.approx(seconds)
    assert type(cfg.timeout) is float


@pytest.mark.parametrize("text", TIMEOUT_BAD)
def test_timeout_refuses(gw: FakeGateway, home: Path, text: str) -> None:
    write(home, f"timeout: {text}\n")
    err = fails(gw)
    assert err.key == "timeout"


@pytest.mark.parametrize(
    ("text", "ok"),
    [
        ("1", True),
        ("30", True),
        ("30s", True),
        ("0.5m", True),
        ("30000ms", True),
        ("0.5", False),
        ("500ms", False),
        ("31", False),
        ("30.0001", False),
        ("1m", False),  # 60 s
        ("true", False),
        ("1h", False),
    ],
)
def test_connect_timeout_range(gw: FakeGateway, home: Path, text: str, ok: bool) -> None:
    write(home, f"connect_timeout: {text}\n")
    if ok:
        assert config.load(gw, None).connect_timeout <= 30
    else:
        assert fails(gw).key == "connect_timeout"


def test_the_literal_true_is_not_a_duration_but_the_string_trueish_is_refused_too(
    gw: FakeGateway, home: Path
) -> None:
    for text in ("true", "trueish"):
        write(home, f"timeout: {text}\n")
        assert fails(gw).key == "timeout"


def test_each_duration_key_is_checked_in_a_drop_in_too(gw: FakeGateway, home: Path) -> None:
    write(home, "timeout: 10\n")
    d = home / ".config" / "ha-notice" / "config.d"
    d.mkdir()
    (d / "a.yaml").write_text("connect_timeout: 99\n", encoding="utf-8")
    assert fails(gw).key == "connect_timeout"


def test_a_later_drop_in_replaces_a_duration(gw: FakeGateway, home: Path) -> None:
    write(home, "timeout: 10\n")
    d = home / ".config" / "ha-notice" / "config.d"
    d.mkdir()
    (d / "a.yaml").write_text("timeout: 2s\n", encoding="utf-8")
    assert config.load(gw, None).timeout == 2.0


def test_timeout_alone_loads_and_connect_timeout_keeps_its_default(
    gw: FakeGateway, home: Path
) -> None:
    # no key constrains another: timeout 2s with the default connect_timeout 3s loads.
    cfg = loads(gw, home, "timeout: 2s\n")
    assert cfg.timeout == 2.0
    assert cfg.connect_timeout == 3.0


def test_connect_timeout_longer_than_timeout_is_not_refused(gw: FakeGateway, home: Path) -> None:
    cfg = loads(gw, home, "timeout: 1s\nconnect_timeout: 30s\n")
    assert (cfg.timeout, cfg.connect_timeout) == (1.0, 30.0)


@pytest.mark.parametrize(
    ("key_name", "text"),
    [
        ("timeout", f"timeout: '{FAKE_SECRET}'\n"),
        ("connect_timeout", f"connect_timeout: '{FAKE_SECRET}'\n"),
        ("default_group", f"default_group: '{FAKE_SECRET}!'\n"),
        ("level_prefix", f"level_prefix: {{info: '{FAKE_SECRET}'}}\n"),
        ("level_prefix", f"level_prefix: {{warn: '{FAKE_SECRET}'}}\n"),
        ("level_prefix", f"level_prefix: {{action: '{FAKE_SECRET}'}}\n"),
        ("level_prefix", f"level_prefix: {{error: '{FAKE_SECRET}'}}\n"),
        ("level_prefix", f"level_prefix: {{info: 'x{FAKE_SECRET[:8]}  '}}\n"),
        ("level_prefix", f'level_prefix: {{info: "{FAKE_SECRET[:8]}\\u200b"}}\n'),
    ],
)
def test_the_error_never_contains_the_value(
    gw: FakeGateway, home: Path, key_name: str, text: str
) -> None:
    write(home, text)
    err = fails(gw)
    assert err.key == key_name
    for shown in (str(err), repr(err), repr(err.error), err.error.envelope["error"]["message"]):
        assert FAKE_SECRET not in shown and FAKE_SECRET[:8] not in shown
    assert FAKE_SECRET[:8] not in json.dumps(err.error.envelope["error"]["details"])


def test_a_bare_float_is_read_as_a_binary_float_before_the_range_check(
    gw: FakeGateway, home: Path
) -> None:
    # Documented: 120.0000000000000001 is the float 120.0 when bare, and exact when quoted.
    assert loads(gw, home, "timeout: 120.0000000000000001\n").timeout == 120.0
    write(home, "timeout: '120.0000000000000001'\n")
    assert fails(gw).key == "timeout"


def test_a_duration_string_is_capped_at_64_characters(gw: FakeGateway, home: Path) -> None:
    at_cap = "1." + "0" * 62  # 64 characters, exactly 1 second
    assert len(at_cap) == 64
    assert loads(gw, home, f"timeout: '{at_cap}'\n").timeout == 1.0
    write(home, f"timeout: '{at_cap}0'\n")
    assert fails(gw).key == "timeout"
    write(home, f"timeout: '{'1' + '0' * 64}'\n")
    assert fails(gw).key == "timeout"


def test_the_duration_cap_holds_under_the_lowest_int_conversion_limit(
    gw: FakeGateway, home: Path
) -> None:
    import sys

    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)  # the lowest value Python allows
    try:
        at_cap = "1." + "0" * 62
        assert loads(gw, home, f"timeout: '{at_cap}'\n").timeout == 1.0
        assert not config.duration_ok("timeout", "1" + "0" * 64)
    finally:
        sys.set_int_max_str_digits(previous)


def test_the_duration_grammar_matches_the_schema() -> None:
    schema = json.loads((ROOT / "schemas" / "config.json").read_text(encoding="utf-8"))
    pattern = schema["$defs"]["duration"]["anyOf"][1]["pattern"]
    for text in ["10", "10s", "1.5m", "500ms", "1e3", "10\n", "-1", "1h", "", "010", "00s", "01.5"]:
        assert bool(re.fullmatch(pattern, text)) is bool(config.DURATION_RE.fullmatch(text))


# --- max_chars -------------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["100", "101", "1000", "1999", "2000"])
def test_max_chars_accepts(gw: FakeGateway, home: Path, text: str) -> None:
    assert loads(gw, home, f"max_chars: {text}\n").max_chars == int(text)


@pytest.mark.parametrize(
    "text",
    [
        "99",
        "0",
        "-1",
        "2001",
        "9" * 400,
        "-" + "9" * 400,
        "true",
        "false",
        "'300'",
        "300.5",
        "null",
    ],
)
def test_max_chars_refuses(gw: FakeGateway, home: Path, text: str) -> None:
    write(home, f"max_chars: {text}\n")
    assert fails(gw).key == "max_chars"


# --- default_group ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value", ["a", "awkit", "my-group_1", "A", "0", "-", "_", "a" * 64, "9" * 64]
)
def test_default_group_accepts(gw: FakeGateway, home: Path, value: str) -> None:
    assert loads(gw, home, f"default_group: '{value}'\n").default_group == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "a b",
        "a" * 65,
        "a\\n",  # a trailing LF: `$` would accept it
        "\\na",
        "a\\r",
        "a.b",
        "a/b",
        "é",
        "ａ",  # fullwidth a
        "١",  # Arabic-Indic digit
        "a\\u0000",
        "a\\u2028",
        "a\\u00a0",
    ],
)
def test_default_group_refuses(gw: FakeGateway, home: Path, value: str) -> None:
    write(home, f'default_group: "{value}"\n')
    assert fails(gw).key == "default_group"


def test_default_group_unset_is_none(gw: FakeGateway) -> None:
    assert config.load(gw, None).default_group is None


def test_default_group_pattern_agrees_with_the_schema() -> None:
    schema = json.loads((ROOT / "schemas" / "config.json").read_text(encoding="utf-8"))
    pattern = schema["properties"]["default_group"]["pattern"]
    for value in ["a", "a b", "a\n", "\na", "", "a" * 64, "a" * 65, "é", "a-_"]:
        assert bool(re.fullmatch(pattern, value)) is bool(config.GROUP_RE.fullmatch(value))
        assert bool(re.fullmatch(pattern, value)) is config.group_ok(value)


# --- level_prefix ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["", "WARN:", "ACTION:", "a" * 16, "é" * 16, "😀" * 16, "[!]", "a b", "a‌b", "é"],
)
def test_level_prefix_accepts(gw: FakeGateway, home: Path, value: str) -> None:
    write(home, f"level_prefix:\n  warn: {dq(value)}\n")
    assert config.load(gw, None).level_prefix["warn"] == value


@pytest.mark.parametrize(
    "value",
    [
        "a" * 17,
        "\U0001f600" * 17,
        "A\nB",
        "A\n",
        "\nA",
        "A\r",
        "A\tB",
        "A\u0085",
        "A ",
        "A  B",  # two spaces: step 5 would collapse them
        " ",
        " A",
        "A\u00a0",  # str.strip removes it
        "\u3000",
        "A\u2028",
        "A\u2029",
        "A\u0000",
        "A\u001b",
        "A\u007f",
        "A\u0090",
        "A\u00ad",
        "A\u200b",
        "A\u200e",
        "A\u202e",
        "A\u2060",
        "A\ufeff",
        "A\ufff9",
        "A\U000e0041",
        "A\u115f",
        "A\u3164",
        "A\uffa0",
        "A\u2800",
        "A\u180b",
        "A\ue000",  # private use
        "A\U000f0000",
        "A\ufdd0",  # noncharacter
        "A\uffff",
        "A\u0378",  # unassigned
        "\u0301",  # only a combining mark: an empty title
        "\u0301 ",
    ],
)
def test_level_prefix_refuses(gw: FakeGateway, home: Path, value: str) -> None:
    write(home, f"level_prefix:\n  info: {dq(value)}\n")
    assert fails(gw).key == "level_prefix"


def test_a_lone_surrogate_cannot_be_written_to_a_file(gw: FakeGateway, home: Path) -> None:
    # A \ud800 escape in YAML: the loader (or the sanitizer rule) refuses it either way.
    write(home, 'level_prefix: {info: "A\\ud800"}\n')
    err = fails(gw)
    assert err.key == "level_prefix"


@pytest.mark.parametrize("level", ["info", "warn", "action", "error"])
def test_each_level_member_is_checked(gw: FakeGateway, home: Path, level: str) -> None:
    write(home, f'level_prefix: {{{level}: "A\\nB"}}\n')
    assert fails(gw).key == "level_prefix"


def test_unknown_member_still_names_level_prefix(gw: FakeGateway, home: Path) -> None:
    write(home, "level_prefix: {debug: 'D:'}\n")
    assert fails(gw).key == "level_prefix"


def test_level_prefix_defaults_and_partial_override(gw: FakeGateway, home: Path) -> None:
    assert config.load(gw, None).level_prefix == {
        "info": "",
        "warn": "WARN:",
        "action": "ACTION:",
        "error": "ERROR:",
    }
    cfg = loads(gw, home, "level_prefix: {warn: '!'}\n")
    assert cfg.level_prefix == {"info": "", "warn": "!", "action": "ACTION:", "error": "ERROR:"}


def test_level_prefix_accessor_is_a_copy(gw: FakeGateway) -> None:
    cfg = config.load(gw, None)
    cfg.level_prefix["info"] = "changed"
    assert cfg.level_prefix["info"] == ""


def test_level_prefix_schema_pattern_is_a_subset_of_the_tool_rule() -> None:
    # Whatever the tool accepts the schema accepts (the tool also applies the sanitizer rule).
    schema = json.loads((ROOT / "schemas" / "config.json").read_text(encoding="utf-8"))
    pattern = schema["properties"]["level_prefix"]["properties"]["info"]["pattern"]
    for value in ["", "WARN:", "a" * 16, "a" * 17, "A\nB", "A\n", "a\u0085", "é"]:
        if config.prefix_ok(value):
            assert re.fullmatch(pattern, value)


# --- defaults and the example ----------------------------------------------------------------


def test_defaults_without_a_config(gw: FakeGateway) -> None:
    cfg = config.load(gw, None)
    assert cfg.values == {}
    assert cfg.enabled is True
    assert cfg.timeout == 10.0
    assert cfg.connect_timeout == 3.0
    assert cfg.max_chars == 1000
    assert cfg.default_group is None
    assert cfg.log is True


def test_the_example_loads_with_the_stated_defaults(gw: FakeGateway, home: Path) -> None:
    text = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
    cfg = loads(gw, home, text)
    example = yaml.safe_load(text)
    # The example shows every key that has a default; the defaults table is that same data.
    for key, default in config.DEFAULTS.items():
        assert example[key] == default, key
    assert cfg.timeout == 10.0
    assert cfg.connect_timeout == 3.0
    assert cfg.max_chars == 1000
    assert cfg.level_prefix == config.DEFAULTS["level_prefix"]
    assert cfg.enabled is True and cfg.log is True
    assert cfg.default_group is None


def test_the_defaults_table_validates_through_the_same_checks(gw: FakeGateway, home: Path) -> None:
    write(home, yaml.safe_dump(config.DEFAULTS))
    config.load(gw, None)


def test_the_defaults_match_the_schema_defaults() -> None:
    schema = json.loads((ROOT / "schemas" / "config.json").read_text(encoding="utf-8"))
    for key, default in config.DEFAULTS.items():
        assert schema["properties"][key]["default"] == default, key


@pytest.mark.parametrize(
    "text",
    [
        "timeout: 1\n",
        "timeout: 120\n",
        "max_chars: 100\n",
        "max_chars: 2000\n",
        "default_group: a\n",
        "level_prefix: {}\n",
    ],
)
def test_boundary_values_load_and_validate_against_the_schema(
    gw: FakeGateway, home: Path, text: str
) -> None:
    write(home, text)
    config.load(gw, None)
    assert schema_errors("config", yaml.safe_load(text)) == []


def test_known_key_types_still_win_over_grammar(gw: FakeGateway, home: Path) -> None:
    write(home, "default_group: 7\n")
    assert fails(gw).key == "default_group"
    write(home, "level_prefix: {info: 1}\n")
    assert fails(gw).key == "level_prefix"


def test_values_stay_as_written_for_the_other_owners(gw: FakeGateway, home: Path) -> None:
    cfg = loads(gw, home, "timeout: 2s\nmax_chars: 300\n")
    assert cfg.values == {"timeout": "2s", "max_chars": 300}


def test_a_bad_member_in_a_drop_in_is_refused_even_when_the_main_file_is_fine(
    gw: FakeGateway, home: Path
) -> None:
    write(home, "level_prefix: {info: 'I:'}\n")
    d = home / ".config" / "ha-notice" / "config.d"
    d.mkdir()
    (d / "a.yaml").write_text('level_prefix: {warn: "A\\nB"}\n', encoding="utf-8")
    assert fails(gw).key == "level_prefix"


def test_repeated_loads_give_the_same_result(gw: FakeGateway, home: Path) -> None:
    write(home, "timeout: 1m\nmax_chars: 300\ndefault_group: g\nlevel_prefix: {warn: '!'}\n")
    first, second = config.load(gw, None), config.load(gw, None)
    assert first.values == second.values
    assert (first.timeout, first.max_chars, first.default_group) == (60.0, 300, "g")


# --- level_prefix is the sanitizer's title rule (issue #16) ----------------------------------


# Independent oracle written from docs/interface.md (the level_prefix rule, sanitizer steps 1 to 5
# and the Cs/Co row). It calls nothing from ha_notice.payload.
_LISTED_REMOVED = {
    0xAD, 0x61C, 0x180E, 0x200B, 0x200E, 0x200F, 0xFEFF, 0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800,
    0x180B, 0x180C, 0x180D, 0x180F,
}  # fmt: skip
for _lo, _hi in [
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0xFFF9, 0xFFFB),
    (0xE0000, 0xE007F),
    (0xE0100, 0xE01EF),
]:
    _LISTED_REMOVED.update(range(_lo, _hi + 1))


def _removed(ch: str) -> bool:
    if ch == "\n":
        return False
    return ord(ch) in _LISTED_REMOVED or unicodedata.category(ch) in ("Cc", "Cs", "Co", "Cn")


def _golden_prefix(value: str) -> bool:
    if len(value) > 16 or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        return False
    if value == "":
        return True
    t = value.replace("\r\n", "\n")
    for sep in ("\r", "\x85", "\u2028", "\u2029"):
        t = t.replace(sep, "\n")
    t = t.replace("\t", " ")
    t = "".join(c for c in t if not _removed(c))
    t = "\n".join(line.rstrip() for line in t.split("\n"))
    while "\n\n\n" in t:
        t = t.replace("\n\n\n", "\n\n")
    t = t.strip().replace("\n", " ")
    while "  " in t:
        t = t.replace("  ", " ")
    if t.strip() != value:
        return False
    # An empty title: only whitespace and marks.
    return not all(c.isspace() or unicodedata.category(c) in ("Mn", "Mc", "Me") for c in value)


def test_prefix_ok_equals_the_sanitizer_over_every_code_point() -> None:
    # Alone, and between two letters (so a mark, a space or a joiner has a neighbour).
    for n in range(0x110000):
        ch = chr(n)
        for value in (ch, "a" + ch + "b"):
            assert config.prefix_ok(value) == _golden_prefix(value), hex(n)


@pytest.mark.parametrize(
    "value",
    ["", "a", "a" * 16, "a" * 17, " a", "a ", "a  b", "a\tb", "a\nb", "\u0301", "a\u0301", "\ud800"]
    + ["😀", "\U0001f600" * 16, "\U0001f600" * 17, "WARN:", "é" * 16],
)
def test_prefix_ok_golden_on_a_table(value: str) -> None:
    assert config.prefix_ok(value) == _golden_prefix(value)
