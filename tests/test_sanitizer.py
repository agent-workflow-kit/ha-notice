"""Sanitizer: the table, the steps and the emptiness rule of docs/interface.md (issue #13).

The removed and kept sets below are a FIXED list of code points, never derived from the running
Python's tables, so the test fails when the rule drifts. The one sweep that does use
``unicodedata`` (``test_cn_follows_the_running_python``) checks the Cn rule the interface says
follows the running Python (3.12 and 3.13 differ on a few code points, so the sweep compares the
sanitizer against the same category rule instead of a list).
"""

from __future__ import annotations

import random
import time
import unicodedata

import pytest

from ha_notice.payload import (
    PayloadError,
    notification_from_flags,
    sanitize_message,
    sanitize_title,
    validate_notification,
)


def cps(*spans: int | tuple[int, int]) -> list[int]:
    out: list[int] = []
    for s in spans:
        out.extend([s] if isinstance(s, int) else range(s[0], s[1] + 1))
    return out


# Removed by the table (Cn members are fixed code points assigned to no character in 3.12 and 3.13).
REMOVED = cps(
    (0x180B, 0x180F),
    (0x2060, 0x206F),
    0xE0000,
    0xE0002,
    0xE0041,
    0xE007F,
    0xE0100,
    0xE01EF,
    0xE01F0,  # Cn
    0x061C,
    0x00AD,
    0x200B,
    0x200E,
    0x200F,
    (0x202A, 0x202E),
    0xFEFF,
    (0xFFF9, 0xFFFB),
    0xFFFE,
    0xFFFF,
    0x1FFFE,
    0x10FFFF,
    (0xFDD0, 0xFDEF),
    0x2800,
    0x115F,
    0x1160,
    0x3164,
    0xFFA0,
    0x0000,
    0x0001,
    0x001B,
    0x007F,
    (0x0080, 0x0084),
    (0x0086, 0x009F),
    0xE000,
    0xF8FF,
    0xF0000,
    0x100000,
    0x0378,  # Cn in every version
    0xE01F0,
)
KEPT = cps(
    (0xFE00, 0xFE0F),
    0x200C,
    0x200D,
    (0x0600, 0x0605),
    0x06DD,
    0x070F,
    0x08E2,
    0x16FE4,
    0x2100,  # U+2100, a plain symbol
    0x00E9,
    0x4E2D,
    0x1F600,
)
# The line breaks of step 2 (U+0085 is a Cc: it is turned into LF before the removal).
BREAKS = [0x2028, 0x2029, 0x0085]


def cp(n: int) -> str:
    return chr(n)


@pytest.mark.parametrize("n", REMOVED)
def test_removed_code_points(n: int) -> None:
    assert sanitize_message(f"a{cp(n)}b") == "ab"
    assert sanitize_title(f"a{cp(n)}b") == "ab"


@pytest.mark.parametrize("n", KEPT)
def test_kept_code_points(n: int) -> None:
    assert sanitize_message(f"a{cp(n)}b") == f"a{cp(n)}b"
    assert sanitize_title(f"a{cp(n)}b") == f"a{cp(n)}b"


@pytest.mark.parametrize("n", BREAKS)
def test_line_breaks_become_lf(n: int) -> None:
    assert sanitize_message(f"a{cp(n)}b") == "a\nb"
    assert sanitize_title(f"a{cp(n)}b") == "a b"


def test_crlf_and_cr_become_one_lf_each() -> None:
    assert sanitize_message("a\r\nb\rc\nd") == "a\nb\nc\nd"


def test_the_tab_becomes_a_space() -> None:
    assert sanitize_message("a\tb") == "a b"
    assert sanitize_message("a\t\tb") == "a  b"  # runs of spaces collapse only in a title
    assert sanitize_title("a\t\tb") == "a b"


def test_a_flag_emoji_of_tag_characters_becomes_its_base_emoji() -> None:
    england = "\U0001f3f4" + "".join(chr(0xE0000 + c) for c in b"gbeng") + "\U000e007f"
    assert sanitize_message(f"x {england} y") == "x \U0001f3f4 y"


def test_emoji_sequences_are_kept_as_sent() -> None:
    family = "\U0001f468\u200d\U0001f469\u200d\U0001f467"
    heart = "\u2764\ufe0f"
    assert sanitize_message(family + heart) == family + heart


def test_nothing_is_normalized() -> None:
    for text in ["e\u0301", "\uff54\uff54\uff53", "\ufb01", "\u212b", "A\u030a"]:
        assert sanitize_message(text) == text


def test_scripts_that_need_the_kept_joiners_survive() -> None:
    persian = "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645"
    assert sanitize_message(persian) == persian
    assert sanitize_message("\u0600\u0661") == "\u0600\u0661"


# --- steps 4 and 5 -------------------------------------------------------------------------


def test_lines_are_right_stripped_and_blank_runs_collapse() -> None:
    assert sanitize_message("a\n \n \nb") == "a\n\nb"
    assert sanitize_message("a   \nb\t\n\n\n\n\nc") == "a\nb\n\nc"
    assert sanitize_message("a\n\nb") == "a\n\nb"


def test_ends_are_stripped_with_unicode_whitespace() -> None:
    assert sanitize_message("\u3000\u00a0 a \u2003\n") == "a"
    assert sanitize_message("\n\n a\n b \n\n") == "a\n b"  # leading space of line 2 is kept


def test_interior_whitespace_is_not_collapsed_in_a_message() -> None:
    assert sanitize_message("a  b\u00a0\u00a0c") == "a  b\u00a0\u00a0c"


def test_a_title_is_one_line_with_single_spaces() -> None:
    assert sanitize_title("a\nb") == "a b"
    assert sanitize_title("a\n\u2028b") == "a b"
    assert sanitize_title("  a \n\n\n b   c  ") == "a b c"
    assert sanitize_title("a\u00a0\u00a0b") == "a\u00a0\u00a0b"  # only U+0020 runs collapse


def test_a_removed_character_does_not_leave_a_gap() -> None:
    assert sanitize_message("a\u200b\n\u200b\n\u200b\nb") == "a\n\nb"
    assert sanitize_title("a \u200b b") == "a b"


# --- emptiness -----------------------------------------------------------------------------

EMPTY_MESSAGES = [
    "",
    " ",
    "\n\t \r\n",
    "\u2d7f",
    "\u0301",
    "\u0903",  # Mc
    "\u20dd",  # Me
    "\u115f\u1160   ",
    "\u3164",
    "\u3000",
    "\u200b\u2060\ufeff",
    "\u0301 \u2d7f\n",
    "\ufe0f",
]


@pytest.mark.parametrize("text", EMPTY_MESSAGES)
def test_an_empty_message_is_empty_message(text: str) -> None:
    with pytest.raises(PayloadError) as info:
        validate_notification({"message": text})
    assert (info.value.reason, info.value.pointer) == ("empty_message", None)


@pytest.mark.parametrize("text", EMPTY_MESSAGES)
def test_an_empty_title_is_absent(text: str) -> None:
    assert validate_notification({"message": "m", "title": text}).title is None
    assert notification_from_flags(title=text, message="m", level=None, link=None).title is None


@pytest.mark.parametrize("text", ["a\u0301", "\u0301a", ".", "\u200d", "a\u2d7f"])
def test_text_with_a_real_character_is_not_empty(text: str) -> None:
    assert validate_notification({"message": text}).message == text.strip()


def test_the_sanitized_values_are_what_the_notification_holds() -> None:
    got = validate_notification({"message": " a\u200b\r\n\r\n\r\n\r\nb ", "title": " T\n\u2028t "})
    assert (got.message, got.title) == ("a\n\nb", "T t")


def test_flags_are_sanitized_like_stdin() -> None:
    got = notification_from_flags(title=" T\nt ", message="a\u200b ", level=None, link=None)
    assert (got.title, got.message) == ("T t", "a")


def test_the_limit_counts_the_input_before_sanitizing() -> None:
    # 100000 removable characters plus one is over the limit even though nothing would be left.
    with pytest.raises(PayloadError) as info:
        validate_notification({"message": "m", "title": "\u200b" * 100001})
    assert info.value.pointer == "/title"
    assert validate_notification({"message": "m", "title": "\u200b" * 100000}).title is None


def test_the_checks_keep_their_order() -> None:
    # A bad title type is reported before an empty message; an empty message comes last.
    with pytest.raises(PayloadError) as info:
        validate_notification({"message": " ", "title": 1})
    assert info.value.pointer == "/title"
    with pytest.raises(PayloadError) as info:
        validate_notification({"message": " ", "level": "nope"})
    assert info.value.pointer == "/level"


# --- lone surrogates -----------------------------------------------------------------------
# Decision: step 1 is the more specific rule ("a lone surrogate: exit 20 invalid_payload"); a
# lone surrogate is refused, never silently removed, and the Cs row never matches a text that
# got this far. The pointer is the field, like any other field error.

LONE = ["\ud800", "\udbff", "\udc00", "\udfff", "a\ud800b", "\udc00\ud800", "x\ud83d", "\ude00y"]


@pytest.mark.parametrize("field", ["title", "message"])
@pytest.mark.parametrize("text", LONE)
def test_a_lone_surrogate_is_refused_with_its_field(field: str, text: str) -> None:
    obj = {"message": "m", field: text}
    with pytest.raises(PayloadError) as info:
        validate_notification(obj)
    assert (info.value.reason, info.value.pointer) == ("invalid_payload", f"/{field}")
    assert info.value.to_error().exit_code == 20
    flags = {"title": None, "message": "m", "level": None, "link": None, field: text}
    with pytest.raises(PayloadError) as flag_info:
        notification_from_flags(**flags)  # type: ignore[arg-type]
    assert (flag_info.value.reason, flag_info.value.pointer) == ("invalid_payload", f"/{field}")


def test_a_lone_surrogate_from_a_json_escape_is_refused() -> None:
    import json

    for doc in ['{"message": "\\ud800"}', '{"message": "m", "title": "\\udc00x"}']:
        field = "message" if '"title"' not in doc else "title"
        with pytest.raises(PayloadError) as info:
            validate_notification(json.loads(doc))
        assert info.value.pointer == f"/{field}"


def test_a_valid_pair_is_one_character_and_accepted() -> None:
    import json

    got = validate_notification(json.loads('{"message": "\\ud83d\\ude00"}'))
    assert got.message == "\U0001f600"


def test_a_lone_surrogate_is_refused_before_the_message_is_judged_empty() -> None:
    with pytest.raises(PayloadError) as info:
        validate_notification({"message": "\ud800"})
    assert info.value.reason == "invalid_payload"


def test_a_surrogate_refusal_never_echoes_the_input() -> None:
    err = validate_pointer_error("secret\ud800value")
    assert "secret" not in repr(err.to_error().envelope)
    assert "secret" not in str(err)


def validate_pointer_error(text: str) -> PayloadError:
    with pytest.raises(PayloadError) as info:
        validate_notification({"message": text})
    return info.value


def test_the_sanitizer_function_itself_still_removes_cs() -> None:
    # The table's Cs row, for a caller (a config prefix) that does not go through validation.
    assert sanitize_title("a\ud800b") == "ab"


# --- sweeps --------------------------------------------------------------------------------

_CONTROLS_KEPT = {0x0A}
# The table's listed Cf and default-ignorable characters, written out independently of the code.
LISTED_RANGES = set(
    cps(
        0x00AD,
        0x061C,
        (0x180B, 0x180F),
        0x200B,
        0x200E,
        0x200F,
        (0x202A, 0x202E),
        (0x2060, 0x206F),
        0xFEFF,
        (0xFFF9, 0xFFFB),
        (0xE0000, 0xE007F),
        (0xE0100, 0xE01EF),
        0x115F,
        0x1160,
        0x3164,
        0xFFA0,
        0x2800,
    )
)


def _expected_removed(n: int) -> bool:
    """The table by category (running Python's Unicode data) plus the fixed list."""
    if n in _CONTROLS_KEPT:
        return False
    if unicodedata.category(chr(n)) in {"Cc", "Cs", "Co", "Cn"}:
        return True
    return n in set(REMOVED) or n in LISTED_RANGES


def test_cn_follows_the_running_python() -> None:
    # Category-equivalence check against the running Python's tables, not a golden list: the
    # fixed REMOVED and KEPT lists above are the golden pins.
    # Every code point, one text: a removed one disappears, any other stays (except the breaks,
    # the tab and the whitespace that the later steps strip at the ends, so each is flanked).
    bad: list[int] = []
    for n in range(0x110000):
        if n in (0x0A, 0x09, 0x0D, *BREAKS):
            continue
        got = sanitize_message(f"a{chr(n)}b")
        want = "ab" if _expected_removed(n) else f"a{chr(n)}b"
        if got != want:
            bad.append(n)
    assert bad == []


def test_cn_includes_noncharacters_of_every_plane() -> None:
    for plane in range(0x11):
        for last in (0xFFFE, 0xFFFF):
            assert sanitize_message(f"a{chr(plane * 0x10000 + last)}b") == "ab"


def test_no_removed_listed_character_is_a_kept_one() -> None:
    assert not set(REMOVED) & set(KEPT)


def test_sanitizing_twice_changes_nothing() -> None:
    rng = random.Random(13)
    pool = (
        ["a", "b", " ", "\n", "\t", "\r", "\u00a0", "\u3000", "\u200b", "\u0301", "\u2028"]
        + [chr(n) for n in (0x200D, 0xFE0F, 0xFFFE, 0xE0041, 0x2D7F, 0x1F600)]
        + ["\x00", "\x85"]
    )
    for _ in range(3000):
        text = "".join(rng.choice(pool) for _ in range(rng.randint(0, 24)))
        for fn in (sanitize_message, sanitize_title):
            once = fn(text)
            assert fn(once) == once


# --- hostile size --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        " \n" * 500_000,
        "\n" * 1_000_000,
        " " * 1_000_000 + "x",
        "x" + " " * 1_000_000,
        "\u200b" * 1_000_000,
        "a \n" * 333_333,
        "\r\n" * 500_000,
        "\u0301" * 1_000_000,
        "\u3000\n" * 500_000,
    ],
)
def test_one_mebibyte_of_hostile_text_is_linear(text: str) -> None:
    start = time.monotonic()
    sanitize_message(text)
    sanitize_title(text)
    assert time.monotonic() - start < 5.0
