"""Command-keyword rule (issue #14, docs/interface.md, Command messages)."""

from __future__ import annotations

import time

import pytest

from ha_notice.payload import (
    PayloadError,
    check_command_keyword,
    notification_from_flags,
    validate_notification,
)
from tests.harness import schema_errors

REFUSED = [
    "tts",
    "TTS",
    "Tts",
    "\uff54\uff54\uff53",  # fullwidth tts
    "  tts  ",
    "\ntts\n",
    "update_deps",
    "UPDATE_WIDGETS",
    "request_location_update",
    "clear_notification",
    "clear_badge",
    "remove_channel",
    "update_complications",
    "command_x",
    "COMMAND_ANYTHING_9",
    "kiosk_x",
    "clear_foo_bar",
    "update_",  # empty tail
    "command_",
    "\uff55pdate_\uff57idgets",  # fullwidth, mixed
    "Kiosk_x",  # Kelvin sign folds to k
    "t\x00ts",  # NUL is removed by the sanitizer first
    "\x00update_deps",
    "\u00adtts",  # soft hyphen removed first
    "update_deps\n",
]

ALLOWED = [
    "update_deps finished",
    "Updated: x",
    "update_deps\nsecond line",
    "update_deps.",
    "update-deps",
    "updat_e",
    "tts now",
    "ttss",
    "tt",
    "source: update_deps",
    "xupdate_deps",
    "update_dep\u00e9",  # non-ASCII tail
    "update_d\u0131ps",  # dotless i is not i
    "t\u200dts",  # kept Cf (ZWJ) inside: not equal to tts
    "ts",
    "hello",
    "request",
    "command",
    "kiosk",
]


@pytest.mark.parametrize("message", REFUSED)
def test_command_message_is_refused(message: str) -> None:
    with pytest.raises(PayloadError) as ei:
        validate_notification({"message": message})
    err = ei.value
    assert (err.reason, err.pointer) == ("command_keyword", None)
    result = err.to_error()
    assert schema_errors("cli/error", result.envelope) == []
    assert result.envelope["error"]["reason"] == "command_keyword"
    assert result.envelope["error"].get("details") in (None, {})
    assert message.strip() not in {str(v) for v in result.envelope["error"].values()}


@pytest.mark.parametrize("message", ALLOWED)
def test_near_miss_is_not_refused(message: str) -> None:
    assert validate_notification({"message": message}).message


def test_check_command_keyword_on_plain_text() -> None:
    assert check_command_keyword("update_deps") is True
    assert check_command_keyword("update_deps x") is False
    assert check_command_keyword("") is False


def test_the_check_runs_after_the_sanitizer() -> None:
    # "up\x00date_x" is a keyword only once the sanitizer has removed the NUL.
    assert check_command_keyword("up\x00date_x") is False
    with pytest.raises(PayloadError) as ei:
        validate_notification({"message": "up\x00date_x"})
    assert ei.value.reason == "command_keyword"


def test_flags_go_through_the_same_rule() -> None:
    with pytest.raises(PayloadError) as ei:
        notification_from_flags(title=None, message="clear_badge", level=None, link=None)
    assert ei.value.reason == "command_keyword"


def test_the_title_is_not_checked() -> None:
    n = validate_notification({"title": "update_deps", "message": "hi"})
    assert n.title == "update_deps"


def test_type_error_wins_over_keyword() -> None:
    with pytest.raises(PayloadError) as ei:
        validate_notification({"message": "tts", "level": "loud"})
    assert (ei.value.reason, ei.value.pointer) == ("invalid_payload", "/level")


@pytest.mark.parametrize(
    "text",
    [
        "update_" + "a" * 99990,
        "a_" * 50000,
        "update_" + "_" * 99990 + " x",
        "\uff54" * 100000,
        "\ufdfa" * 100000,  # NFKC expands a lot
        " " * 99999 + "tts",
    ],
)
def test_hostile_input_is_linear(text: str) -> None:
    start = time.monotonic()
    try:
        validate_notification({"message": text})
    except PayloadError:
        pass
    assert time.monotonic() - start < 10.0
