"""Notification validation: fields, levels and unknown fields (issue #11); the sanitizer is in
test_sanitizer.py (issue #13)."""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

import pytest

from ha_notice import payload
from ha_notice.output import dumps
from ha_notice.payload import (
    Notification,
    PayloadError,
    notification_from_flags,
    validate_notification,
)
from tests.harness import schema_errors

SAMPLES = json.loads((Path(__file__).parent / "samples" / "notification.json").read_text("utf-8"))


def refusal(obj: object) -> PayloadError:
    with pytest.raises(PayloadError) as info:
        validate_notification(obj)
    return info.value


def assert_invalid(obj: object, pointer: str) -> None:
    err = refusal(obj)
    assert (err.reason, err.pointer) == ("invalid_payload", pointer)
    envelope = err.to_error()
    assert envelope.exit_code == 20
    assert schema_errors("cli/error", envelope.envelope) == []
    assert envelope.envelope["error"]["details"] == {"pointer": pointer}


# --- empty_message -------------------------------------------------------------------------


@pytest.mark.parametrize("obj", [{}, {"title": "x"}, {"level": "warn"}, {"message": ""}])
def test_absent_or_empty_message_is_empty_message(obj: dict[str, Any]) -> None:
    err = refusal(obj)
    assert (err.reason, err.pointer) == ("empty_message", None)
    result = err.to_error()
    assert result.exit_code == 20
    assert result.envelope["error"]["reason"] == "empty_message"
    assert result.envelope["error"]["details"] is None
    assert schema_errors("cli/error", result.envelope) == []


def test_a_type_error_wins_over_an_empty_message() -> None:
    assert_invalid({"title": 1}, "/title")
    assert_invalid({"level": "nope"}, "/level")


# --- unknown fields ------------------------------------------------------------------------


def test_unknown_field_is_refused_with_its_pointer() -> None:
    assert_invalid({"message": "m", "data": {}}, "/data")


def test_unknown_field_wins_over_empty_message() -> None:
    assert_invalid({"data": 1}, "/data")


@pytest.mark.parametrize(
    "key",
    [
        "x" * 5000,
        "a" * 65,
        "",
        "a b",
        "é",
        "a/b",
        "~0",
        "a\nb",
        "x\n",
        "\ud800",
        "😀",
        "/x",
        "x" * 64 + "!",
    ],
)
def test_hostile_unknown_field_name_is_pointer_question_mark(key: str) -> None:
    err = refusal({"message": "a", key: 1})
    assert err.pointer == "/?"
    # the key appears nowhere: the envelope equals the one for a different hostile key
    other = refusal({"message": "a", "other hostile key!": 1})
    assert dumps(err.to_error().envelope) == dumps(other.to_error().envelope)


def test_plain_unknown_field_name_boundary() -> None:
    assert_invalid({"message": "a", "a" * 64: 1}, "/" + "a" * 64)
    assert_invalid({"message": "a", "a" * 65: 1}, "/?")
    assert_invalid({"message": "a", "A-b_9": 1}, "/A-b_9")


def test_the_unknown_field_name_never_reaches_the_message() -> None:
    result = refusal({"message": "a", "secret-field": 1}).to_error()
    assert "secret-field" not in result.envelope["error"]["message"]


def test_known_field_names_are_case_sensitive() -> None:
    assert_invalid({"message": "a", "Title": "x"}, "/Title")


def test_several_unknown_fields_report_the_smallest_whatever_the_order() -> None:
    for keys in itertools.permutations(["zeta", "alpha", "mid"]):
        obj: dict[str, Any] = {"message": "a"}
        obj.update({k: 1 for k in keys})
        assert refusal(obj).pointer == "/alpha"


def test_refusal_is_independent_of_key_order() -> None:
    items = [("title", 1), ("message", 2), ("level", "bad"), ("link", None)]
    pointers = {refusal(dict(order)).pointer for order in itertools.permutations(items)}
    assert pointers == {"/title"}


@pytest.mark.parametrize(
    ("obj", "pointer"),
    [
        ({"message": 2, "level": "bad"}, "/message"),
        ({"level": "bad", "link": 1}, "/level"),
        ({"link": 1, "level": "bad"}, "/level"),
        ({"level": "bad", "message": 2}, "/message"),
    ],
)
def test_check_order_is_message_then_level_then_link(obj: dict[str, Any], pointer: str) -> None:
    assert_invalid(obj, pointer)


def test_a_non_string_key_is_unusable() -> None:
    assert refusal({"message": "a", 1: 2}).pointer == "/?"


# --- types ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value", [None, 1, 1.5, True, False, [], ["a"], {}, {"a": 1}, b"a", 0, float("nan")]
)
@pytest.mark.parametrize("field", ["title", "message", "level", "link"])
def test_a_field_of_the_wrong_type_is_refused(field: str, value: Any) -> None:
    obj: dict[str, Any] = {"message": "a"}
    obj[field] = value
    assert_invalid(obj, f"/{field}")


def test_a_str_subclass_is_not_a_string() -> None:
    class S(str):
        pass

    assert_invalid({"message": S("a")}, "/message")


@pytest.mark.parametrize("value", [None, 1, "x", [], True, "", 0])
def test_a_document_that_is_not_an_object_is_refused_at_the_root(value: object) -> None:
    assert_invalid(value, "")


# --- levels --------------------------------------------------------------------------------


@pytest.mark.parametrize("level", payload.LEVELS)
def test_each_level_is_accepted(level: str) -> None:
    assert validate_notification({"message": "m", "level": level}).level == level


def test_the_vocabulary_is_closed_and_ordered() -> None:
    assert payload.LEVELS == ("info", "warn", "action", "error")


@pytest.mark.parametrize(
    "level",
    [
        "",
        "INFO",
        "Info",
        "info ",
        " info",
        "info\n",
        "critical",
        "warning",
        "debug",
        "é",
        "x" * 5000,
    ],
)
def test_a_level_outside_the_vocabulary_is_refused(level: str) -> None:
    assert_invalid({"message": "m", "level": level}, "/level")


def test_the_level_defaults_to_info() -> None:
    assert validate_notification({"message": "m"}).level == "info"


# --- limits --------------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["title", "message"])
def test_text_over_100000_characters_is_refused(field: str) -> None:
    obj = {"message": "m", field: "a" * 100001}
    assert_invalid(obj, f"/{field}")


@pytest.mark.parametrize("field", ["title", "message"])
def test_text_of_exactly_100000_characters_is_accepted(field: str) -> None:
    result = validate_notification({"message": "m", field: "a" * 100000})
    assert len(getattr(result, field)) == 100000


def test_the_limit_counts_characters_not_bytes() -> None:
    assert validate_notification({"message": "😀" * 100000}).message == "😀" * 100000
    assert_invalid({"message": "😀" * 100001}, "/message")


# --- accepted notifications ----------------------------------------------------------------


def test_all_fields() -> None:
    got = validate_notification(
        {"title": "T", "message": "m", "level": "warn", "link": "https://a.example/x"}
    )
    assert got == Notification("m", "warn", "T", "https://a.example/x")


def test_title_and_link_are_none_when_absent() -> None:
    got = validate_notification({"message": "m"})
    assert (got.title, got.link) == (None, None)


def test_the_input_is_not_modified() -> None:
    obj = {"message": " m\n", "title": ""}
    validate_notification(obj)
    assert obj == {"message": " m\n", "title": ""}


def test_an_empty_title_is_absent() -> None:
    assert validate_notification({"message": "m", "title": ""}).title is None


def test_a_whitespace_only_message_is_empty_message() -> None:
    assert (refusal({"message": " "}).reason, refusal({"message": "\n\t"}).pointer) == (
        "empty_message",
        None,
    )


# --- flags and stdin parity ----------------------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"message": "m"},
        {"message": "m", "title": "T"},
        {"message": "m", "level": "error", "link": "https://a.example/"},
        {"message": "héllo\n😀", "title": "t\ttab", "level": "action"},
        {"message": "x" * 100000},
        {"message": "m", "title": ""},
    ],
)
def test_flags_and_json_give_the_same_notification(fields: dict[str, str]) -> None:
    from_flags = notification_from_flags(
        title=fields.get("title"),
        message=fields.get("message"),
        level=fields.get("level"),
        link=fields.get("link"),
    )
    from_json = validate_notification(json.loads(json.dumps(fields)))
    assert from_flags == from_json
    if fields.get("title") == "":
        assert from_flags.title is None  # an empty title is absent (sanitizer)


@pytest.mark.parametrize(
    "flags",
    [
        {"title": "x", "message": None, "level": None, "link": None},
        {"title": None, "message": "", "level": None, "link": None},
        {"title": None, "message": "m", "level": "bad", "link": None},
        {"title": None, "message": "m", "level": "", "link": None},
        {"title": None, "message": "m", "level": None, "link": ""},
        {"title": None, "message": "m", "level": None, "link": "javascript:x"},
        {"title": "x" * 100001, "message": "m", "level": None, "link": None},
        {"title": None, "message": "m" * 100001, "level": None, "link": None},
    ],
)
def test_flags_and_json_are_refused_the_same_way(flags: dict[str, str | None]) -> None:
    given = {k: v for k, v in flags.items() if v is not None}
    with pytest.raises(PayloadError) as a:
        notification_from_flags(**flags)  # type: ignore[arg-type]
    b = refusal(given)
    assert (a.value.reason, a.value.pointer) == (b.reason, b.pointer)


# --- schema agreement ----------------------------------------------------------------------

# The link rule (issue #15): the field layer accepts any string, so the link rule refuses these
# samples as ``link_invalid`` (with no details).
_LINK_RULES = {
    "link_trailing_lf",
    "link_space",
    "link_non_ascii",
    "link_too_long",
    "link_empty",
}


@pytest.mark.parametrize("name", list(SAMPLES["valid"]))
def test_every_valid_sample_passes_the_field_checks(name: str) -> None:
    sample = SAMPLES["valid"][name]
    assert schema_errors("notification", sample) == []
    try:
        validate_notification(sample)
    except PayloadError as err:
        # The schema has no minLength: an empty message is the tool's empty_message check.
        assert (name, err.reason) == ("empty_message_is_the_tools_check", "empty_message")


@pytest.mark.parametrize(
    "name",
    [n for n in SAMPLES["invalid"] if n not in _LINK_RULES and not n.startswith("actions_")],
)
def test_every_invalid_sample_is_refused_like_the_schema_says(name: str) -> None:
    sample = SAMPLES["invalid"][name]
    assert schema_errors("notification", sample["instance"]) != []
    err = refusal(sample["instance"])
    if sample["keyword"] == "required":
        assert (err.reason, err.pointer) == ("empty_message", None)
    elif sample["keyword"] == "additionalProperties":
        assert (err.reason, err.pointer) == ("invalid_payload", "/data")
    else:
        pointer = "".join(f"/{p}" for p in sample["path"])
        assert (err.reason, err.pointer) == ("invalid_payload", pointer)


@pytest.mark.parametrize("name", sorted(_LINK_RULES))
def test_link_rule_samples_are_refused_as_link_invalid(name: str) -> None:
    instance = SAMPLES["invalid"][name]["instance"]
    err = refusal(instance)
    assert (err.reason, err.pointer) == ("link_invalid", None)
