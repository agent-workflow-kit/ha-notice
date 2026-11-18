"""Notification actions with allowlisted URI schemes (issue #37, docs/interface.md, Notification:
actions)."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from ha_notice.config import DEFAULTS
from ha_notice.payload import (
    ACTION_TITLE_MAX,
    ACTIONS_MAX,
    Action,
    Notification,
    PayloadError,
    parse_notification,
    validate_notification,
)
from ha_notice.render import render, serialize
from tests.harness import Golden, schema_errors
from tests.timing import LOAD_SLACK_S

PREFIX = dict(DEFAULTS["level_prefix"])


def act(title: Any = "Open", uri: Any = "https://a.example/x") -> dict[str, Any]:
    return {"title": title, "uri": uri}


def note(actions: Any, **extra: Any) -> dict[str, Any]:
    return {"message": "m", "actions": actions, **extra}


def refusal(obj: object, hosts: list[str] | None = None) -> PayloadError:
    with pytest.raises(PayloadError) as info:
        validate_notification(obj, hosts)
    return info.value


def assert_refused(
    obj: object, reason: str, pointer: str | None, hosts: list[str] | None = None
) -> None:
    err = refusal(obj, hosts)
    assert (err.reason, err.pointer) == (reason, pointer)
    env = err.to_error()
    assert env.exit_code == 20
    assert schema_errors("cli/error", env.envelope) == []
    details = env.envelope["error"]["details"]
    assert details == (None if pointer is None else {"pointer": pointer})


def rendered(n: Notification) -> dict[str, Any]:
    return render(n, max_chars=1000, default_group=None, level_prefix=PREFIX).body


# --- the limits ----------------------------------------------------------------------------


def test_constants() -> None:
    assert (ACTIONS_MAX, ACTION_TITLE_MAX) == (3, 64)


@pytest.mark.parametrize("count", [0, 1, 2, 3])
def test_zero_to_three_actions_are_accepted_in_order(count: int) -> None:
    items = [act(f"T{i}", f"https://a.example/{i}") for i in range(count)]
    n = validate_notification(note(items))
    assert n.actions == tuple(Action(f"T{i}", f"https://a.example/{i}") for i in range(count))
    assert schema_errors("notification", note(items)) == []


def test_four_actions_are_refused_at_the_list() -> None:
    assert_refused(note([act()] * 4), "invalid_payload", "/actions")
    assert schema_errors("notification", note([act()] * 4)) != []


def test_the_count_is_checked_before_any_item() -> None:
    # Item 0 is invalid too, but the list is refused first.
    assert_refused(note(["x"] * 4), "invalid_payload", "/actions")


@pytest.mark.parametrize("value", [None, "x", 1, True, {}, {"title": "a", "uri": "https://a.example"}])
def test_actions_must_be_a_list(value: object) -> None:
    assert_refused(note(value), "invalid_payload", "/actions")


def test_a_tuple_is_not_a_json_list() -> None:
    assert_refused(note((act(),)), "invalid_payload", "/actions")


@pytest.mark.parametrize("item", [None, "x", 1, [], [act()], True])
def test_items_must_be_objects(item: object) -> None:
    assert_refused(note([act(), item]), "invalid_payload", "/actions/1")


# --- keys and titles -----------------------------------------------------------------------


def test_unknown_key_is_refused_with_the_smallest_name() -> None:
    bad = {**act(), "zeta": 1, "alpha": 2}
    assert_refused(note([bad]), "invalid_payload", "/actions/0/alpha")


@pytest.mark.parametrize("key", ["action", "data", "icon", "k" * 65, "", "a b", "é", "a/b", "ac\n"])
def test_unknown_keys_are_refused_and_hostile_names_are_not_echoed(key: str) -> None:
    plain = key in ("action", "data", "icon")
    expected = f"/actions/2/{key}" if plain else "/actions/2/?"
    assert_refused(note([act(), act(), {**act(), key: "x"}]), "invalid_payload", expected)
    err = refusal(note([act(), act(), {**act(), key: "x"}]))
    assert key not in json.dumps(err.to_error().envelope) or plain


def test_unknown_keys_win_over_a_bad_title() -> None:
    assert_refused(note([{"title": 1, "uri": 2, "x": 3}]), "invalid_payload", "/actions/0/x")


def test_title_is_required() -> None:
    assert_refused(note([{"uri": "https://a.example"}]), "invalid_payload", "/actions/0/title")


def test_uri_is_required() -> None:
    assert_refused(note([{"title": "t"}]), "invalid_payload", "/actions/0/uri")
    assert_refused(note([act(), {"title": "t"}]), "invalid_payload", "/actions/1/uri")


@pytest.mark.parametrize(
    "title",
    [None, 1, ["a"], "", "   ", "\t\n", "\u200b\u200b", "\x00", "\u0301", "x" * 65],
)
def test_bad_titles_are_refused(title: object) -> None:
    assert_refused(note([act(title=title)]), "invalid_payload", "/actions/0/title")


def test_title_lone_surrogate_and_over_input_limit_are_refused() -> None:
    assert_refused(note([act(title="a\ud800")]), "invalid_payload", "/actions/0/title")
    assert_refused(note([act(title="a" * 100001)]), "invalid_payload", "/actions/0/title")


def test_title_is_sanitized_like_a_title() -> None:
    n = validate_notification(note([act(title="  A\u200b\r\nB\tC  \u202e  ")]))
    assert n.actions[0].title == "A B C"


def test_title_limit_counts_sanitized_characters_and_is_never_cut() -> None:
    n = validate_notification(note([act(title="x" * 64)]))
    assert n.actions[0].title == "x" * 64
    # 80 raw characters, 64 after sanitizing: accepted.
    n = validate_notification(note([act(title="x" * 64 + "\u200b" * 16)]))
    assert len(n.actions[0].title) == 64
    assert_refused(note([act(title="x" * 65)]), "invalid_payload", "/actions/0/title")
    assert_refused(note([act(title="\U0001f600" * 65)]), "invalid_payload", "/actions/0/title")
    assert len(validate_notification(note([act(title="\U0001f600" * 64)])).actions[0].title) == 64


@pytest.mark.parametrize("title", ["tts", "command_x", "update_widgets", "clear_notification"])
def test_a_command_word_title_is_a_title_not_a_command(title: str) -> None:
    # The command-keyword rule applies to the message only; the phone does not read an action
    # title as a command.
    n = validate_notification(note([act(title=title)]))
    assert n.actions[0].title == title


def test_the_message_keyword_rule_is_unchanged_with_actions() -> None:
    assert_refused({"message": "tts", "actions": [act()]}, "command_keyword", None)


# --- uris ----------------------------------------------------------------------------------


@pytest.mark.parametrize("uri", ["https://a.example/x", "http://a.example:8123/?q=1#f", "HTTP://X"])
def test_allowed_uris(uri: str) -> None:
    assert validate_notification(note([act(uri=uri)])).actions[0].uri == uri


@pytest.mark.parametrize(
    "uri",
    [
        "app://x",
        "javascript:x",
        "intent://x",
        "homeassistant://navigate/x",
        "tel:1",
        "file:///x",
        "mailto:a@b.example",
        "sms:1",
        "ftp://a.example",
        "JaVaScRiPt:alert(1)",
    ],
)
def test_forbidden_schemes_are_link_scheme(uri: str) -> None:
    assert_refused(note([act(), act(uri=uri)]), "link_scheme", "/actions/1/uri")


@pytest.mark.parametrize(
    "uri",
    [
        "//host/x",
        "/lovelace/0",
        "lovelace/0",
        "https:/x",
        "https://",
        "https://u:p@a.example/",
        "https://u@a.example/",
        "https://a.example/\n",
        "https://a.example/a b",
        "https://a.example/é",
        "https://a.example/\\x",
        "https://a.example:0/",
        "https://a.example:65536/",
        "https://[::g]/",
        "",
        "https://a.example/" + "a" * 1024,
    ],
)
def test_malformed_uris_are_link_invalid(uri: str) -> None:
    assert_refused(note([act(uri=uri)]), "link_invalid", "/actions/0/uri")


@pytest.mark.parametrize("uri", [None, 1, ["https://a.example"], {"u": 1}])
def test_uri_must_be_a_string(uri: object) -> None:
    assert_refused(note([act(uri=uri)]), "invalid_payload", "/actions/0/uri")


def test_link_hosts_apply_to_every_action_uri() -> None:
    hosts = ["ha.example"]
    ok = note([act(uri="https://ha.example/x"), act(uri="https://a.ha.example:8/y")])
    assert len(validate_notification(ok, hosts).actions) == 2
    bad = note([act(uri="https://ha.example/x"), act(uri="https://evil.example/")])
    assert_refused(bad, "link_invalid", "/actions/1/uri", hosts)
    assert_refused(note([act(uri="https://[::1]/")]), "link_invalid", "/actions/0/uri", hosts)
    assert_refused(note([act()]), "link_invalid", "/actions/0/uri", [])
    # Unset: no restriction.
    assert len(validate_notification(bad).actions) == 2


def test_link_hosts_do_not_turn_a_scheme_refusal_into_a_host_refusal() -> None:
    assert_refused(note([act(uri="app://x")]), "link_scheme", "/actions/0/uri", ["ha.example"])


def test_check_order_link_then_actions_then_empty_message() -> None:
    assert_refused(
        {"actions": [act(uri="app://x")], "link": "ftp://a.example"}, "link_scheme", None
    )
    assert_refused({"actions": [act(uri="app://x")]}, "link_scheme", "/actions/0/uri")
    assert_refused({"message": "  ", "actions": [act(uri="app://x")]}, "link_scheme", "/actions/0/uri")
    assert_refused({"message": "  ", "actions": [act()]}, "empty_message", None)
    # Items are judged in order and the first refusal wins.
    assert_refused(
        note([act(title=""), act(uri="app://x")]), "invalid_payload", "/actions/0/title"
    )


def test_no_input_is_echoed_in_errors() -> None:
    secret = "SECRETVALUE"
    for obj in (
        note([act(title=secret * 20)]),
        note([act(uri=f"app://{secret}")]),
        note([act(uri=f"https://{secret}@a.example/")]),
        note([{**act(), secret: 1}]),
        note([secret]),
    ):
        err = refusal(obj)
        assert secret not in json.dumps(err.to_error().envelope)
        assert secret not in err.to_error().message


# --- rendering -----------------------------------------------------------------------------


def test_actions_are_rendered_in_order_with_exact_bytes() -> None:
    n = validate_notification(
        note([act("Open HA", "HTTPS://Ha.Example/Lovelace?X=1#Y"), act("Docs", "http://b.example")])
    )
    body = rendered(n)
    assert serialize(body) == (
        b'{"message":"m","data":{"actions":['
        b'{"action":"URI","title":"Open HA","uri":"https://Ha.Example/Lovelace?X=1#Y"},'
        b'{"action":"URI","title":"Docs","uri":"http://b.example"}]}}'
    )
    assert n.actions[0].uri.startswith("HTTPS://")  # the notification is not modified


def test_key_order_in_data_puts_actions_last() -> None:
    n = validate_notification(note([act()], link="https://a.example/l"))
    out = render(
        n, max_chars=1000, default_group="g", level_prefix=PREFIX, tag="awkit-" + "0" * 24
    ).body
    assert list(out["data"]) == ["url", "clickAction", "tag", "group", "actions"]
    assert list(out["data"]["actions"][0]) == ["action", "title", "uri"]


def test_no_actions_changes_nothing() -> None:
    n = validate_notification({"message": "m", "link": "https://a.example"})
    assert n.actions == ()
    assert rendered(n)["data"] == {
        "url": "https://a.example",
        "clickAction": "https://a.example",
    }
    assert "data" not in rendered(validate_notification({"message": "m"}))
    assert "data" not in rendered(validate_notification(note([])))


def test_titles_are_not_cut_by_the_message_budget() -> None:
    n = validate_notification(note([act("x" * 64)] * 3, message="y" * 5000))
    out = rendered(n)
    assert [a["title"] for a in out["data"]["actions"]] == ["x" * 64] * 3
    assert out["message"].endswith("…[truncated]")


def test_the_rendered_body_matches_the_schema() -> None:
    n = validate_notification(note([act("é😀", "HtTp://a.example/p")] * 3))
    doc = {
        "outcome": "dry_run",
        "tool": "ha-notice",
        "level": "info",
        "truncated": False,
        "bytes": 1,
        "duration_ms": 0,
        "http_status": None,
        "tag_set": False,
        "dedupe_key": None,
        "warnings": [],
        "rendered": rendered(n),
    }
    assert schema_errors("cli/send", doc) == []
    doc["rendered"]["data"]["actions"][0]["action"] = "TEL"
    assert schema_errors("cli/send", doc) != []
    doc["rendered"]["data"]["actions"][0]["action"] = "URI"
    doc["rendered"]["data"]["actions"] *= 2
    assert schema_errors("cli/send", doc) != []


def test_golden_request_body(golden: Golden) -> None:
    n = validate_notification(
        {
            "title": "Deploy",
            "message": "Deploy finished",
            "level": "action",
            "actions": [
                {"title": "Open dashboard", "uri": "HTTPS://ha.example/lovelace/0?x=1#y"},
                {"title": "Logs é😀", "uri": "http://logs.example:8080/run/1"},
            ],
        }
    )
    out = render(
        n, max_chars=1000, default_group="ops", level_prefix=PREFIX, tag="awkit-0123456789abcdef01234567"
    )
    golden.check("request", "actions.json", serialize(out.body).decode("utf-8"))


# --- schema agreement and hostile input ----------------------------------------------------


def test_schema_samples_agree_with_the_tool() -> None:
    import pathlib

    samples = json.loads(
        (pathlib.Path(__file__).parent / "samples" / "notification.json").read_text("utf-8")
    )
    for name, inst in samples["valid"].items():
        if "actions" in inst:
            assert schema_errors("notification", inst) == [], name
            validate_notification(inst)
    count = 0
    for name, sample in samples["invalid"].items():
        inst = sample["instance"]
        if not isinstance(inst, dict) or "actions" not in inst:
            continue
        count += 1
        assert schema_errors("notification", inst) != [], name
        assert refusal(inst).reason in {"invalid_payload", "link_invalid", "link_scheme"}, name
    assert count >= 5


def test_the_nesting_cap_still_applies_inside_actions() -> None:
    deep = '{"message":"m","actions":[{"title":"t","uri":"https://a.example","x":' + "[" * 101
    deep += "]" * 101 + "}]}"
    with pytest.raises(PayloadError) as info:
        parse_notification(deep.encode())
    assert (info.value.reason, info.value.pointer) == ("invalid_payload", "")


def test_hostile_one_mebibyte_input_with_many_actions_is_refused_fast() -> None:
    item = '{"title":"t","uri":"https://a.example/"}'
    body = '{"message":"m","actions":[' + ",".join([item] * 25000) + "]}"
    assert 900_000 < len(body) <= 1_048_576
    start = time.monotonic()
    with pytest.raises(PayloadError) as info:
        parse_notification(body.encode())
    assert (info.value.reason, info.value.pointer) == ("invalid_payload", "/actions")
    assert time.monotonic() - start < 2 + LOAD_SLACK_S


def test_hostile_long_titles_and_uris_are_bounded() -> None:
    items = [act(title="\u200b" * 99999 + "x", uri="https://a.example/" + "%" * 900)] * 3
    start = time.monotonic()
    with pytest.raises(PayloadError):
        validate_notification(note(items))
    assert time.monotonic() - start < 2 + LOAD_SLACK_S


def test_parse_notification_accepts_actions_from_json_bytes() -> None:
    raw = json.dumps(note([act("é")]), ensure_ascii=False).encode()
    assert parse_notification(raw).actions == (Action("é", "https://a.example/x"),)
