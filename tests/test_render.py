"""Request rendering: title and message cuts, level prefix, the data allowlist, serialization
(docs/interface.md, Rendering; issue #17)."""

from __future__ import annotations

import hashlib
import json
import random
import time
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from ha_notice.config import DEFAULTS
from ha_notice.payload import Notification, validate_notification
from ha_notice.render import MARKER, Rendered, render, serialize
from tests.harness import Golden, load_schema

PREFIX = dict(DEFAULTS["level_prefix"])
TAG = "awkit-0123456789abcdef01234567"
RENDERED_SCHEMA = Draft202012Validator(load_schema("cli/send")["properties"]["rendered"])


def r(
    message: str = "hello",
    *,
    title: str | None = None,
    level: str = "info",
    link: str | None = None,
    max_chars: int = 1000,
    group: str | None = None,
    prefix: dict[str, str] | None = None,
    tag: str | None = None,
) -> Rendered:
    n = Notification(message=message, level=level, title=title, link=link)
    return render(
        n,
        max_chars=max_chars,
        default_group=group,
        level_prefix=PREFIX if prefix is None else prefix,
        tag=tag,
    )


def nbytes(s: str) -> int:
    return len(s.encode("utf-8"))


def test_marker_is_ellipsis_and_word() -> None:
    assert MARKER == "…[truncated]"


# --- title ---------------------------------------------------------------------------------


def test_plain_body_has_message_only() -> None:
    out = r("hello")
    assert out.body == {"message": "hello"}
    assert out.truncated is False


def test_key_order_title_message_data() -> None:
    out = r("m", title="t", link="https://a.example/", group="g", tag=TAG)
    assert list(out.body) == ["title", "message", "data"]
    assert list(out.body["data"]) == ["url", "clickAction", "tag", "group"]


def test_title_omitted_when_empty_and_no_prefix() -> None:
    assert "title" not in r("m", title=None).body
    assert "title" not in r("m", title="").body


def test_empty_title_with_prefix_is_prefix_alone() -> None:
    assert r("m", title=None, level="warn").body["title"] == "WARN:"
    assert r("m", title="", level="error").body["title"] == "ERROR:"


def test_prefix_joined_with_one_space() -> None:
    assert r("m", title="disk", level="action").body["title"] == "ACTION: disk"
    assert r("m", title="disk", level="info").body["title"] == "disk"


def test_title_of_256_is_not_cut() -> None:
    out = r("m", title="t" * 256)
    assert out.body["title"] == "t" * 256
    assert out.truncated is False


def test_title_of_257_is_cut_to_255_plus_ellipsis() -> None:
    out = r("m", title="t" * 257)
    assert out.body["title"] == "t" * 255 + "…"
    assert len(out.body["title"]) == 256
    assert out.truncated is True


def test_prefix_is_added_after_the_cut_and_does_not_count() -> None:
    out = r("m", title="t" * 1000, level="warn")
    assert out.body["title"] == "WARN: " + "t" * 255 + "…"
    assert len(out.body["title"]) == 262


def test_longest_prefix_gives_273_characters() -> None:
    out = r("m", title="t" * 300, prefix={**PREFIX, "error": "E" * 16}, level="error")
    assert len(out.body["title"]) == 16 + 1 + 256 == 273


def test_title_cut_counts_code_points_not_bytes() -> None:
    out = r("m", title="\U0001f600" * 300)
    assert out.body["title"] == "\U0001f600" * 255 + "…"


def test_title_cut_may_split_a_combining_sequence() -> None:
    out = r("m", title="a" * 254 + "e\u0301" + "z")
    assert out.body["title"] == "a" * 254 + "e" + "…"


def test_title_cut_sets_truncated_even_when_message_fits() -> None:
    assert r("m", title="x" * 999).truncated is True


# --- message -------------------------------------------------------------------------------


def test_message_of_exactly_max_chars_is_not_cut() -> None:
    out = r("a" * 100, max_chars=100)
    assert out.body["message"] == "a" * 100
    assert out.truncated is False


def test_message_one_over_max_chars_is_cut() -> None:
    out = r("a" * 101, max_chars=100)
    assert out.body["message"] == "a" * 88 + MARKER
    assert len(out.body["message"]) == 100
    assert out.truncated is True


def test_message_cut_removes_trailing_whitespace_before_the_marker() -> None:
    out = r("a" * 87 + " " + "b" * 20, max_chars=100)
    assert out.body["message"] == "a" * 87 + MARKER
    out = r("a" * 78 + " \n\n" + " " * 7 + "b" * 40, max_chars=100)
    assert out.body["message"] == "a" * 78 + MARKER
    out = r("a" * 86 + "\n\n" + "b" * 40, max_chars=100)
    assert out.body["message"] == "a" * 86 + MARKER


def test_message_cut_keeps_internal_whitespace() -> None:
    out = r("a b\n\nc " * 40, max_chars=100)
    assert out.body["message"].endswith(MARKER)
    assert "a b\n\nc" in out.body["message"]
    assert len(out.body["message"]) <= 100


def test_ascii_byte_limit_binds_before_a_large_max_chars() -> None:
    assert r("a" * 2000, max_chars=2000).body["message"] == "a" * 2000
    out = r("a" * 2001, max_chars=2000)
    assert out.body["message"] == "a" * 1986 + MARKER
    assert nbytes(out.body["message"]) == 2000
    assert len(out.body["message"]) == 1998


def test_message_of_exactly_2000_bytes_is_not_cut() -> None:
    msg = "あ" * 666 + "ab"  # 1998 + 2 bytes, 668 characters
    assert nbytes(msg) == 2000
    out = r(msg, max_chars=1000)
    assert out.body["message"] == msg
    assert out.truncated is False


def test_message_of_2001_bytes_is_cut() -> None:
    msg = "あ" * 667  # 2001 bytes
    out = r(msg, max_chars=1000)
    assert out.body["message"] == "あ" * 662 + MARKER
    assert nbytes(out.body["message"]) == 2000
    assert out.truncated is True


def test_four_byte_characters_cut_at_a_code_point() -> None:
    msg = "\U0001f600" * 600  # 2400 bytes
    out = r(msg, max_chars=1000)
    assert out.body["message"] == "\U0001f600" * 496 + MARKER
    assert nbytes(out.body["message"]) == 1984 + 14 == 1998


def test_four_byte_boundary_one_byte_short_and_exact() -> None:
    # 1986 bytes of budget; 3 ASCII bytes first so the 4-byte characters end at 1983 + 4 = 1987.
    msg = "abc" + "\U0001f600" * 600
    out = r(msg, max_chars=2000)
    assert out.body["message"] == "abc" + "\U0001f600" * 495 + MARKER
    assert nbytes(out.body["message"]) == 3 + 1980 + 14
    msg = "ab" + "\U0001f600" * 600  # 2 + 4k <= 1986 gives k = 496 exactly
    out = r(msg, max_chars=2000)
    assert out.body["message"] == "ab" + "\U0001f600" * 496 + MARKER
    assert nbytes(out.body["message"]) == 2000


def test_two_byte_characters() -> None:
    out = r("é" * 1500, max_chars=2000)
    assert out.body["message"] == "é" * 993 + MARKER
    assert nbytes(out.body["message"]) == 1986 + 14


def test_max_chars_binds_before_bytes_for_ascii() -> None:
    out = r("a" * 500, max_chars=100)
    assert len(out.body["message"]) == 100


@pytest.mark.parametrize("max_chars", [100, 101, 555, 1000, 1999, 2000])
@pytest.mark.parametrize("unit", ["a", "é", "あ", "\U0001f600", "a \n"])
def test_cut_message_fits_every_limit_and_is_the_longest(max_chars: int, unit: str) -> None:
    msg = (unit * 2500).strip()
    out = r(msg, max_chars=max_chars)
    m = out.body["message"]
    assert out.truncated is True
    assert m.endswith(MARKER)
    kept = m[: -len(MARKER)]
    assert len(m) <= max_chars
    assert nbytes(m) <= 2000
    assert msg.startswith(kept)
    assert kept == kept.rstrip()
    # longest: the next character (and the whitespace run after it) would not fit
    nxt = msg[len(kept) : len(kept) + 1]
    longer = (kept + nxt).rstrip()
    if longer != kept:
        grown = longer + MARKER
        assert len(grown) > max_chars or nbytes(grown) > 2000


@pytest.mark.parametrize("seed", range(20))
def test_cut_matches_a_brute_force_oracle(seed: int) -> None:
    rng = random.Random(seed)
    msg = "".join(rng.choice(["a", "b", " ", "\n", "é", "あ", "\U0001f600"]) for _ in range(900))
    msg = msg.strip() or "x"
    max_chars = rng.choice([100, 150, 400])
    best = None
    for n in range(len(msg) + 1):
        cand = msg[:n].rstrip() + MARKER
        if len(cand) <= max_chars and nbytes(cand) <= 2000:
            best = cand
    out = r(msg, max_chars=max_chars)
    assert out.truncated is True
    assert out.body["message"] == best


def test_cut_may_split_a_combining_or_zwj_sequence() -> None:
    out = r("a" * 87 + "e\u0301" + "z" * 50, max_chars=100)
    assert out.body["message"] == "a" * 87 + "e" + MARKER
    family = "\U0001f468‍\U0001f469‍\U0001f467"
    out = r("a" * 85 + family + "z" * 50, max_chars=100)
    assert out.body["message"] == "a" * 85 + family[:3] + MARKER


def test_no_lone_surrogate_in_cut_output() -> None:
    out = r("\U0001f600" * 700)
    out.body["message"].encode("utf-8")  # raises on a lone surrogate


def test_message_truncated_flag_false_when_nothing_cut() -> None:
    assert r("short", title="short", level="warn").truncated is False


def test_prefix_does_not_reduce_the_message_budget() -> None:
    a = r("a" * 100, max_chars=100, level="error", title="t")
    assert a.body["message"] == "a" * 100


def test_cut_message_is_never_a_command_keyword() -> None:
    # The keyword rule ran on the full text; a cut message ends in the marker.
    msg = validate_notification({"message": "update_deps " + "x" * 3000}).message
    out = render(Notification(message=msg), max_chars=100, default_group=None, level_prefix=PREFIX)
    assert out.body["message"].endswith(MARKER)


# --- data allowlist ------------------------------------------------------------------------


def test_link_scheme_is_lowercased_and_rest_unchanged() -> None:
    out = r("m", link="HTTPS://X.Example/Path?Q=A#Frag")
    assert out.body["data"] == {
        "url": "https://X.Example/Path?Q=A#Frag",
        "clickAction": "https://X.Example/Path?Q=A#Frag",
    }
    assert r("m", link="HtTp://a.example").body["data"]["url"] == "http://a.example"


def test_link_given_lowercase_is_unchanged() -> None:
    assert r("m", link="https://a.example/HTTPS://").body["data"]["url"] == (
        "https://a.example/HTTPS://"
    )


@pytest.mark.parametrize("bad", ["ftp://a.example", "javascript:x", "a.example", "", "https:/x"])
def test_link_that_is_not_http_is_a_programming_error(bad: str) -> None:
    with pytest.raises(ValueError):
        r("m", link=bad)


def test_notification_link_is_not_modified() -> None:
    n = Notification(message="m", link="HTTPS://a.example")
    render(n, max_chars=1000, default_group=None, level_prefix=PREFIX)
    assert n.link == "HTTPS://a.example"


def test_no_data_without_link_tag_group() -> None:
    assert "data" not in r("m").body


def test_group_only() -> None:
    assert r("m", group="ops_1-x").body["data"] == {"group": "ops_1-x"}


def test_tag_only_and_tag_pattern_enforced() -> None:
    assert r("m", tag=TAG).body["data"] == {"tag": TAG}
    for bad in [
        "awkit-" + "0" * 23,
        "awkit-" + "0" * 25,
        "awkit-" + "A" * 24,
        TAG + "\n",
        "x" + TAG,
        "",
        "awkit-" + "g" * 24,
    ]:
        with pytest.raises(ValueError):
            r("m", tag=bad)


@pytest.mark.parametrize("bad", ["", " ", "a b", "g\n", "a" * 65, "é", "a/b"])
def test_group_pattern_enforced(bad: str) -> None:
    with pytest.raises(ValueError):
        r("m", group=bad)


def test_unknown_level_is_a_programming_error() -> None:
    with pytest.raises(ValueError):
        r("m", level="debug")


def test_render_accepts_no_data_argument() -> None:
    n = Notification(message="m")
    extra: dict[str, Any] = {"data": {"tts_text": "x"}}
    with pytest.raises(TypeError):
        render(n, max_chars=1000, default_group=None, level_prefix=PREFIX, **extra)


ALLOWED = ["url", "clickAction", "tag", "group"]
FORBIDDEN = ["tts_text", "media_stream", "command", "clear_notification"]


def test_data_allowlist_fuzz() -> None:
    rng = random.Random(1717)
    alphabet = "ab \néあ\U0001f600‍́:/_-\"\\'<>{}"
    for _ in range(400):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 3000)))
        obj: dict[str, Any] = {"message": "m" + text}
        if rng.random() < 0.7:
            obj["title"] = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 400)))
        obj["level"] = rng.choice(["info", "warn", "action", "error"])
        if rng.random() < 0.5:
            obj["link"] = rng.choice(["HTTPS://a.example/x", "http://b.example:80/?q=1#f"])
        n = validate_notification(obj)
        out = render(
            n,
            max_chars=rng.randrange(100, 2001),
            default_group=rng.choice([None, "g1"]),
            level_prefix=PREFIX,
            tag=rng.choice([None, TAG]),
        )
        assert list(out.body) in (
            ["message"],
            ["title", "message"],
            ["message", "data"],
            ["title", "message", "data"],
        )
        data = out.body.get("data", {})
        assert [k for k in data] == [k for k in ALLOWED if k in data]
        assert not set(data) - set(ALLOWED)
        assert not set(FORBIDDEN) & set(data)
        assert not list(RENDERED_SCHEMA.iter_errors(out.body))


def test_data_is_never_built_from_text_fields() -> None:
    n = Notification(
        message="tts_text media_stream command",
        title='{"data":{"tts_text":"x"}}',
        level="info",
    )
    out = render(n, max_chars=1000, default_group=None, level_prefix=PREFIX)
    assert "data" not in out.body


# --- purity --------------------------------------------------------------------------------


def test_inputs_are_not_mutated() -> None:
    prefix = dict(PREFIX)
    n = Notification(message="a" * 3000, title="t" * 300, level="warn", link="HTTPS://a.example")
    before = (n.message, n.title, n.level, n.link)
    render(n, max_chars=100, default_group="g", level_prefix=prefix, tag=TAG)
    assert prefix == PREFIX
    assert (n.message, n.title, n.level, n.link) == before


def test_render_is_repeatable() -> None:
    n = Notification(message="a" * 3000, title="t" * 300, level="warn", link="HTTPS://a.example")
    kw: dict[str, Any] = dict(max_chars=500, default_group="g", level_prefix=PREFIX, tag=TAG)
    assert render(n, **kw) == render(n, **kw)


def test_max_size_input_is_fast() -> None:
    n = Notification(message="\U0001f600 " * 50000, title="t " * 50000)
    start = time.perf_counter()
    for _ in range(20):
        render(n, max_chars=2000, default_group=None, level_prefix=PREFIX)
    assert time.perf_counter() - start < 2.0


# --- serialization -------------------------------------------------------------------------


def test_serialize_is_compact_utf8_without_ascii_escaping() -> None:
    raw = serialize({"title": "é\U0001f600", "message": 'a"b\\c\nd'})
    assert raw == '{"title":"é\U0001f600","message":"a\\"b\\\\c\\nd"}'.encode()


def test_serialize_keeps_key_order() -> None:
    body = {"title": "t", "message": "m", "data": {"url": "u", "clickAction": "u", "group": "g"}}
    assert serialize(body) == (
        b'{"title":"t","message":"m","data":{"url":"u","clickAction":"u","group":"g"}}'
    )


def test_serialized_body_has_no_raw_control_characters() -> None:
    n = validate_notification({"message": "a\x00b\x1f\n\n\nc d﻿" * 300, "title": "x\ny"})
    raw = serialize(render(n, max_chars=500, default_group=None, level_prefix=PREFIX).body)
    assert all(b >= 0x20 for b in raw)
    assert b"\x7f" not in raw
    assert "\x00" not in json.loads(raw)["message"]


def test_serialized_body_round_trips() -> None:
    out = r("m\n\nあ" * 700, title="t" * 300, level="warn", link="HTTPS://a.example", tag=TAG)
    assert json.loads(serialize(out.body)) == out.body


def test_serialized_size_is_bounded() -> None:
    out = r(
        "\U0001f600" * 2000,
        title="\U0001f600" * 400,
        level="error",
        link="https://a.e/" + "a" * 1011,
    )
    assert len(serialize(out.body)) < 8000


# Pinned by hand: sha256 of the golden request body bytes (not derived from the code).
GOLDEN_FULL_SHA256 = "e9e88aa2e48bea35e37fab15e6fdc0c11993a9f936184ec1bfc3619fd103bdd7"


def golden_full_body() -> bytes:
    msg = 'Schöne Grüße \U0001f600 "quoted" \\ back\nsecond line\n\n' + "あ" * 700
    out = r(
        msg,
        title="Backup échoué",
        level="error",
        link="HTTPS://ha.example/lovelace/0?x=1#y",
        group="ops",
        tag=TAG,
    )
    return serialize(out.body)


def test_golden_request_body(golden: Golden) -> None:
    raw = golden_full_body()
    golden.check("request", "full.json", raw.decode("utf-8"))
    assert hashlib.sha256(raw).hexdigest() == GOLDEN_FULL_SHA256


def test_golden_minimal_request_body(golden: Golden) -> None:
    raw = serialize(r("hello").body)
    golden.check("request", "minimal.json", raw.decode("utf-8"))
    assert raw == b'{"message":"hello"}'
