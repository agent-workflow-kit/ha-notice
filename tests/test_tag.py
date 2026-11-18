"""Tag derivation from the dedupe key (docs/interface.md, Rendering, ``tag``; issue #18)."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys

import pytest

from ha_notice.cli import DEDUPE_KEY_MAX
from ha_notice.payload import Notification
from ha_notice.render import render, tag_from_dedupe_key

# Computed outside Python with ``printf '%s' <key> | sha256sum | cut -c1-24``.
VECTORS = [
    ("a", "awkit-ca978112ca1bbdcafac231b3"),
    ("-abc", "awkit-649d85fcc5d7e13d1217fc85"),
    ("é", "awkit-4a99557e4033c3539de2eb65"),
    ("\U0001f600", "awkit-f0443a342c5ef54783a111b5"),
    ("a\x00b", "awkit-59b271ae1bbcb1d31d419298"),
    ("a\nb", "awkit-7e18f737311b2dc3b2f269dd"),
    ("a" * 1024, "awkit-2edc986847e209b4016e141a"),
]


@pytest.mark.parametrize(("key", "tag"), VECTORS)
def test_fixed_vectors(key: str, tag: str) -> None:
    assert tag_from_dedupe_key(key) == tag


def test_matches_the_interface_formula() -> None:
    key = "router:backup:42"
    expected = "awkit-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
    assert tag_from_dedupe_key(key) == expected


@pytest.mark.parametrize("key", ["a", "é", "x" * 1024, "\x00", "\n", "Ünï😀"])
def test_shape_is_lowercase_hex_and_does_not_contain_the_key(key: str) -> None:
    tag = tag_from_dedupe_key(key)
    assert re.fullmatch(r"awkit-[0-9a-f]{24}", tag)
    assert key not in tag


def test_deterministic_and_distinct() -> None:
    assert tag_from_dedupe_key("k") == tag_from_dedupe_key("k")
    keys = ["a", "A", "a ", " a", "a\n", "a\x00", "\x00a", "é", "é"]
    assert len({tag_from_dedupe_key(k) for k in keys}) == len(keys)


def test_key_is_not_normalized_or_case_folded() -> None:
    assert tag_from_dedupe_key("é") != tag_from_dedupe_key("é")
    assert tag_from_dedupe_key("K") != tag_from_dedupe_key("k")


def test_accepts_the_longest_key_the_cli_accepts() -> None:
    assert DEDUPE_KEY_MAX == 1024
    tag_from_dedupe_key("x" * DEDUPE_KEY_MAX)
    with pytest.raises(ValueError, match="dedupe key"):
        tag_from_dedupe_key("x" * (DEDUPE_KEY_MAX + 1))


def test_empty_key_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="dedupe key"):
        tag_from_dedupe_key("")


@pytest.mark.parametrize("key", ["\ud800", "a\udc80b", "\udcff"])
def test_lone_surrogate_is_a_plain_value_error_without_the_key(key: str) -> None:
    # The CLI refuses these (exit 2 usage) before a tag is derived; here they must not escape
    # as an UnicodeEncodeError that echoes the text, and must never be replaced silently.
    with pytest.raises(ValueError, match="UTF-8") as exc:
        tag_from_dedupe_key(key)
    assert type(exc.value) is ValueError
    assert "a" not in str(exc.value).replace("dedupe key is not valid UTF-8", "")


def test_non_string_is_refused() -> None:
    with pytest.raises(TypeError):
        tag_from_dedupe_key(b"a")  # type: ignore[arg-type]


def test_derived_tag_is_accepted_by_render_and_lands_in_data() -> None:
    n = Notification(message="hello", level="info", title=None, link=None)
    tag = tag_from_dedupe_key("k")
    out = render(
        n, max_chars=1000, default_group=None, level_prefix={"info": ""}, tag=tag
    )
    assert out.body["data"] == {"tag": tag}


@pytest.mark.parametrize(("key", "tag"), VECTORS)
def test_independent_of_locale_and_environment(key: str, tag: str) -> None:
    code = (
        "import sys; from ha_notice.render import tag_from_dedupe_key as t; "
        "sys.stdout.write(t(sys.argv[1].encode().decode('utf-8')))"
    )
    env = {"LC_ALL": "C", "PYTHONUTF8": "0", "PYTHONHASHSEED": "random"}
    for name in ("PATH", "PYTHONPATH", "VIRTUAL_ENV"):
        if name in os.environ:
            env[name] = os.environ[name]
    # The key crosses a process boundary in a file, never argv, to stay locale-free.
    out = subprocess.run(
        [sys.executable, "-I", "-c", code.replace("sys.argv[1].encode().decode('utf-8')", "open(0, 'rb').read().decode('utf-8')")],
        input=key.encode("utf-8"),
        env=env,
        capture_output=True,
        check=True,
        timeout=60,
    )
    assert out.stdout.decode() == tag
