"""The link rule (docs/interface.md, Notification: link rule; issue #15)."""

from __future__ import annotations

import time
from typing import Any

import pytest

from ha_notice.link import link_reason
from ha_notice.payload import PayloadError, validate_notification
from tests.timing import LOAD_SLACK_S

PREFIX = "https://a.example/"

ACCEPTED = [
    "https://a.example",
    "https://a.example/",
    "http://a.example/",
    "HTTPS://x.example",
    "HtTp://x.example",
    "https://a.example/%41",
    "https://a.example/p'q(r)",
    "https://a.example/a?b=c&d=e#frag",
    "https://a.example?x",
    "https://a.example#x",
    "https://a.example/#",
    "https://a.example/?",
    "https://a.example:1",
    "https://a.example:65535/",
    "https://a.example:080/",
    "https://xn--bcher-kva.example/",
    "https://localhost",
    "https://[::1]/",
    "http://[::1]/",
    "https://[2001:db8::1]:8443/x",
    "https://[::ffff:1.2.3.4]/",
    "https://2130706433/",
    "https://1.2.3.4/",
    "https://a.example/a@b:c",
    "https://a.example//x",
    "https://a.example/" + "a" * (1024 - len("https://a.example/")),
]

# (link, reason): refused with link_invalid by the grammar.
INVALID = [
    "",
    'https://a.example/"x',
    "https://a.example/a|b",
    "https://a.example/{x}",
    "https://a.example/<x>",
    "https://a.example/a^b",
    "https://a.example/a`b",
    "https://a.example/a\\b",
    "https://a.example\\@evil.example",
    "https://a.example/%zz",
    "https://a.example/%4",
    "https://a.example/%",
    "https://a.example#a#b",
    "https://[8]/",
    "https://[a]/",
    "https://[:]#x",
    "https://[::1",
    "https://[::1]x/",
    "https://[::1%eth0]/",
    "https://[1:2:3:4:5:6:7:8:9]/",
    "https://[::g]/",
    "https://[]/",
    "https://:80/",
    "https:///x",
    "https://",
    "https://user@a.example/",
    "https://user:pw@a.example/",
    "https://@a.example/",
    "https://a.example:0/",
    "https://a.example:65536/",
    "https://a.example:99999/",
    "https://a.example:123456/",
    "https://a.example:/",
    "https://a.example:80:80/",
    "https://a.example:abc/",
    "https://a.example./",
    "https://.a.example/",
    "https://a..example/",
    "https://a_b.example/",
    "https://a.example /x",
    "https://a.example/ x",
    "https://a.example/\tx",
    "https://a.example/x\n",
    "https://a.example/x\r",
    "https://a.example/x\x00",
    "https://a.example/x\x7f",
    "https://a.example/\u00e9",
    "https://b\u00fccher.example/",
    "https://a.example/\U0001f600",
    "https://a.example/\ud800",
    "https://\uff41.example/",
    " https://a.example/",
    "https://a.example/ ",
    "//a.example/",
    "a.example/",
    "/x",
    "https:a.example",
    "https:/a.example",
    "https:\\\\a.example",
    "https//a.example",
    "http s://a.example",
    "1http://a.example",
    "-http://a.example",
    "https://a.example/" + "a" * (1025 - len("https://a.example/")),
    "https://a.example/" + "a" * 100000,
    "\u212attps://a.example/",  # not an ASCII scheme token at all
    "ht\u017fp://a.example/",
]

SCHEMES = [
    "javascript:x",
    "JavaScript:alert(1)",
    "data:text/html,x",
    "intent://x#Intent;end",
    "homeassistant://navigate/x",
    "app://x",
    "tel:+123",
    "mailto:a@b",
    "ftp://a.example/",
    "file:///etc/passwd",
    "example.com:80/x",
    "a:b",
    "h:",
    "httpx://a.example/",
    "https+x://a.example/",
    "http.s://a.example/",
    "x-y.z+w://a.example/",
]


@pytest.mark.parametrize("link", ACCEPTED)
def test_accepted(link: str) -> None:
    assert link_reason(link) is None


@pytest.mark.parametrize("link", INVALID)
def test_link_invalid(link: str) -> None:
    assert link_reason(link) == "link_invalid"


@pytest.mark.parametrize("link", SCHEMES)
def test_link_scheme(link: str) -> None:
    assert link_reason(link) == "link_scheme"


def test_scheme_is_judged_before_the_rest_of_the_link() -> None:
    # A bad scheme wins over a bad tail; a good scheme with a bad tail is link_invalid.
    assert link_reason('javascript:"') == "link_scheme"
    assert link_reason('https:"') == "link_invalid"
    assert link_reason("tel:+1 2") == "link_invalid"  # step 1 (space) comes first


def test_the_cap_is_exact_at_1024() -> None:
    ok = PREFIX + "a" * (1024 - len(PREFIX))
    assert len(ok) == 1024 and link_reason(ok) is None
    assert link_reason(ok + "a") == "link_invalid"


def test_hostile_inputs_are_linear() -> None:
    start = time.perf_counter()
    for link in (
        "https://" + "a." * 511,
        "https://" + "a-" * 511 + "!",
        "https://a.example/" + "%41" * 335 + "%",
        "https://a.example/" + "a" * 100000,
        "x" * 2_000_000,
        "https://[" + ":" * 1000 + "]/",
    ):
        link_reason(link)
    assert time.perf_counter() - start < 1.0 + LOAD_SLACK_S


def test_a_str_subclass_is_not_given_special_treatment() -> None:
    class S(str):
        pass

    assert link_reason(S("https://a.example/")) is None


# --- through validate_notification ----------------------------------------------------------


def refusal(obj: dict[str, Any]) -> PayloadError:
    with pytest.raises(PayloadError) as info:
        validate_notification(obj)
    return info.value


@pytest.mark.parametrize("link", ACCEPTED)
def test_notification_keeps_an_accepted_link_unchanged(link: str) -> None:
    # Lowercasing the scheme is rendering (#17); validation returns the link as given.
    assert validate_notification({"message": "m", "link": link}).link == link


@pytest.mark.parametrize("link", ["", 'https://a.example/"x', "https://a.example/x\n"])
def test_notification_link_invalid_has_no_details(link: str) -> None:
    err = refusal({"message": "m", "link": link})
    assert (err.reason, err.pointer) == ("link_invalid", None)
    error = err.to_error().envelope["error"]
    assert (error["reason"], error["details"]) == ("link_invalid", None)


def test_notification_link_scheme_has_no_details() -> None:
    err = refusal({"message": "m", "link": "javascript:x"})
    assert (err.reason, err.pointer) == ("link_scheme", None)
    assert err.to_error().envelope["error"]["details"] is None


def test_a_non_string_link_is_still_invalid_payload() -> None:
    for value in (None, 1, ["https://a.example"], True):
        err = refusal({"message": "m", "link": value})
        assert (err.reason, err.pointer) == ("invalid_payload", "/link")


def test_link_checks_come_before_empty_message_and_command_keyword() -> None:
    assert refusal({"message": "tts", "link": "javascript:x"}).reason == "link_scheme"
    assert refusal({"message": "tts", "link": "nope"}).reason == "link_invalid"
    assert refusal({"link": "nope"}).reason == "link_invalid"
    assert refusal({"message": " ", "link": "javascript:x"}).reason == "link_scheme"
    assert refusal({"message": "tts", "link": PREFIX}).reason == "command_keyword"
    assert refusal({"link": PREFIX}).reason == "empty_message"


def test_earlier_fields_still_win_over_the_link() -> None:
    err = refusal({"message": "m", "level": "bad", "link": "javascript:x"})
    assert (err.reason, err.pointer) == ("invalid_payload", "/level")
    err = refusal({"title": 1, "message": "m", "link": "javascript:x"})
    assert err.pointer == "/title"


def test_link_is_not_sanitized() -> None:
    # Characters the sanitizer would remove make the link invalid instead of silently changing it.
    assert refusal({"message": "m", "link": "https://a.example/\u200b"}).reason == "link_invalid"
