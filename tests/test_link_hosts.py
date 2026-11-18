"""``link_hosts``: the key grammar, the ``Config`` accessor and the host match (issue #16)."""

from __future__ import annotations

from pathlib import Path

import pytest

from ha_notice import config
from ha_notice.config import ConfigError
from ha_notice.link import link_host_allowed
from ha_notice.payload import PayloadError, validate_notification
from tests.fake_gateway import FakeGateway

ENTRY_GOOD = [
    "example.com",
    "a.example.com",
    "a-b.example.com",
    "1.2.3.4",  # digits are labels; it can only equal a link host that is written the same way
    "xn--bcher-kva.example",
    "a.b",
    "0.0",
    "a" * 63 + "." + "b" * 63,
    ".".join(["a"] * 127),  # 253 characters
]
ENTRY_BAD = [
    "",
    "com",
    ".example.com",
    "example.com.",
    ".",
    "..",
    "a..b",
    "Example.com",
    "EXAMPLE.COM",
    "-a.example.com",
    "a-.example.com",
    "a_b.example.com",
    "a b.example.com",
    "example.com\n",
    "example.com/",
    "example.com:443",
    "https://example.com",
    "*.example.com",
    "[::1]",
    "::1",
    "bücher.example",
    "ｅxample.com",  # fullwidth e
    "exampleK.com",  # Kelvin sign
    "ſ.example.com",  # long s
    "a" * 64 + ".example.com",
    ".".join(["a"] * 127) + "a",  # 254 characters
    "a" * 254,
    "exam\x00ple.com",
    "example.com\ud800",
]


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    (path / ".config" / "ha-notice").mkdir(parents=True)
    return path


@pytest.fixture
def gw(home: Path) -> FakeGateway:
    return FakeGateway(home=str(home))


def write(home: Path, text: str, name: str = "config.yaml") -> None:
    base = home / ".config" / "ha-notice"
    target = base / "config.d" / name if name != "config.yaml" else base / name
    target.parent.mkdir(exist_ok=True)
    target.write_text(text, encoding="utf-8")


def yaml_list(items: list[str]) -> str:
    # Every character escaped, so control and odd code points reach the grammar check.
    return "link_hosts:\n" + "".join(
        '  - "' + "".join(f"\\U{ord(c):08x}" for c in item) + '"\n' for item in items
    )


def load(gw: FakeGateway) -> config.Config:
    return config.load(gw, None)


# --- the key ---------------------------------------------------------------------------------


@pytest.mark.parametrize("entry", ENTRY_GOOD)
def test_good_entry(gw: FakeGateway, home: Path, entry: str) -> None:
    write(home, yaml_list([entry]))
    assert load(gw).link_hosts == (entry,)


@pytest.mark.parametrize("entry", ENTRY_BAD)
def test_bad_entry_is_config_invalid_naming_the_key(
    gw: FakeGateway, home: Path, entry: str
) -> None:
    write(home, yaml_list(["example.org", entry]))
    with pytest.raises(ConfigError) as info:
        load(gw)
    assert info.value.key == "link_hosts"
    shown = repr(info.value.error.envelope)
    assert "example.org" not in shown
    if len(entry) >= 8:  # shorter ones can collide with envelope words ("com", "::1")
        assert entry not in shown


@pytest.mark.parametrize(
    "marker", ["zz-marker-Q9", "zz-marker-Q9.", "ZZ-marker-Q9.com", "zz_Q9.com"]
)
def test_a_bad_entry_with_a_unique_marker_is_never_echoed(
    gw: FakeGateway, home: Path, marker: str
) -> None:
    write(home, yaml_list(["example.org", marker]))
    with pytest.raises(ConfigError) as info:
        load(gw)
    assert info.value.key == "link_hosts"
    assert "Q9" not in repr(info.value.error.envelope)


def test_unset_is_none(gw: FakeGateway) -> None:
    assert load(gw).link_hosts is None


def test_empty_list_is_config_invalid(gw: FakeGateway, home: Path) -> None:
    write(home, "link_hosts: []\n")
    with pytest.raises(ConfigError) as info:
        load(gw)
    assert info.value.key == "link_hosts"


def test_32_entries_pass_and_33_fail(gw: FakeGateway, home: Path) -> None:
    names = [f"h{i}.example.com" for i in range(33)]
    write(home, yaml_list(names[:32]))
    assert load(gw).link_hosts == tuple(names[:32])
    write(home, yaml_list(names))
    with pytest.raises(ConfigError) as info:
        load(gw)
    assert info.value.key == "link_hosts"


def test_duplicates_are_accepted_and_kept(gw: FakeGateway, home: Path) -> None:
    write(home, yaml_list(["example.com", "example.com"]))
    assert load(gw).link_hosts == ("example.com", "example.com")


@pytest.mark.parametrize(
    "text", ["link_hosts: example.com\n", "link_hosts: 1\n", "link_hosts: ~\n"]
)
def test_a_non_list_is_config_invalid(gw: FakeGateway, home: Path, text: str) -> None:
    write(home, text)
    with pytest.raises(ConfigError) as info:
        load(gw)
    assert info.value.key == "link_hosts"


def test_a_later_drop_in_replaces_the_whole_list(gw: FakeGateway, home: Path) -> None:
    write(home, yaml_list(["a.example.com", "b.example.com"]))
    write(home, yaml_list(["c.example.com"]), "10-more.yaml")
    assert load(gw).link_hosts == ("c.example.com",)


def test_the_accessor_is_a_tuple_so_a_caller_cannot_grow_the_allowed_list(
    gw: FakeGateway, home: Path
) -> None:
    write(home, yaml_list(["a.example.com"]))
    cfg = load(gw)
    before = repr(cfg.values["link_hosts"])
    hosts = cfg.link_hosts
    assert isinstance(hosts, tuple)
    with pytest.raises(TypeError):
        hosts[0] = "evil.com"  # type: ignore[index]
    grown = list(hosts) + ["evil.com"]
    assert grown[-1] == "evil.com"
    assert cfg.link_hosts == ("a.example.com",)
    assert repr(cfg.values["link_hosts"]) == before


def test_entry_grammar_agrees_with_the_schema_pattern() -> None:
    import json
    import re

    root = Path(__file__).resolve().parent.parent
    schema = json.loads((root / "schemas" / "config.json").read_text(encoding="utf-8"))
    item = schema["properties"]["link_hosts"]["items"]
    for entry in ENTRY_GOOD + ENTRY_BAD:
        in_schema = len(entry) <= item["maxLength"] and re.search(item["pattern"], entry)
        assert config.link_host_entry_ok(entry) == bool(in_schema), repr(entry)


# --- matching --------------------------------------------------------------------------------

MATCH = [
    ("https://example.com", ["example.com"], True),
    ("https://example.com/x?y#z", ["example.com"], True),
    ("https://EXAMPLE.com/", ["example.com"], True),
    ("HTTPS://Example.COM:8443/", ["example.com"], True),
    ("https://a.example.com/", ["example.com"], True),
    ("https://a.b.example.com/", ["example.com"], True),
    ("https://a.b.example.com/", ["b.example.com"], True),
    ("https://a.example.com/", ["x.org", "example.com"], True),
    ("https://example.com:1/", ["example.com"], True),
    ("https://xn--bcher-kva.example/", ["xn--bcher-kva.example"], True),
    ("https://1.2.3.4/", ["1.2.3.4"], True),
    # Plain suffix test on the host text: a numeric entry matches IPv4 hosts ending in it.
    ("https://9.1.2.3.4/", ["1.2.3.4"], True),
    ("https://127.0.0.1/", ["0.1"], True),
    ("https://evil-example.com/", ["example.com"], False),
    ("https://evilexample.com/", ["example.com"], False),
    ("https://example.com.evil/", ["example.com"], False),
    ("https://example.com.evil.org/", ["example.com"], False),
    ("https://example.org/", ["example.com"], False),
    ("https://com/", ["example.com"], False),
    ("https://localhost/", ["example.com"], False),
    ("https://b.example.com/", ["a.example.com"], False),  # a sibling, not a subdomain
    ("https://example.com/", ["a.example.com"], False),  # a parent is not matched
    ("https://2130706433/", ["example.com"], False),
    ("https://2130706433/", ["2130706433.com"], False),
    ("https://[::1]/", ["example.com"], False),  # a bracket host is never matched
    ("https://[::1]/", ["1.example", "::1"], False),
    ("https://[2001:db8::1]:8443/", ["example.com"], False),
    ("https://example.com@evil.org/", ["example.com"], False),  # userinfo is the link rule's
    ("https://a.example.com/", [], False),  # defensive: nothing allowed
]


@pytest.mark.parametrize(("link", "hosts", "ok"), MATCH)
def test_link_host_allowed(link: str, hosts: list[str], ok: bool) -> None:
    from ha_notice.link import link_reason

    if "@" not in link:
        assert link_reason(link) is None
        assert link_host_allowed(link, hosts) is ok


@pytest.mark.parametrize(("link", "hosts", "ok"), MATCH)
def test_validate_notification_with_link_hosts(link: str, hosts: list[str], ok: bool) -> None:
    obj = {"message": "m", "link": link}
    if "@" in link:
        with pytest.raises(PayloadError) as info:
            validate_notification(obj, link_hosts=hosts)
        assert (info.value.reason, info.value.pointer) == ("link_invalid", None)
    elif ok:
        assert validate_notification(obj, link_hosts=hosts).link == link
    else:
        with pytest.raises(PayloadError) as info:
            validate_notification(obj, link_hosts=hosts)
        err = info.value
        assert (err.reason, err.pointer) == ("link_invalid", "/link")
        error = err.to_error().envelope["error"]
        assert error["details"] == {"pointer": "/link"}


def test_unset_means_no_restriction() -> None:
    for link in ["https://2130706433/", "https://[::1]/", "https://anything.example/"]:
        assert validate_notification({"message": "m", "link": link}).link == link
        assert validate_notification({"message": "m", "link": link}, link_hosts=None).link == link


def test_link_hosts_without_a_link_changes_nothing() -> None:
    assert validate_notification({"message": "m"}, link_hosts=["example.com"]).link is None


def test_plain_link_failures_win_over_the_host_check() -> None:
    for link, reason in [("javascript:x", "link_scheme"), ("https://a.example/ x", "link_invalid")]:
        with pytest.raises(PayloadError) as info:
            validate_notification({"message": "m", "link": link}, link_hosts=["example.com"])
        assert (info.value.reason, info.value.pointer) == (reason, None)


def test_host_refusal_comes_before_empty_message_and_command_keyword() -> None:
    for obj in [{"link": "https://evil.org/"}, {"message": "tts", "link": "https://evil.org/"}]:
        with pytest.raises(PayloadError) as info:
            validate_notification(obj, link_hosts=["example.com"])
        assert info.value.pointer == "/link"


def test_refusal_never_echoes_the_link() -> None:
    with pytest.raises(PayloadError) as info:
        validate_notification(
            {"message": "m", "link": "https://SECRET-HOST.evil.org/"}, link_hosts=["example.com"]
        )
    assert "SECRET" not in repr(info.value.to_error().envelope)


def test_a_long_link_and_many_labels_are_linear() -> None:
    link = "https://" + ".".join(["a"] * 500) + ".example.com/"
    assert len(link) <= 1024
    assert link_host_allowed(link, ["example.com"] * 32) is True
    assert link_host_allowed(link, ["example.org"] * 32) is False
