"""Config keys base_url, service, token_env, ca_file and the token (issue #10).

Grammar cases go through ``config.parse_base_url`` and, as a whole, through ``config.load`` on a
real file (like tests/test_config_keys.py). The schema is compared with the tool's checks.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

import pytest

from ha_notice import config
from ha_notice.config import BaseUrl, ConfigError, CredentialError
from ha_notice.gateway import SourceError
from tests.fake_gateway import FakeGateway
from tests.harness import load_schema, schema_errors

FAKE_TOKEN = "FAKE-TOKEN-zq7Wm3-do-not-leak"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    (path / ".config" / "ha-notice").mkdir(parents=True)
    return path


@pytest.fixture
def gw(home: Path) -> FakeGateway:
    return FakeGateway(home=str(home))


def write(home: Path, text: str, name: str = "config.yaml") -> None:
    path = home / ".config" / "ha-notice" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(text, encoding="utf-8")


def q(value: str) -> str:
    """A YAML double-quoted scalar with every character escaped."""
    return '"' + "".join(f"\\U{ord(c):08x}" for c in value) + '"'


def key_of_failure(gw: FakeGateway) -> str:
    with pytest.raises(ConfigError) as info:
        config.load(gw, None)
    return info.value.key


# --- base_url grammar ------------------------------------------------------------------------

GOOD_URLS = [
    ("https://ha.example", "https", "ha.example", None, ""),
    ("https://ha.example/", "https", "ha.example", None, ""),
    ("https://ha.example///", "https", "ha.example", None, ""),
    ("HTTPS://HA.Example", "https", "ha.example", None, ""),
    ("hTtPs://ha.example:8123", "https", "ha.example", "8123", ""),
    ("https://ha.example:1", "https", "ha.example", "1", ""),
    ("https://ha.example:65535", "https", "ha.example", "65535", ""),
    ("https://ha.example:00443", "https", "ha.example", "00443", ""),
    ("https://ha.example:080", "https", "ha.example", "080", ""),
    ("https://ha.example/ha", "https", "ha.example", None, "/ha"),
    ("https://ha.example/a/b.c/_d~e-f/", "https", "ha.example", None, "/a/b.c/_d~e-f"),
    ("https://ha.example/...", "https", "ha.example", None, "/..."),
    ("https://ha.example/.a", "https", "ha.example", None, "/.a"),
    ("https://10.0.0.5:8123", "https", "10.0.0.5", "8123", ""),
    ("https://localhost", "https", "localhost", None, ""),
    ("https://xn--bcher-kva.example", "https", "xn--bcher-kva.example", None, ""),
    ("https://[::1]", "https", "::1", None, ""),
    ("https://[FE80::1]:8123/x", "https", "fe80::1", "8123", "/x"),
    ("https://[::ffff:10.0.0.1]", "https", "::ffff:10.0.0.1", None, ""),
]


@pytest.mark.parametrize(("text", "scheme", "host", "port", "prefix"), GOOD_URLS)
def test_base_url_good(text: str, scheme: str, host: str, port: str | None, prefix: str) -> None:
    parsed = config.parse_base_url(text)
    assert parsed is not None
    assert (parsed.scheme, parsed.host, parsed.port_text, parsed.prefix) == (
        scheme,
        host,
        port,
        prefix,
    )


def test_base_url_derived_parts() -> None:
    plain = config.parse_base_url("HTTPS://HA.example/")
    assert plain == BaseUrl("https", "ha.example", None, "", False)
    assert (plain.port, plain.authority) == (443, "ha.example")
    assert plain.request_path("mobile_app_x") == "/api/services/notify/mobile_app_x"
    assert plain.probe_path == "/api/"
    kept = config.parse_base_url("https://ha.example:0443/p/q//")
    assert kept is not None
    assert (kept.port, kept.authority) == (443, "ha.example:0443")
    assert kept.request_path("s") == "/p/q/api/services/notify/s"
    assert kept.probe_path == "/p/q/api/"
    http = config.parse_base_url("http://[::1]:8080")
    assert http is not None
    assert (http.scheme, http.port, http.authority) == ("http", 8080, "[::1]:8080")
    assert http.host == "::1"
    assert config.parse_base_url("http://h.example").port == 80  # type: ignore[union-attr]


BAD_URLS = [
    "",
    " ",
    "ha.example",
    "//ha.example",
    "https:/ha.example",
    "https:ha.example",
    "ftp://x",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "wss://ha.example",
    "httpss://ha.example",
    "https://",
    "https:///",
    "https:///path",
    " https://ha.example",
    "https://ha.example ",
    "https://ha .example",
    "https://ha.example\n",
    "\nhttps://ha.example",
    "https://ha.example\r\n",
    "https://ha.example\t",
    "https://ha.example\x00",
    "https://ha.example/\x00",
    # percent-encoded host, backslash, userinfo, query, fragment
    "https://ha%2eexample",
    "https://%68a.example",
    "https://ha.example%00",
    "https://ha.example/%41",
    "https://ha.example\\evil.example",
    "https://ha.example/a\\b",
    "https:\\\\ha.example",
    "https://user@ha.example",
    "https://user:pw@ha.example",
    "https://:pw@ha.example",
    "https://ha.example@evil.example",
    "https://evil.example\\@ha.example",
    "https://ha.example?x=1",
    "https://ha.example/?x=1",
    "https://ha.example/a?x",
    "https://ha.example#frag",
    "https://ha.example/a#frag",
    "https://ha.example/a;b",
    "https://ha.example/a b",
    "https://ha.example/a,b",
    # ports
    "https://ha.example:",
    "https://ha.example:abc",
    "https://ha.example:80a",
    "https://ha.example:99999",
    "https://ha.example:65536",
    "https://ha.example:0",
    "https://ha.example:00000",
    "https://ha.example:000000080",
    "https://ha.example:-1",
    "https://ha.example:+80",
    "https://ha.example: 80",
    "https://ha.example:80:80",
    "https://ha.example:٨٠",  # Arabic-Indic digits
    "https://ha.example:８０",  # fullwidth digits
    # hosts
    "https://.ha.example",
    "https://ha.example.",
    "https://ha..example",
    "https://ha_example",
    "https://ha.example:8123:",
    "https://hé.example",
    "https://bücher.example",
    "https://ｈａ.example",  # fullwidth
    "https://ha.ех",  # Cyrillic lookalikes
    "https://ha。example",  # ideographic full stop
    "https://ha.example\u200b",
    "https://[::1",
    "https://::1]",
    "https://[]",
    "https://[8]",
    "https://[a]",
    "https://[:]",
    "https://[::1]x",
    "https://[::1]:",
    "https://[::1%25eth0]",
    "https://[::g]",
    "https://[1:2:3:4:5:6:7:8:9]",
    "https://[::1]:99999",
    "https://[ha.example]",
    "https://[::1]]",
    "https://[[::1]]",
    "https://a.example[::1]",
    # path prefix
    "https://ha.example//ha",
    "https://ha.example/ha//x",
    "https://ha.example/./",
    "https://ha.example/.",
    "https://ha.example/..",
    "https://ha.example/../",
    "https://ha.example/a/./b",
    "https://ha.example/a/../b",
    "https://ha.example/a/..",
    "https://ha.example/a/.//",
    "https://ha.example/é",
    "https://ha.example/%2e%2e",
    "https://ha.example/*",
    # size
    "https://" + "a" * 2041,
]


@pytest.mark.parametrize("text", BAD_URLS)
def test_base_url_bad(text: str) -> None:
    assert config.parse_base_url(text) is None


def test_base_url_size_boundary() -> None:
    host = "a" * (2048 - len("https://"))
    assert config.parse_base_url("https://" + host) is not None
    assert config.parse_base_url("https://" + host + "a") is None


def test_base_url_that_is_not_a_string_is_refused() -> None:
    for value in (None, 5, b"https://ha.example", ["https://ha.example"]):
        assert config.parse_base_url(value) is None  # type: ignore[arg-type]


def test_base_url_hostile_input_is_fast() -> None:
    for text in ["https://" + "a." * 1000 + "!", "https://x/" + "a/" * 1000 + "!", "https://x" + "/" * 2000]:
        config.parse_base_url(text)


SCHEMA_CORPUS = [t for t, *_ in GOOD_URLS] + [
    t for t in BAD_URLS if not t.startswith("https://[") or "::1" in t
]


@pytest.mark.parametrize("text", SCHEMA_CORPUS)
def test_the_tool_never_accepts_what_the_schema_refuses(text: str) -> None:
    # The schema is the wider check (it accepts "[8]", which the tool's address parse refuses);
    # whatever the tool accepts, the schema accepts, and for the shared corpus they agree.
    parsed = config.parse_base_url(text)
    schema_ok = schema_errors("config", {"base_url": text, "allow_insecure_http": True}) == []
    assert (parsed is not None) is schema_ok


def test_the_tool_is_stricter_than_the_schema_only_for_ipv6_text() -> None:
    for text in ["https://[8]", "https://[a]", "https://[:]", "https://[1:2:3:4:5:6:7:8:9]"]:
        assert config.parse_base_url(text) is None
        assert schema_errors("config", {"base_url": text}) == []


def test_base_url_scheme_http_needs_the_insecure_flag_in_the_schema_too() -> None:
    assert schema_errors("config", {"base_url": "http://h.example"}) != []
    ok = {"base_url": "http://h.example", "allow_insecure_http": True}
    assert schema_errors("config", ok) == []


# --- base_url through load -------------------------------------------------------------------


def test_load_accepts_and_exposes_a_base_url(gw: FakeGateway, home: Path) -> None:
    write(home, "base_url: HTTPS://HA.Example:8123/prefix/\n")
    cfg = config.load(gw, None)
    assert cfg.values["base_url"] == "HTTPS://HA.Example:8123/prefix/"  # kept as written
    parsed = cfg.base_url
    assert parsed is not None
    assert (parsed.host, parsed.port, parsed.prefix) == ("ha.example", 8123, "/prefix")
    assert cfg.base_url_text == "https://ha.example:8123/prefix"


def test_no_base_url_is_none(gw: FakeGateway, home: Path) -> None:
    write(home, "service: x\n")
    assert config.load(gw, None).base_url is None


@pytest.mark.parametrize(
    "text",
    [
        "https://ha.example:99999",
        "https://ha.example:abc",
        "https://%68a.example",
        "https://a\\b",
        "https://hé.example",
        "https://ha.example//x",
        "https://u@ha.example",
        "https://ha.example?x",
        "ftp://x",
        "",
        "https://ha.example\n",
    ],
)
def test_load_refuses_a_bad_base_url_naming_the_key_only(
    gw: FakeGateway, home: Path, text: str
) -> None:
    write(home, f"base_url: {q(text)}\n")
    with pytest.raises(ConfigError) as info:
        config.load(gw, None)
    assert info.value.key == "base_url"
    envelope = info.value.error.envelope["error"]
    assert envelope["details"] == {"key": "base_url"}
    for part in (text, "ha.example"):
        if part:
            assert part not in repr(info.value.error) + str(info.value)


def test_http_needs_allow_insecure_http(gw: FakeGateway, home: Path) -> None:
    write(home, "base_url: http://ha.local:8123\n")
    assert key_of_failure(gw) == "base_url"
    write(home, "base_url: http://ha.local:8123\nallow_insecure_http: false\n")
    assert key_of_failure(gw) == "base_url"
    write(home, "base_url: http://ha.local:8123\nallow_insecure_http: true\n")
    cfg = config.load(gw, None)
    assert cfg.base_url is not None
    assert cfg.base_url.scheme == "http"
    assert cfg.allow_insecure_http is True


def test_http_is_checked_on_the_merged_config(gw: FakeGateway, home: Path) -> None:
    # The flag may come from any file, before or after the file that holds the URL.
    write(home, "base_url: http://ha.local\n")
    write(home, "allow_insecure_http: true\n", "config.d/10.yaml")
    assert config.load(gw, None).allow_insecure_http is True
    write(home, "allow_insecure_http: true\n")
    write(home, "base_url: http://ha.local\n", "config.d/10.yaml")
    assert config.load(gw, None).base_url is not None
    write(home, "base_url: http://ha.local\nallow_insecure_http: true\n")
    write(home, "allow_insecure_http: false\n", "config.d/10.yaml")
    assert key_of_failure(gw) == "base_url"


def test_https_never_needs_the_flag(gw: FakeGateway, home: Path) -> None:
    write(home, "base_url: https://ha.example\nallow_insecure_http: false\n")
    assert config.load(gw, None).allow_insecure_http is False


def test_a_bad_base_url_in_a_dropin_is_refused(gw: FakeGateway, home: Path) -> None:
    write(home, "base_url: https://ha.example\n")
    write(home, "base_url: ftp://x\n", "config.d/10.yaml")
    assert key_of_failure(gw) == "base_url"


# --- service ---------------------------------------------------------------------------------

GOOD_SERVICES = ["mobile_app_x", "a", "0", "_", "a" * 64, "x_1_2"]
BAD_SERVICES = [
    "",
    "A",
    "mobile-app",
    "mobile.app",
    "notify.mobile_app_x",
    "a/b",
    "a b",
    "a\n",
    "\na",
    "é",
    "a" * 65,
    "../x",
    "%61",
    "ａ",
]


@pytest.mark.parametrize("value", GOOD_SERVICES)
def test_service_good(gw: FakeGateway, home: Path, value: str) -> None:
    write(home, f"service: {q(value)}\n")
    assert config.load(gw, None).service == value


@pytest.mark.parametrize("value", BAD_SERVICES)
def test_service_bad(gw: FakeGateway, home: Path, value: str) -> None:
    write(home, f"service: {q(value)}\n")
    assert key_of_failure(gw) == "service"


def test_service_pattern_agrees_with_the_schema() -> None:
    for value in GOOD_SERVICES + BAD_SERVICES:
        assert config.service_ok(value) is (schema_errors("config", {"service": value}) == [])


def test_no_service_is_none(gw: FakeGateway, home: Path) -> None:
    write(home, "enabled: true\n")
    assert config.load(gw, None).service is None


# --- token_env -------------------------------------------------------------------------------

GOOD_TOKEN_ENV = ["HA_TOKEN", "HA_X", "HA_" + "A" * 60, "HA_0_9", "HA__"]
BAD_TOKEN_ENV = [
    "",
    "TOKEN",
    "HA_",
    "ha_token",
    "Ha_TOKEN",
    "HA-TOKEN",
    "HATOKEN",
    "HA_TOKEN\n",
    "\nHA_TOKEN",
    "HA_TOKEN ",
    " HA_TOKEN",
    "HA_" + "A" * 61,
    "HA_tok",
    "HA_É",
    "HA_ＴＯＫＥＮ",
    "HA_TOKEN=x",
    "HA_NOTICE_TOKEN\x00",
    "PATH",
    "HOME",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "https://ha.example",
    "$HA_TOKEN",
    "${HA_TOKEN}",
]


@pytest.mark.parametrize("value", GOOD_TOKEN_ENV)
def test_token_env_good(gw: FakeGateway, home: Path, value: str) -> None:
    write(home, f"token_env: {value}\n")
    assert config.load(gw, None).token_env == value


@pytest.mark.parametrize("value", BAD_TOKEN_ENV)
def test_token_env_bad(gw: FakeGateway, home: Path, value: str) -> None:
    write(home, f"token_env: {q(value)}\n")
    with pytest.raises(ConfigError) as info:
        config.load(gw, None)
    assert info.value.key == "token_env"
    assert value not in repr(info.value.error) + str(info.value) or value == ""


def test_token_env_agrees_with_the_schema() -> None:
    for value in GOOD_TOKEN_ENV + BAD_TOKEN_ENV:
        assert config.token_env_ok(value) is (
            schema_errors("config", {"token_env": value}) == []
        ), repr(value)
        pattern = load_schema("config")["properties"]["token_env"]["pattern"]
        assert config.token_env_ok(value) is bool(re.fullmatch(pattern, value))


def test_token_env_defaults_to_ha_token(gw: FakeGateway, home: Path) -> None:
    write(home, "enabled: true\n")
    assert config.load(gw, None).token_env == "HA_TOKEN"


# --- allow_insecure_http accessor ------------------------------------------------------------


def test_allow_insecure_http_defaults_to_false(gw: FakeGateway, home: Path) -> None:
    write(home, "enabled: true\n")
    assert config.load(gw, None).allow_insecure_http is False


# --- ca_file ---------------------------------------------------------------------------------

GOOD_CA = ["/etc/ssl/ca.pem", "/", "/a b/c é.pem", "/" + "a" * 4095]
BAD_CA = [
    "",
    "ca.pem",
    "./ca.pem",
    "~/ca.pem",
    "~",
    "C:\\ca.pem",
    "file:///ca.pem",
    "/ca\n",
    "\n/ca",
    "/c\x00a",
    "/c\x1fa",
    "/c\x7fa",
    "/" + "a" * 4096,
    " /ca.pem",
]


@pytest.mark.parametrize("value", GOOD_CA)
def test_ca_file_good(gw: FakeGateway, home: Path, value: str) -> None:
    write(home, f"ca_file: {q(value)}\n")
    assert config.load(gw, None).ca_file == value


@pytest.mark.parametrize("value", BAD_CA)
def test_ca_file_bad(gw: FakeGateway, home: Path, value: str) -> None:
    write(home, f"ca_file: {q(value)}\n")
    assert key_of_failure(gw) == "ca_file"


def test_ca_file_agrees_with_the_schema() -> None:
    for value in GOOD_CA + BAD_CA:
        assert config.ca_file_ok(value) is (schema_errors("config", {"ca_file": value}) == [])


def test_load_does_not_read_the_ca_file(gw: FakeGateway, home: Path) -> None:
    # A dry run needs no readable ca_file; the readability check is its own step.
    write(home, "ca_file: /nonexistent/ca.pem\n")
    assert config.load(gw, None).ca_file == "/nonexistent/ca.pem"


class CaGateway(FakeGateway):
    """Records which paths the CA check reads."""

    reads: list[tuple[str, int]]

    def read_config(self, path: str, max_bytes: int) -> bytes | None:
        if not path.endswith(".yaml"):
            self.__dict__.setdefault("reads", []).append((path, max_bytes))
        return super().read_config(path, max_bytes)


def test_check_ca_file_accepts_a_readable_file(home: Path, tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    gw = CaGateway(home=str(home))
    write(home, f"ca_file: {ca}\n")
    cfg = config.load(gw, None)
    cfg.check_ca_file(gw)
    assert gw.reads == [(str(ca), config.MAX_CA_FILE_BYTES)]


def test_check_ca_file_without_a_ca_file_reads_nothing(home: Path) -> None:
    gw = CaGateway(home=str(home))
    write(home, "service: x\n")
    config.load(gw, None).check_ca_file(gw)
    assert getattr(gw, "reads", []) == []


def _ca_failure(home: Path, gw: FakeGateway, path: Path) -> ConfigError:
    write(home, f"ca_file: {q(str(path))}\n")
    cfg = config.load(gw, None)
    with pytest.raises(ConfigError) as info:
        cfg.check_ca_file(gw)
    return info.value


def test_check_ca_file_missing(home: Path, gw: FakeGateway, tmp_path: Path) -> None:
    err = _ca_failure(home, gw, tmp_path / "missing.pem")
    assert err.key == "ca_file"
    assert err.error.envelope["error"]["details"] == {"key": "ca_file"}
    assert "missing" not in repr(err.error) + str(err)


def test_check_ca_file_directory(home: Path, gw: FakeGateway, tmp_path: Path) -> None:
    assert _ca_failure(home, gw, tmp_path).key == "ca_file"


def test_check_ca_file_dangling_symlink(home: Path, gw: FakeGateway, tmp_path: Path) -> None:
    link = tmp_path / "link.pem"
    link.symlink_to(tmp_path / "gone.pem")
    assert _ca_failure(home, gw, link).key == "ca_file"


def test_check_ca_file_fifo_does_not_block(home: Path, gw: FakeGateway, tmp_path: Path) -> None:
    fifo = tmp_path / "fifo.pem"
    os.mkfifo(fifo)
    assert _ca_failure(home, gw, fifo).key == "ca_file"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_check_ca_file_unreadable(home: Path, gw: FakeGateway, tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("x", encoding="utf-8")
    ca.chmod(0)
    try:
        assert not os.access(ca, os.R_OK)
        assert _ca_failure(home, gw, ca).key == "ca_file"
    finally:
        ca.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_check_ca_file_too_large(home: Path, gw: FakeGateway, tmp_path: Path) -> None:
    ca = tmp_path / "big.pem"
    ca.write_bytes(b"x" * (config.MAX_CA_FILE_BYTES + 1))
    assert _ca_failure(home, gw, ca).key == "ca_file"
    ca.write_bytes(b"x" * config.MAX_CA_FILE_BYTES)
    config.load(gw, None).check_ca_file(gw)


def test_check_ca_file_gateway_error_is_config_invalid(home: Path, tmp_path: Path) -> None:
    class Failing(FakeGateway):
        def read_config(self, path: str, max_bytes: int) -> bytes | None:
            if path.endswith(".yaml"):
                return super().read_config(path, max_bytes)
            raise SourceError("secret detail /private/path")

    gw = Failing(home=str(home))
    write(home, "ca_file: /private/path\n")
    cfg = config.load(gw, None)
    with pytest.raises(ConfigError) as info:
        cfg.check_ca_file(gw)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None
    assert "private" not in repr(info.value.error) + str(info.value)


# --- the destination of a send ---------------------------------------------------------------


def test_check_destination_names_the_missing_key(gw: FakeGateway, home: Path) -> None:
    write(home, "enabled: true\n")
    cfg = config.load(gw, None)
    with pytest.raises(ConfigError) as info:
        cfg.check_destination()
    assert info.value.key == "base_url"
    write(home, "base_url: https://ha.example\n")
    with pytest.raises(ConfigError) as info:
        config.load(gw, None).check_destination()
    assert info.value.key == "service"
    write(home, "base_url: https://ha.example\nservice: x\n")
    config.load(gw, None).check_destination()


def test_a_dry_run_style_load_needs_neither_base_url_nor_service(
    gw: FakeGateway, home: Path
) -> None:
    write(home, "enabled: true\n")
    cfg = config.load(gw, None)
    assert (cfg.base_url, cfg.service, cfg.ca_file) == (None, None, None)


# --- the token -------------------------------------------------------------------------------


def cfg_with(gw: FakeGateway, home: Path, text: str = "enabled: true\n") -> config.Config:
    write(home, text)
    return config.load(gw, None)


def test_token_is_read_from_the_named_variable_only(gw: FakeGateway, home: Path) -> None:
    cfg = cfg_with(gw, home, "token_env: HA_OTHER\n")
    env = {"HA_TOKEN": "wrong", "HA_OTHER": FAKE_TOKEN, "HA_NOTICE_TOKEN": "wrong2"}
    assert cfg.read_token(env) == FAKE_TOKEN


def test_default_variable_is_ha_token(gw: FakeGateway, home: Path) -> None:
    cfg = cfg_with(gw, home)
    assert cfg.read_token({"HA_TOKEN": FAKE_TOKEN, "HA_OTHER": "x"}) == FAKE_TOKEN


@pytest.mark.parametrize("env", [{}, {"HA_OTHER": "x"}, {"HA_TOKEN": ""}, {"HA_TOKEN": " \r\n"}])
def test_missing_or_empty_token(gw: FakeGateway, home: Path, env: dict[str, str]) -> None:
    cfg = cfg_with(gw, home)
    with pytest.raises(CredentialError) as info:
        cfg.read_token(env)
    assert info.value.env == "HA_TOKEN"
    assert info.value.error.envelope["error"]["details"] == {"env": "HA_TOKEN"}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (FAKE_TOKEN + "\r\n", FAKE_TOKEN),
        (FAKE_TOKEN + "\n", FAKE_TOKEN),
        ("\n" + FAKE_TOKEN + " \t", FAKE_TOKEN),
        ("a" * 4096, "a" * 4096),
        ("a" * 4096 + "\r\n", "a" * 4096),
        ("~", "~"),
        ("!", "!"),
    ],
)
def test_token_is_trimmed(gw: FakeGateway, home: Path, raw: str, expected: str) -> None:
    assert cfg_with(gw, home).read_token({"HA_TOKEN": raw}) == expected


@pytest.mark.parametrize(
    "raw",
    [
        FAKE_TOKEN + " x",  # interior space
        "ab cd",
        "ab\tcd",
        "ab\ncd",
        "ab\rcd",
        "ab\x00cd",
        "ab\x7fcd",
        "abé",
        "ab\u00a0cd",
        "ab\u200bcd",
        "ａｂ",
        "a" * 4097,
        "a" * 4097 + "\n",
        "\u2028",
    ],
)
def test_invalid_token_is_refused_without_echo(gw: FakeGateway, home: Path, raw: str) -> None:
    cfg = cfg_with(gw, home)
    with pytest.raises(CredentialError) as info:
        cfg.read_token({"HA_TOKEN": raw})
    text = repr(info.value) + str(info.value) + repr(info.value.error) + repr(info.value.args)
    assert raw.strip()[:6] not in text or not raw.strip()[:6]
    assert info.value.__cause__ is None


def test_token_never_appears_in_any_repr(gw: FakeGateway, home: Path) -> None:
    cfg = cfg_with(gw, home)
    env = {"HA_TOKEN": FAKE_TOKEN}
    cfg.read_token(env)
    assert FAKE_TOKEN not in repr(cfg)
    assert FAKE_TOKEN not in repr(cfg.base_url)
    # A refused token (one too long) is not in the exception either.
    bad = FAKE_TOKEN + "x" * 5000
    with pytest.raises(CredentialError) as info:
        cfg.read_token({"HA_TOKEN": bad})
    assert FAKE_TOKEN not in repr(info.value) + str(info.value) + repr(info.value.error)
    assert FAKE_TOKEN not in repr(vars(info.value))


def test_token_env_is_never_taken_from_the_environment(gw: FakeGateway, home: Path) -> None:
    # There are no HA_NOTICE_* overrides: the name comes from the config alone.
    cfg = cfg_with(gw, home, "token_env: HA_CFG\n")
    env = {"HA_NOTICE_TOKEN_ENV": "HA_ENV", "HA_ENV": "x", "HA_NOTICE_TOKEN": "y", "HA_CFG": FAKE_TOKEN}
    assert cfg.read_token(env) == FAKE_TOKEN
    assert cfg.token_env == "HA_CFG"
    with pytest.raises(CredentialError):
        cfg.read_token({"HA_NOTICE_TOKEN_ENV": "HA_ENV", "HA_ENV": FAKE_TOKEN})


def test_credential_error_has_no_cause_or_context(gw: FakeGateway, home: Path) -> None:
    cfg = cfg_with(gw, home)
    with pytest.raises(CredentialError) as info:
        cfg.read_token({"HA_TOKEN": "a b"})
    assert info.value.__cause__ is None
    assert info.value.__context__ is None


# --- schema defaults and keys stay tied ------------------------------------------------------


def test_example_still_loads(gw: FakeGateway, home: Path) -> None:
    example = (Path(__file__).resolve().parent.parent / "config.example.yaml").read_text("utf-8")
    write(home, example)
    cfg = config.load(gw, None)
    assert cfg.token_env == "HA_TOKEN"
