"""The Home Assistant client: request shape, trust, token handling, one attempt (issue #22).

The client under test is ``ha_notice.hass`` on the real gateway against the wire-level fake
server (``tests/fake_ha.py``). Response mapping, retries and the deadline belong to #23, #24 and
#25; here a failure is the exception the gateway raises.
"""

from __future__ import annotations

import dataclasses
import http.client
import json
import os
import socket
import ssl
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from ha_notice import __version__
from ha_notice.config import Config, CredentialError, parse_base_url
from ha_notice.gateway import CaCandidates, ConnectSpec, GatewayError, RealGateway
from ha_notice.hass import (
    BODY_CAP,
    Target,
    TrustError,
    exchange,
    make_target,
    open_connection,
    probe_once,
    request_headers,
    select_trust,
    send_once,
)
from tests import fake_ha
from tests.fake_gateway import FakeGateway
from tests.fake_ha import EDGE_ROWS, FakeHA, Reply, make_self_signed_cert, redirect

TOKEN = "HA_leakcheck-0123456789-ABCDEF"
SERVICE = "mobile_app_test"
BODY = json.dumps({"title": "café", "message": "héllo \U0001f600"}, ensure_ascii=False).encode()
NO_CA = CaCandidates("", "", ())
# X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, UNABLE_TO_GET_ISSUER_CERT_LOCALLY and
# SELF_SIGNED_CERT_IN_CHAIN
UNTRUSTED = (18, 20, 19)
HOST_MISMATCH = (64,)  # X509_V_ERR_IP_ADDRESS_MISMATCH (a DNS name gives 62, HOSTNAME_MISMATCH)
EXPIRED = (10,)  # X509_V_ERR_CERT_HAS_EXPIRED


class CaGateway(RealGateway):
    """A real gateway whose compiled CA locations are the test's."""

    def __init__(self, candidates: CaCandidates = NO_CA) -> None:
        self.candidates = candidates

    def ca_candidates(self) -> CaCandidates:
        return self.candidates


def target_for(
    ha: FakeHA,
    *,
    token: str = TOKEN,
    tls: ssl.SSLContext | None = None,
    prefix: str = "",
    connect_timeout: float = 5.0,
    io_timeout: float = 5.0,
) -> Target:
    parsed = parse_base_url(f"{ha.scheme}://127.0.0.1:{ha.port}{prefix}")
    assert parsed is not None
    return Target(parsed, token, "HA_TOKEN", tls, connect_timeout, io_timeout)


def trust_of(*certs: Path) -> ssl.SSLContext:
    return RealGateway().new_tls_context([], (), [c.read_bytes() for c in certs])


@pytest.fixture(scope="session")
def unrelated_ca(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A CA certificate whose subject differs from the fake's (same-subject certificates shadow
    each other in an OpenSSL store, which would hide what a test means to show)."""
    directory = tmp_path_factory.mktemp("unrelated-ca")
    config = fake_ha.OPENSSL_CONFIG.replace("CN = fake-ha", "CN = unrelated-ca")
    original = fake_ha.OPENSSL_CONFIG
    fake_ha.OPENSSL_CONFIG = config
    try:
        return make_self_signed_cert(directory, sans=("DNS:unrelated.invalid",), name="un")[0]
    finally:
        fake_ha.OPENSSL_CONFIG = original


# --- the request on the wire -------------------------------------------------------------------


def test_post_request_line_headers_and_body_are_exact() -> None:
    with FakeHA(token=TOKEN) as ha:
        response = send_once(RealGateway(), target_for(ha), SERVICE, BODY)
    assert (response.status, response.body, response.too_large) == (200, b"[]", False)
    raw = ha.received[0]
    assert raw.startswith(f"POST /api/services/notify/{SERVICE} HTTP/1.1\r\n".encode())
    request = ha.requests[0]
    names = [k.lower() for k, _ in request.headers]
    assert sorted(names) == sorted(
        [
            "host",
            "authorization",
            "accept",
            "accept-encoding",
            "connection",
            "user-agent",
            "content-type",
            "content-length",
        ]
    )
    assert request.header("Host") == f"127.0.0.1:{ha.port}"
    assert request.header("Authorization") == f"Bearer {TOKEN}"
    assert request.header("Content-Type") == "application/json"
    assert request.header("Content-Length") == str(len(BODY))  # bytes, not characters
    assert len(BODY) != len(BODY.decode())
    assert request.header("Accept") == "application/json"
    assert request.header("Accept-Encoding") == "identity"
    assert request.header("Connection") == "close"
    assert request.header("User-Agent") == f"ha-notice/{__version__}"
    assert request.body == BODY
    assert len(ha.requests) == 1


def test_probe_is_a_bodyless_get_without_content_headers() -> None:
    with FakeHA(token=TOKEN) as ha:
        response = probe_once(RealGateway(), target_for(ha))
    assert (response.status, response.body) == (200, b'{"message": "API running."}')
    request = ha.requests[0]
    assert (request.method, request.path, request.body) == ("GET", "/api/", b"")
    names = {k.lower() for k, _ in request.headers}
    assert names == {
        "host",
        "authorization",
        "accept",
        "accept-encoding",
        "connection",
        "user-agent",
    }


@pytest.mark.parametrize("suffix", ["", "/"])
def test_prefix_is_applied_once_with_no_double_or_trailing_slash(suffix: str) -> None:
    with FakeHA(token=TOKEN, prefix="ha/sub") as ha:
        parsed = parse_base_url(f"http://127.0.0.1:{ha.port}/ha/sub{suffix}")
        assert parsed is not None
        target = Target(parsed, TOKEN, "HA_TOKEN", None, 5.0, 5.0)
        assert send_once(RealGateway(), target, SERVICE, BODY).status == 200
        assert probe_once(RealGateway(), target).status == 200
    assert [r.path for r in ha.requests] == [
        f"/ha/sub/api/services/notify/{SERVICE}",
        "/ha/sub/api/",
    ]


@pytest.mark.parametrize(
    "service", ["", "a/b", "../x", "a b", "A", "x?y=1", "x\r\nHost: evil", "x" * 65, "é"]
)
def test_a_service_outside_the_grammar_never_reaches_the_wire(service: str) -> None:
    with FakeHA(token=TOKEN) as ha:
        with pytest.raises(ValueError):
            send_once(RealGateway(), target_for(ha), service, BODY)
    assert ha.connections == 0


def test_host_header_keeps_the_port_as_written() -> None:
    with FakeHA(token=TOKEN) as ha:
        parsed = parse_base_url(f"http://localhost:{ha.port}")
        assert parsed is not None
        target = Target(parsed, TOKEN, "HA_TOKEN", None, 5.0, 5.0)
        # localhost may resolve to ::1 first; the fake listens on IPv4 only, the gateway tries on.
        send_once(RealGateway(), target, SERVICE, BODY)
    assert ha.requests[0].header("Host") == f"localhost:{ha.port}"


def test_headers_are_built_without_the_body_headers_for_a_get() -> None:
    parsed = parse_base_url("https://ha.example:8123")
    assert parsed is not None
    target = Target(parsed, TOKEN, "HA_TOKEN", RealGateway().new_tls_context([]), 1.0, 1.0)
    get = request_headers(target, body=None)
    assert "Content-Type" not in get and "Content-Length" not in get
    assert get["Host"] == "ha.example:8123"
    assert request_headers(target, body=b"x")["Content-Length"] == "1"


# --- the token ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "",
        "a\r\nX-Evil: 1",
        "abc\ndef",
        "abc def",
        "tokén",
        "tokĀn",
        "☃",
        "a" * 4097,
        "tab\there",
        "nul\x00x",
        "del\x7f",
    ],
)
def test_a_bad_token_is_rejected_before_any_io(token: str) -> None:
    with FakeHA() as ha:
        with pytest.raises(CredentialError) as info:
            target_for(ha, token=token)
    assert ha.connections == 0
    assert info.value.env == "HA_TOKEN"
    assert token not in str(info.value) or token == ""


def test_the_longest_valid_token_is_sent() -> None:
    token = "t" * 4096
    with FakeHA() as ha:
        send_once(RealGateway(), target_for(ha, token=token), SERVICE, BODY)
    assert ha.requests[0].header("Authorization") == f"Bearer {token}"


def test_make_target_checks_the_token_before_reading_any_trust_file() -> None:
    class Tripwire(CaGateway):
        def ca_candidates(self) -> CaCandidates:
            raise AssertionError("trust was consulted before the credential")

    config = Config({"base_url": "https://ha.example", "service": SERVICE})
    with pytest.raises(CredentialError):
        make_target(Tripwire(), config, {"HA_TOKEN": "bad token"}, io_timeout=1.0)
    with pytest.raises(CredentialError):
        make_target(Tripwire(), config, {}, io_timeout=1.0)


def test_make_target_trims_the_token_and_uses_the_configured_timeouts(
    self_signed_cert: tuple[Path, Path],
) -> None:
    cert = self_signed_cert[0]
    config = Config(
        {
            "base_url": "https://HA.example:8123/p/",
            "service": SERVICE,
            "token_env": "HA_OTHER",
            "ca_file": str(cert),
            "connect_timeout": "7s",
        }
    )
    target = make_target(CaGateway(), config, {"HA_OTHER": f"  {TOKEN}\n"}, io_timeout=9.0)
    assert target.token == TOKEN
    assert (target.connect_timeout, target.io_timeout) == (7.0, 9.0)
    assert target.base.authority == "ha.example:8123"
    assert target.tls is not None


def test_make_target_refuses_http_without_allow_insecure_http() -> None:
    class Tripwire(CaGateway):
        def connect(self, spec: ConnectSpec):  # noqa: ANN202
            raise AssertionError("connected")

    with FakeHA() as ha:
        config = Config({"base_url": f"http://127.0.0.1:{ha.port}", "service": SERVICE})
        with pytest.raises(ValueError) as info:
            make_target(Tripwire(), config, {"HA_TOKEN": TOKEN}, io_timeout=1.0)
        _assert_no_token(info.value)
        flagged = Config({**config.values, "allow_insecure_http": False})
        with pytest.raises(ValueError):
            make_target(Tripwire(), flagged, {"HA_TOKEN": TOKEN}, io_timeout=1.0)
    assert ha.connections == 0


def test_make_target_for_http_builds_no_tls_context() -> None:
    config = Config(
        {"base_url": "http://ha.example", "service": SERVICE, "allow_insecure_http": True}
    )
    target = make_target(CaGateway(), config, {"HA_TOKEN": TOKEN}, io_timeout=1.0)
    assert target.tls is None


def test_a_target_never_shows_its_token() -> None:
    with FakeHA() as ha:
        target = target_for(ha)
    assert TOKEN not in repr(target) and TOKEN not in str(target)


def _chain(exc: BaseException | None) -> list[BaseException]:
    seen: list[BaseException] = []
    while exc is not None and exc not in seen:
        seen.append(exc)
        exc = exc.__cause__ or exc.__context__
    return seen


def _assert_no_token(exc: BaseException) -> None:
    for item in _chain(exc):
        texts = [str(item), repr(item), *(repr(a) for a in item.args)]
        assert all(TOKEN not in t for t in texts), type(item)


def test_no_failure_carries_the_token(
    self_signed_cert: tuple[Path, Path], other_cert: tuple[Path, Path]
) -> None:
    cert, key = self_signed_cert
    failures: list[BaseException] = []

    def attempt(run: Callable[[], object]) -> None:
        with pytest.raises(BaseException) as info:
            run()
        failures.append(info.value)

    gateway = RealGateway()
    with socket.socket() as s:  # a port nothing listens on
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
    refused = parse_base_url(f"http://127.0.0.1:{dead}")
    assert refused is not None
    attempt(
        lambda: send_once(
            gateway, Target(refused, TOKEN, "HA_TOKEN", None, 2.0, 2.0), SERVICE, BODY
        )
    )
    with FakeHA(certfile=cert, keyfile=key) as tls_ha:  # untrusted certificate
        attempt(
            lambda: send_once(
                gateway, target_for(tls_ha, tls=trust_of(other_cert[0])), SERVICE, BODY
            )
        )
    with FakeHA(script=[Reply(raw=b"garbage\r\n\r\n")]) as ha:
        attempt(lambda: send_once(gateway, target_for(ha), SERVICE, BODY))
    with FakeHA(script=[Reply(body=b"x" * 50, declared_length=500)]) as ha:
        attempt(lambda: send_once(gateway, target_for(ha), SERVICE, BODY))
    with FakeHA(script=[Reply(drop=True)]) as ha:
        attempt(lambda: send_once(gateway, target_for(ha), SERVICE, BODY))
    with FakeHA(script=[Reply(delay=1.5)]) as ha:
        attempt(lambda: send_once(gateway, target_for(ha, io_timeout=0.3), SERVICE, BODY))
    with FakeHA() as ha:

        def refuse() -> None:
            raise RuntimeError("gate abandoned")

        attempt(lambda: send_once(gateway, target_for(ha), SERVICE, BODY, before_write=refuse))
    with pytest.raises(TrustError) as trust_info:
        select_trust(CaGateway(), None)
    failures.append(trust_info.value)
    assert len(failures) == 8
    for failure in failures:
        _assert_no_token(failure)


def test_the_token_goes_only_to_the_configured_host_and_redirects_are_not_followed() -> None:
    with FakeHA() as other, FakeHA() as ha:
        for status in (301, 302, 307, 308):
            ha.script = [redirect(f"{other.base_url}/api/services/notify/{SERVICE}", status)]
            response = send_once(RealGateway(), target_for(ha), SERVICE, BODY)
            assert response.status == status
        assert response.body == b""
    assert other.connections == 0
    assert other.requests == [] and other.received == []
    assert len(ha.requests) == 4
    assert all(r.header("Authorization") == f"Bearer {TOKEN}" for r in ha.requests)


# A regression guard against moving the client to urllib or requests (they read these variables);
# the gateway's own http.client use never consults them.
@pytest.mark.parametrize(
    "variable", ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]
)
def test_proxy_variables_are_ignored(monkeypatch: pytest.MonkeyPatch, variable: str) -> None:
    with FakeHA() as proxy, FakeHA(token=TOKEN) as ha:
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "no_proxy"):
            monkeypatch.setenv(name, "")
        monkeypatch.setenv(variable, proxy.base_url)
        monkeypatch.setenv("NO_PROXY", "")
        assert send_once(RealGateway(), target_for(ha), SERVICE, BODY).status == 200
        assert probe_once(RealGateway(), target_for(ha)).status == 200
    assert proxy.connections == 0 and proxy.received == []
    assert len(ha.requests) == 2


# --- the answer --------------------------------------------------------------------------------


def test_a_large_body_is_cut_at_the_cap_and_flagged() -> None:
    with FakeHA(script=[Reply(body=b"x" * (BODY_CAP * 4))]) as ha:
        response = send_once(RealGateway(), target_for(ha), SERVICE, BODY)
    assert response.too_large and len(response.body) == BODY_CAP


def test_a_body_exactly_at_the_cap_is_not_flagged() -> None:
    with FakeHA(script=[Reply(body=b"y" * BODY_CAP)]) as ha:
        response = send_once(RealGateway(), target_for(ha), SERVICE, BODY)
    assert not response.too_large and len(response.body) == BODY_CAP


def test_a_chunked_answer_is_read_whole() -> None:
    with FakeHA(script=[Reply(body=b'[{"a": 1}]', chunked=True)]) as ha:
        response = send_once(RealGateway(), target_for(ha), SERVICE, BODY)
    assert (response.status, response.body) == (200, b'[{"a": 1}]')


def test_an_interim_100_continue_is_followed_by_the_real_answer() -> None:
    raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]"
    with FakeHA(script=[Reply(raw=raw)]) as ha:
        response = send_once(RealGateway(), target_for(ha), SERVICE, BODY)
    assert (response.status, response.body) == (200, b"[]")
    assert ha.requests[0].header("Expect") is None  # we never ask for it
    # TODO(#25): an endless run of 100 responses is ended by the deadline, not here.


@pytest.mark.parametrize("name", sorted(EDGE_ROWS))
def test_every_edge_row_comes_back_raw_and_unclassified(name: str) -> None:
    reply = EDGE_ROWS[name]
    with FakeHA(script=[reply]) as ha:
        response = send_once(RealGateway(), target_for(ha), SERVICE, BODY)
    assert (response.status, response.body) == (reply.status, reply.body)


def test_a_truncated_answer_raises_incomplete_read() -> None:
    with FakeHA(script=[Reply(body=b"x" * 10, declared_length=100)]) as ha:
        with pytest.raises(http.client.IncompleteRead):
            send_once(RealGateway(), target_for(ha), SERVICE, BODY)


def test_a_close_delimited_truncated_body_is_accepted_as_complete() -> None:
    """Pins what ``exchange`` cannot know (for #23): an answer with neither Content-Length nor
    chunking ends when the peer closes, so a body cut short by a dropped connection is
    indistinguishable from a complete one and is returned as is, without an error."""
    raw = b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n[{"entity'
    with FakeHA(script=[Reply(raw=raw)]) as ha:
        response = send_once(RealGateway(), target_for(ha), SERVICE, BODY)
    assert (response.status, response.body, response.too_large) == (200, b'[{"entity', False)


def test_a_non_http_answer_raises_an_http_exception() -> None:
    with FakeHA(script=[Reply(raw=b"SSH-2.0-nope\r\n\r\n")]) as ha:
        with pytest.raises(http.client.HTTPException):
            send_once(RealGateway(), target_for(ha), SERVICE, BODY)


def test_a_silent_server_ends_with_a_timeout() -> None:
    with FakeHA(script=[Reply(delay=3.0)]) as ha:
        with pytest.raises(TimeoutError):
            send_once(RealGateway(), target_for(ha, io_timeout=0.3), SERVICE, BODY)


def test_a_connection_that_is_refused_raises_oserror_before_any_request() -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
    parsed = parse_base_url(f"http://127.0.0.1:{dead}")
    assert parsed is not None
    with pytest.raises(ConnectionRefusedError):
        send_once(RealGateway(), Target(parsed, TOKEN, "HA_TOKEN", None, 2.0, 2.0), SERVICE, BODY)


def test_the_connection_is_closed_after_the_attempt() -> None:
    closed: list[bool] = []

    class Spy(RealGateway):
        def connect(self, spec: ConnectSpec):  # noqa: ANN202
            conn = super().connect(spec)
            original = conn.close

            def close() -> None:
                closed.append(True)
                original()

            conn.close = close  # type: ignore[method-assign]
            return conn

    with FakeHA() as ha:
        send_once(Spy(), target_for(ha), SERVICE, BODY)
    assert closed


# --- the seam between connect and write --------------------------------------------------------


def test_before_write_runs_after_connect_and_before_any_byte_is_written() -> None:
    with FakeHA() as ha:
        gateway = RealGateway()
        conn = open_connection(gateway, target_for(ha))
        deadline = time.monotonic() + 5
        while ha.connections < 1 and time.monotonic() < deadline:
            time.sleep(0.01)  # the accept thread counts the connection a moment later
        assert ha.connections == 1 and ha.requests == []  # connected, nothing sent
        events: list[str] = []

        def gate() -> None:
            events.append("gate")
            assert ha.requests == []

        exchange(conn, target_for(ha), "GET", "/api/", None, before_write=gate)
    assert events == ["gate"] and len(ha.requests) == 1


def test_an_unknown_scheme_is_refused_before_any_connection() -> None:
    class CountingGateway:
        def __init__(self) -> None:
            self.connects = 0

        def connect(self, spec: ConnectSpec) -> object:
            self.connects += 1
            raise AssertionError("no connection may be attempted")

    parsed = parse_base_url("http://ha.example")
    assert parsed is not None
    target = Target(dataclasses.replace(parsed, scheme="ftp"), TOKEN, "HA_TOKEN", None, 1.0, 1.0)
    gateway = CountingGateway()
    with pytest.raises(ValueError, match="unsupported scheme") as caught:
        open_connection(gateway, target)  # type: ignore[arg-type]
    assert gateway.connects == 0
    assert TOKEN not in str(caught.value)


def test_a_refusing_gate_writes_nothing_and_closes() -> None:
    class Refused(Exception):
        pass

    def gate() -> None:
        raise Refused

    with FakeHA() as ha:
        with pytest.raises(Refused):
            send_once(RealGateway(), target_for(ha), SERVICE, BODY, before_write=gate)
        deadline = time.monotonic() + 5
        while ha.connections < 1 and time.monotonic() < deadline:
            time.sleep(0.01)  # the accept thread counts the connection a moment later
    assert ha.connections == 1
    assert ha.requests == [] and all(r == b"" for r in ha.received)


# --- TLS ---------------------------------------------------------------------------------------


def test_the_selected_context_is_strict(self_signed_cert: tuple[Path, Path]) -> None:
    ctx = select_trust(CaGateway(), str(self_signed_cert[0]))
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert ctx.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert ctx.cert_store_stats()["x509_ca"] == 1


def test_ca_file_alone_is_the_whole_trust_when_the_default_is_empty(
    self_signed_cert: tuple[Path, Path],
) -> None:
    cert, key = self_signed_cert
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key) as ha:
        tls = select_trust(CaGateway(), str(cert))
        response = send_once(RealGateway(), target_for(ha, tls=tls), SERVICE, BODY)
    assert response.status == 200 and ha.requests[0].tls


def test_no_default_trust_and_no_ca_file_is_a_trust_error() -> None:
    with pytest.raises(TrustError) as info:
        select_trust(CaGateway(), None)
    assert info.value.reason == "no_trust"
    assert "no usable CA certificates" in str(info.value)


@pytest.mark.parametrize("bad", ["missing", "empty", "text", "directory"])
def test_an_unusable_ca_file_is_a_trust_error(
    tmp_path: Path, self_signed_cert: tuple[Path, Path], bad: str
) -> None:
    path = tmp_path / "ca.pem"
    if bad == "empty":
        path.write_bytes(b"")
    elif bad == "text":
        path.write_text("this is not a certificate\n")
    elif bad == "directory":
        path.mkdir()
    default = CaCandidates(str(self_signed_cert[0]), "", ())  # a good default does not hide it
    with pytest.raises(TrustError) as info:
        select_trust(CaGateway(default), str(path))
    assert info.value.reason == "ca_file"
    assert str(tmp_path) not in str(info.value)


NOISE = {
    "utf8-comment": "# café ☃\n".encode(),
    "latin1-comment": "# café\n".encode("latin-1"),
    "bom": b"\xef\xbb\xbf",
    "nul-and-0xff": b"\x00\xff\xfe junk \x80\n",
}


@pytest.mark.parametrize("noise", sorted(NOISE))
@pytest.mark.parametrize("where", ["before", "after", "between"])
def test_ca_file_ignores_non_ascii_text_outside_the_certificate_blocks(
    tmp_path: Path,
    self_signed_cert: tuple[Path, Path],
    other_cert: tuple[Path, Path],
    noise: str,
    where: str,
) -> None:
    junk = NOISE[noise]
    first = self_signed_cert[0].read_bytes()
    second = other_cert[0].read_bytes()
    body = {
        "before": junk + first,
        "after": first + junk,
        "between": first + junk + second,
    }[where]
    path = tmp_path / "ca.pem"
    path.write_bytes(body)
    tls = select_trust(CaGateway(), str(path))
    assert tls.cert_store_stats()["x509_ca"] == (2 if where == "between" else 1)


def test_ca_file_with_noise_still_verifies_the_server(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    cert, key = self_signed_cert
    path = tmp_path / "ca.pem"
    path.write_bytes("# café\n".encode() + cert.read_bytes() + b"\xff\n")
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key) as ha:
        tls = select_trust(CaGateway(), str(path))
        assert send_once(RealGateway(), target_for(ha, tls=tls), SERVICE, BODY).status == 200


def _der(cert: Path) -> bytes:
    return ssl.PEM_cert_to_DER_cert(cert.read_text())


@pytest.mark.parametrize("shape", ["der", "truncated", "no-end", "empty", "noise-only", "trusted"])
def test_ca_file_without_a_whole_certificate_block_is_a_trust_error(
    tmp_path: Path, self_signed_cert: tuple[Path, Path], shape: str
) -> None:
    pem = self_signed_cert[0].read_text()
    data = {
        "der": _der(self_signed_cert[0]),
        "truncated": pem[: len(pem) // 2].encode(),
        "no-end": pem.replace("-----END CERTIFICATE-----", "").encode(),
        "empty": b"",
        "noise-only": "# café\n\xff".encode(),
        # a block kind the library does not load as a CA bundle entry is not extracted
        "trusted": pem.replace("CERTIFICATE", "TRUSTED CERTIFICATE").encode(),
    }[shape]
    path = tmp_path / "ca.pem"
    path.write_bytes(data)
    with pytest.raises(TrustError) as info:
        select_trust(CaGateway(), str(path))
    assert info.value.reason == "ca_file"


def test_a_garbled_certificate_block_in_ca_file_is_a_trust_error(tmp_path: Path) -> None:
    path = tmp_path / "ca.pem"
    path.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    with pytest.raises(TrustError) as info:
        select_trust(CaGateway(), str(path))
    assert info.value.reason == "ca_file"


def test_a_default_bundle_with_non_ascii_comments_is_usable_as_compiled_cafile(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    cafile = tmp_path / "cert.pem"
    cafile.write_bytes(
        "## Bundle — café\n".encode() + b"\xff\xfe\n" + self_signed_cert[0].read_bytes()
    )
    tls = select_trust(CaGateway(CaCandidates(str(cafile), "", ())), None)
    assert tls.cert_store_stats()["x509_ca"] == 1


def test_a_default_bundle_with_non_ascii_comments_is_usable_as_fallback_file(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    fallback = tmp_path / "ca-bundle.crt"
    fallback.write_bytes(
        "# Zertifikate — für alle\n".encode() + self_signed_cert[0].read_bytes() + b"\x00\xff"
    )
    candidates = CaCandidates(str(tmp_path / "missing.pem"), "", (str(fallback),))
    assert select_trust(CaGateway(candidates), None).cert_store_stats()["x509_ca"] == 1


def test_a_default_bundle_that_is_der_or_noise_is_not_usable(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    der = tmp_path / "der.pem"
    der.write_bytes(_der(self_signed_cert[0]))
    noise = tmp_path / "noise.pem"
    noise.write_bytes("café\xff".encode())
    with pytest.raises(TrustError) as info:
        select_trust(CaGateway(CaCandidates(str(der), "", (str(noise),))), None)
    assert info.value.reason == "no_trust"


def test_a_failing_default_source_is_no_trust_and_not_blamed_on_ca_file(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    capath = tmp_path / "certs"
    capath.mkdir()
    (capath / "x.pem").write_text("whatever")

    class BrokenDirectory(FakeGateway):
        def new_tls_context(self, ca_files, ca_dirs=(), ca_pems=()):  # noqa: ANN001, ANN202
            if ca_dirs:
                raise GatewayError("trust file cannot be loaded")
            return super().new_tls_context(ca_files, ca_dirs, ca_pems)

    gateway = BrokenDirectory(ca=CaCandidates("", str(capath), ()))
    with pytest.raises(TrustError) as info:
        select_trust(gateway, str(self_signed_cert[0]))  # ca_file is fine on its own
    assert info.value.reason == "no_trust"
    # and a bad ca_file is still blamed on ca_file, with the same broken default in place
    bad = tmp_path / "bad.pem"
    bad.write_text("nothing here")
    with pytest.raises(TrustError) as info:
        select_trust(gateway, str(bad))
    assert info.value.reason == "ca_file"


def test_a_self_signed_certificate_without_trust_fails_verification(
    self_signed_cert: tuple[Path, Path], other_cert: tuple[Path, Path]
) -> None:
    cert, key = self_signed_cert
    default = CaCandidates(str(other_cert[0]), "", ())
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key) as ha:
        tls = select_trust(CaGateway(default), None)
        with pytest.raises(ssl.SSLCertVerificationError) as info:
            send_once(RealGateway(), target_for(ha, tls=tls), SERVICE, BODY)
        assert info.value.verify_code in UNTRUSTED
    assert ha.requests == [] and ha.received in ([], [b""])  # no request bytes were sent


def test_ca_file_is_added_to_a_usable_default(
    self_signed_cert: tuple[Path, Path], unrelated_ca: Path
) -> None:
    cert, key = self_signed_cert
    default = CaCandidates(str(unrelated_ca), "", ())
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key) as ha:
        tls = select_trust(CaGateway(default), str(cert))
        assert tls.cert_store_stats()["x509_ca"] == 2  # both the default and ca_file
        assert send_once(RealGateway(), target_for(ha, tls=tls), SERVICE, BODY).status == 200


def test_a_certificate_for_another_name_fails_even_when_trusted(
    other_cert: tuple[Path, Path],
) -> None:
    cert, key = other_cert
    with FakeHA(certfile=cert, keyfile=key) as ha:
        tls = select_trust(CaGateway(), str(cert))
        with pytest.raises(ssl.SSLCertVerificationError) as info:
            send_once(RealGateway(), target_for(ha, tls=tls), SERVICE, BODY)
        assert info.value.verify_code in HOST_MISMATCH
    assert ha.requests == []


def _serve_and_send(cert: tuple[Path, Path], host: str = "127.0.0.1") -> int:
    """Send one request to an HTTPS fake that presents ``cert`` and trusts only ``cert``."""
    with FakeHA(token=TOKEN, certfile=cert[0], keyfile=cert[1]) as ha:
        parsed = parse_base_url(f"https://{host}:{ha.port}")
        assert parsed is not None
        tls = select_trust(CaGateway(), str(cert[0]))
        target = Target(parsed, TOKEN, "HA_TOKEN", tls, 5.0, 5.0)
        return send_once(RealGateway(), target, SERVICE, BODY).status


def test_a_dns_name_san_verifies_through_localhost(self_signed_cert: tuple[Path, Path]) -> None:
    # localhost may resolve to ::1 first; the fake listens on IPv4 only and the gateway tries on.
    assert _serve_and_send(self_signed_cert, "localhost") == 200


def test_an_rsa_leaf_that_is_not_a_ca_with_an_ip_san_verifies(tmp_path: Path) -> None:
    cert = make_self_signed_cert(tmp_path, name="rsa-leaf", rsa=True, is_ca=False)
    assert _serve_and_send(cert) == 200


def test_a_certificate_without_a_san_fails_even_when_trusted(tmp_path: Path) -> None:
    cert = make_self_signed_cert(tmp_path, name="no-san", sans=())
    with pytest.raises(ssl.SSLCertVerificationError) as info:
        _serve_and_send(cert)
    assert info.value.verify_code in HOST_MISMATCH


def test_an_expired_certificate_fails_even_when_trusted(tmp_path: Path) -> None:
    cert = make_self_signed_cert(tmp_path, name="expired", expired=True)
    with pytest.raises(ssl.SSLCertVerificationError) as info:
        _serve_and_send(cert)
    assert info.value.verify_code in EXPIRED


def test_tls_against_a_plain_http_server_sends_only_a_client_hello_and_no_token() -> None:
    with FakeHA() as ha:
        parsed = parse_base_url(f"https://127.0.0.1:{ha.port}")
        assert parsed is not None
        tls = RealGateway().new_tls_context([])
        with pytest.raises((ssl.SSLError, OSError)):
            send_once(
                RealGateway(), Target(parsed, TOKEN, "HA_TOKEN", tls, 2.0, 2.0), SERVICE, BODY
            )
        deadline = time.monotonic() + 5
        while not any(ha.received) and time.monotonic() < deadline:
            time.sleep(0.01)  # the server thread records the bytes a moment later
    assert ha.requests == []
    seen = [r for r in ha.received if r]
    assert seen, "the client sent nothing at all, so the handshake was not attempted"
    assert all(r[:2] == b"\x16\x03" for r in seen)  # a TLS handshake record, not an HTTP request
    assert all(TOKEN.encode() not in r and b"POST" not in r for r in seen)


def test_the_http_scheme_is_honoured_against_a_tls_server(
    self_signed_cert: tuple[Path, Path],
) -> None:
    """``http`` against a TLS port is a configuration error of the caller: no handshake is
    started, the server cannot parse the plain-text request and drops the connection, so the
    attempt ends with a connection error and no request is ever answered. (The token is in that
    plain-text request by design: ``http`` needs ``allow_insecure_http``.)"""
    cert, key = self_signed_cert
    with FakeHA(certfile=cert, keyfile=key) as ha:
        parsed = parse_base_url(f"http://127.0.0.1:{ha.port}")
        assert parsed is not None
        target = Target(parsed, TOKEN, "HA_TOKEN", None, 2.0, 2.0)
        with pytest.raises(ConnectionError):
            send_once(RealGateway(), target, SERVICE, BODY)
    assert ha.requests == []


def test_ssl_environment_variables_are_ignored(
    monkeypatch: pytest.MonkeyPatch,
    self_signed_cert: tuple[Path, Path],
    other_cert: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    cert, key = self_signed_cert
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    (cert_dir / "server.pem").write_bytes(cert.read_bytes())
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))  # the "fake CA" that would verify the server
    monkeypatch.setenv("SSL_CERT_DIR", str(cert_dir))
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(cert))
    monkeypatch.setenv("CURL_CA_BUNDLE", str(cert))
    # With nothing usable there is no trust at all, whatever the variables name.
    with pytest.raises(TrustError):
        select_trust(CaGateway(), None)
    # With an unrelated default the server does not verify.
    default = CaCandidates(str(other_cert[0]), "", ())
    with FakeHA(certfile=cert, keyfile=key) as ha:
        tls = select_trust(CaGateway(default), None)
        with pytest.raises(ssl.SSLCertVerificationError) as info:
            send_once(RealGateway(), target_for(ha, tls=tls), SERVICE, BODY)
        assert info.value.verify_code in UNTRUSTED
        # The real gateway's own candidates are the compiled ones, never the variables.
        real = RealGateway().ca_candidates()
        assert str(cert) not in (real.cafile, real.capath)
        assert str(cert_dir) not in (real.cafile, real.capath)


# --- trust selection: the CA fallback matrix ---------------------------------------------------


def test_an_empty_compiled_cafile_and_empty_capath_and_no_fallback_leave_no_trust(
    tmp_path: Path,
) -> None:
    cafile = tmp_path / "cert.pem"
    cafile.write_bytes(b"")
    capath = tmp_path / "certs"
    capath.mkdir()
    with pytest.raises(TrustError) as info:
        select_trust(
            CaGateway(CaCandidates(str(cafile), str(capath), (str(tmp_path / "nope"),))), None
        )
    assert info.value.reason == "no_trust"


def test_with_an_empty_default_ca_file_alone_is_the_whole_trust(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    cert, key = self_signed_cert
    cafile = tmp_path / "cert.pem"
    cafile.write_bytes(b"")
    capath = tmp_path / "certs"
    capath.mkdir()
    gateway = CaGateway(CaCandidates(str(cafile), str(capath), ()))
    tls = select_trust(gateway, str(cert))
    assert tls.cert_store_stats()["x509_ca"] == 1
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key) as ha:
        assert send_once(RealGateway(), target_for(ha, tls=tls), SERVICE, BODY).status == 200


def test_both_compiled_locations_missing_fall_back_to_the_first_usable_file(
    tmp_path: Path, self_signed_cert: tuple[Path, Path], other_cert: tuple[Path, Path]
) -> None:
    junk = tmp_path / "junk.crt"
    junk.write_text("not a certificate")
    candidates = CaCandidates(
        str(tmp_path / "missing.pem"),
        str(tmp_path / "missing-dir"),
        (str(tmp_path / "absent.crt"), str(junk), str(other_cert[0]), str(self_signed_cert[0])),
    )
    tls = select_trust(CaGateway(candidates), None)
    assert tls.cert_store_stats()["x509_ca"] == 1  # only the first usable fallback (other_cert)
    cert, key = self_signed_cert
    with FakeHA(certfile=cert, keyfile=key) as ha:
        with pytest.raises(ssl.SSLCertVerificationError) as info:
            send_once(RealGateway(), target_for(ha, tls=tls), SERVICE, BODY)
        assert info.value.verify_code in UNTRUSTED


def test_a_usable_compiled_cafile_means_no_fallback_is_used(
    tmp_path: Path, self_signed_cert: tuple[Path, Path], other_cert: tuple[Path, Path]
) -> None:
    candidates = CaCandidates(str(other_cert[0]), "", (str(self_signed_cert[0]),))
    assert select_trust(CaGateway(candidates), None).cert_store_stats()["x509_ca"] == 1


def test_a_non_empty_capath_counts_as_usable_and_stops_the_fallback(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    capath = tmp_path / "certs"
    capath.mkdir()
    (capath / "unhashed.pem").write_bytes(self_signed_cert[0].read_bytes())  # name is not a hash
    candidates = CaCandidates(
        str(tmp_path / "missing.pem"), str(capath), (str(self_signed_cert[0]),)
    )
    cert, key = self_signed_cert
    tls = select_trust(CaGateway(candidates), None)  # no TrustError: the directory is the trust
    assert tls.cert_store_stats()["x509_ca"] == 0  # unhashed files are not found lazily
    with FakeHA(certfile=cert, keyfile=key) as ha:
        with pytest.raises(ssl.SSLCertVerificationError) as info:
            send_once(RealGateway(), target_for(ha, tls=tls), SERVICE, BODY)  # tls, not retryable
        assert info.value.verify_code in UNTRUSTED
    assert ha.requests == []


def test_a_capath_that_is_a_file_or_missing_is_not_used(
    tmp_path: Path, self_signed_cert: tuple[Path, Path]
) -> None:
    as_file = tmp_path / "file"
    as_file.write_text("x")
    for capath in (str(as_file), str(tmp_path / "missing")):
        with pytest.raises(TrustError):
            select_trust(CaGateway(CaCandidates("", capath, ())), None)


def test_both_default_locations_are_used_together(
    tmp_path: Path, self_signed_cert: tuple[Path, Path], other_cert: tuple[Path, Path]
) -> None:
    capath = tmp_path / "certs"
    capath.mkdir()
    (capath / "x.pem").write_text("whatever")
    candidates = CaCandidates(str(other_cert[0]), str(capath), ())
    cert, key = self_signed_cert
    tls = select_trust(CaGateway(candidates), str(cert))
    assert tls.cert_store_stats()["x509_ca"] == 2


def test_the_real_gateway_default_trust_does_not_verify_the_fake(
    self_signed_cert: tuple[Path, Path],
) -> None:
    cert, key = self_signed_cert
    cafile = ssl.get_default_verify_paths().openssl_cafile
    try:
        tls = select_trust(RealGateway(), None)
    except TrustError:
        if cafile and os.path.isfile(cafile) and os.path.getsize(cafile) > 0:
            pytest.fail("the compiled openssl_cafile exists and is not empty, yet it is not usable")
        pytest.skip("this host has no usable default trust")
    with FakeHA(certfile=cert, keyfile=key) as ha:
        with pytest.raises(ssl.SSLCertVerificationError) as info:
            send_once(RealGateway(), target_for(ha, tls=tls), SERVICE, BODY)
        assert info.value.verify_code in UNTRUSTED


# --- the gateway's trust loaders ---------------------------------------------------------------


def test_the_gateway_loads_pem_bytes_and_refuses_bad_input(
    self_signed_cert: tuple[Path, Path],
) -> None:
    gateway = RealGateway()
    pem = self_signed_cert[0].read_bytes()
    assert gateway.new_tls_context([], (), [pem]).cert_store_stats()["x509_ca"] == 1
    for bad in (b"", b"junk", "é".encode()):
        with pytest.raises(Exception) as info:
            gateway.new_tls_context([], (), [bad])
        assert type(info.value).__name__ == "GatewayError"


def test_has_entries_is_true_only_for_a_directory_with_something_in_it(tmp_path: Path) -> None:
    gateway = RealGateway()
    empty = tmp_path / "empty"
    empty.mkdir()
    full = tmp_path / "full"
    full.mkdir()
    (full / ".hidden").write_text("")
    plain = tmp_path / "plain"
    plain.write_text("x")
    assert not gateway.has_entries(str(empty))
    assert gateway.has_entries(str(full))  # any entry counts, hidden or not
    assert not gateway.has_entries(str(plain))
    assert not gateway.has_entries(str(tmp_path / "missing"))
    assert not gateway.has_entries("")
