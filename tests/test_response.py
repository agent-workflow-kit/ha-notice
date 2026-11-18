"""Response mapping (issue #23): pure functions from an answer or an exception to a result.

The oracle is ``schemas/cli/error.json``: every error produced here must build into an envelope
that validates, with and without a dedupe key (``tag_sent``).
"""

from __future__ import annotations

import errno
import http.client
import socket
import ssl
from typing import Any

import pytest

from ha_notice import output
from ha_notice.config import CredentialError
from ha_notice.hass import RawResponse, TrustError
from ha_notice.response import (
    ErrorSpec,
    Gate,
    Op,
    Retry,
    Success,
    classify_exception,
    classify_response,
)
from tests.harness import schema_errors

HINT = output.HOST_REJECTED_HINT
SECRET = "HA_leakcheck-0123456789-ABCDEF"


def raw(status: int, body: bytes = b"[]", too_large: bool = False) -> RawResponse:
    return RawResponse(status, body, too_large)


def built(spec: ErrorSpec, *, tag: bool = False) -> dict[str, Any]:
    """The envelope body of a spec, validated against the schema."""
    kwargs: dict[str, Any] = {"tag_sent": tag}
    if spec.code == "rate_limited":
        kwargs["retry_after_s"] = 2
    result = spec.build(**kwargs)
    assert schema_errors("cli/error", result.envelope) == []
    assert result.exit_code == output.EXIT_CODES[spec.code]
    return result.envelope["error"]


def err(value: object) -> ErrorSpec:
    assert isinstance(value, ErrorSpec), value
    return value


# --- success ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body", [b"[]", b" [ ] \n", b'[{"a":1}]', b'["x", 1, null, true]', b"[[[]]]", b"[1.5e3]"]
)
def test_a_200_with_a_json_list_is_sent(body: bytes) -> None:
    assert classify_response(raw(200, body), op=Op.SEND) == Success(200)


def test_the_content_type_is_not_consulted() -> None:
    # RawResponse has no headers at all; a list is a list whatever the host said it was.
    assert classify_response(raw(200, b"[]"), op=Op.SEND) == Success(200)


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b'{"a":1}',
        b"null",
        b"1",
        b'"x"',
        b"true",
        b"",
        b"   ",
        b"<html><body>Home Assistant</body></html>",
        b"[",
        b"[1,]",
        b"[1] x",
        b"\xef\xbb\xbf[]",  # a BOM is refused
        b"\xff[]",  # not UTF-8
        b"[\xc3]",  # truncated UTF-8
        b"[NaN]",
        b"[Infinity]",
        b"[-Infinity]",
        b"[1e999]",
        b'[{"a":1,"a":2}]',  # duplicate keys
        b"[" + b"9" * 4301 + b"]",  # integer over 4300 digits
        b"[" * 101 + b"]" * 101,  # nesting over 100
        b"[" * 100000,
        b"[" * 100000 + b"]" * 100000,
        b"\x00",
    ],
)
def test_a_200_whose_body_is_not_a_json_list_is_wrong_host_response(body: bytes) -> None:
    spec = err(classify_response(raw(200, body), op=Op.SEND))
    error = built(spec)
    assert (error["code"], error["details"]) == ("wrong_host_response", {"http_status": 200})
    assert (error["retryable"], error["unknown_outcome"]) == (False, True)
    assert spec.retry is Retry.NONE


def test_a_list_at_the_nesting_limit_is_accepted() -> None:
    assert classify_response(raw(200, b"[" * 100 + b"]" * 100), op=Op.SEND) == Success(200)


def test_a_body_cut_at_the_cap_is_a_bad_body_even_when_the_prefix_parses() -> None:
    spec = err(classify_response(raw(200, b"[]", too_large=True), op=Op.SEND))
    assert spec.code == "wrong_host_response"
    assert built(spec)["unknown_outcome"] is True


def test_a_huge_valid_list_that_is_too_large_is_a_bad_body() -> None:
    body = b"[" + b"1," * 32768 + b"1]"
    assert len(body) > 64 * 1024
    spec = err(classify_response(raw(200, body[: 64 * 1024], too_large=True), op=Op.SEND))
    assert spec.code == "wrong_host_response"


@pytest.mark.parametrize("status", [201, 202, 203, 204, 205, 206, 207, 226, 299])
def test_any_other_2xx_is_wrong_host_response_with_unknown_outcome(status: int) -> None:
    for body in (b"[]", b"", b"{}"):
        error = built(err(classify_response(raw(status, body), op=Op.SEND)))
        assert error["code"] == "wrong_host_response"
        assert error["details"] == {"http_status": status}
        assert (error["retryable"], error["unknown_outcome"]) == (False, True)


# --- the status table ---------------------------------------------------------------------


def test_the_400_row_carries_the_fixed_hint_and_never_the_body() -> None:
    body = f'{{"message": "{SECRET} unknown service"}}'.encode()
    spec = err(classify_response(raw(400, body), op=Op.SEND))
    error = built(spec)
    assert error["code"] == "host_rejected"
    assert error["details"] == {"http_status": 400, "hint": HINT}
    assert HINT == "check the notify service name and the message; run validate --test-message"
    assert (error["retryable"], error["unknown_outcome"]) == (False, False)
    assert SECRET not in output.dumps(spec.build().envelope)
    assert spec.retry is Retry.NONE


@pytest.mark.parametrize("status", [401, 403])
def test_401_and_403_are_auth_required(status: int) -> None:
    error = built(err(classify_response(raw(status, b"{}"), op=Op.SEND)))
    assert (error["code"], error["details"]) == ("auth_required", {"http_status": status})
    assert (error["retryable"], error["unknown_outcome"]) == (False, False)


@pytest.mark.parametrize("status", [404, 405])
def test_404_and_405_name_base_url(status: int) -> None:
    spec = err(classify_response(raw(status, b"404: Not Found"), op=Op.SEND))
    error = built(spec)
    assert (error["code"], error["details"]) == ("wrong_host_response", {"http_status": status})
    assert (error["retryable"], error["unknown_outcome"]) == (False, False)
    assert "base_url" in error["message"] and "path prefix" in error["message"]


def test_429_is_rate_limited_and_marked_for_the_retry_loop() -> None:
    spec = err(classify_response(raw(429, b"{}"), op=Op.SEND))
    assert spec.retry is Retry.RATE_LIMIT
    for tag in (False, True):
        error = built(spec, tag=tag)
        assert (error["code"], error["details"]) == ("rate_limited", {"http_status": 429})
        assert (error["retryable"], error["unknown_outcome"]) == (True, False)
        assert error["retry_after_s"] == 2


def test_a_rate_limited_spec_needs_the_retry_loop_to_supply_the_wait() -> None:
    with pytest.raises(ValueError):
        err(classify_response(raw(429), op=Op.SEND)).build()


@pytest.mark.parametrize("status", [500, 501, 502, 503, 504, 520, 599])
def test_5xx_is_upstream_error_possibly_delivered_and_never_retried(status: int) -> None:
    spec = err(classify_response(raw(status, b"<html>"), op=Op.SEND))
    assert spec.retry is Retry.NONE
    plain = built(spec)
    tagged = built(spec, tag=True)
    assert (plain["code"], plain["details"]) == ("upstream_error", {"http_status": status})
    assert (plain["retryable"], plain["unknown_outcome"]) == (False, True)
    assert (tagged["retryable"], tagged["unknown_outcome"]) == (True, True)


@pytest.mark.parametrize("status", [300, 301, 302, 303, 304, 307, 308, 399])
def test_3xx_is_wrong_host_response_without_unknown_outcome(status: int) -> None:
    error = built(err(classify_response(raw(status, b""), op=Op.SEND)))
    assert (error["code"], error["details"]) == ("wrong_host_response", {"http_status": status})
    assert (error["retryable"], error["unknown_outcome"]) == (False, False)


@pytest.mark.parametrize("status", [402, 406, 408, 409, 410, 413, 418, 422])
def test_any_other_listed_range_status_is_wrong_host_response_not_unknown(status: int) -> None:
    error = built(err(classify_response(raw(status, b"[]"), op=Op.SEND)))
    assert (error["code"], error["details"]) == ("wrong_host_response", {"http_status": status})
    assert (error["retryable"], error["unknown_outcome"]) == (False, False)


@pytest.mark.parametrize(
    "status", [-1, 0, 1, 99, *range(100, 200), 600, 601, 999, 1000, 10**9, 2**70]
)
def test_a_status_outside_200_to_599_or_a_1xx_is_not_a_status_and_is_possibly_delivered(
    status: int,
) -> None:
    for op in (Op.SEND, Op.PROBE):
        spec = err(classify_response(raw(status, b"[]"), op=op))
        assert (spec.code, spec.details) == ("wrong_host_response", {})
    error = built(err(classify_response(raw(status, b"[]"), op=Op.SEND)))
    assert error["code"] == "wrong_host_response"
    assert error["details"] is None
    assert (error["retryable"], error["unknown_outcome"]) == (False, True)
    assert schema_errors("cli/error", {"error": error}) == []


@pytest.mark.parametrize("status", [True, False, 200.0, "200", None])
def test_a_status_that_is_not_an_int_is_not_a_status(status: Any) -> None:
    error = built(err(classify_response(raw(status, b"[]"), op=Op.SEND)))
    assert (error["code"], error["details"]) == ("wrong_host_response", None)


def test_every_status_from_100_to_599_is_mapped_and_valid_for_both_ops() -> None:
    expected = {
        400: "host_rejected",
        401: "auth_required",
        403: "auth_required",
        429: "rate_limited",
    }
    seen: set[str] = set()
    for status in range(100, 600):
        for op in (Op.SEND, Op.PROBE):
            for body in (b"[]", b"{}", b"x"):
                got = classify_response(raw(status, body), op=op)
                if isinstance(got, Success):
                    assert status == 200 and op in (Op.SEND, Op.PROBE)
                    continue
                spec = err(got)
                seen.add(spec.code)
                if status in expected:
                    assert spec.code == expected[status]
                elif 500 <= status:
                    assert spec.code == "upstream_error"
                else:
                    assert spec.code == "wrong_host_response"
                if not spec.probe:
                    for tag in (False, True):
                        built(spec, tag=tag)
    assert seen == {
        "host_rejected",
        "auth_required",
        "rate_limited",
        "upstream_error",
        "wrong_host_response",
    }


def test_no_response_body_is_ever_echoed() -> None:
    body = f'[{{"token": "{SECRET}"}}] <script>'.encode()
    for status in range(100, 600):
        got = classify_response(raw(status, body), op=Op.SEND)
        if isinstance(got, ErrorSpec):
            kwargs: dict[str, Any] = {"retry_after_s": 2} if got.code == "rate_limited" else {}
            assert SECRET not in output.dumps(got.build(**kwargs).envelope)


# --- the probe ----------------------------------------------------------------------------


@pytest.mark.parametrize("body", [b"{}", b'{"message":"API running."}', b' {"a":[1]} '])
def test_a_probe_200_with_a_json_object_is_ok(body: bytes) -> None:
    assert classify_response(raw(200, body), op=Op.PROBE) == Success(200)


@pytest.mark.parametrize(
    "body", [b"[]", b"[{}]", b"null", b"", b"<html>", b'{"a":1,"a":2}', b"{NaN}", b"\xff{}"]
)
def test_a_probe_200_that_is_not_an_object_is_wrong_host_response(body: bytes) -> None:
    spec = err(classify_response(raw(200, body), op=Op.PROBE))
    assert (spec.code, spec.details) == ("wrong_host_response", {"http_status": 200})
    assert spec.probe


def test_a_probe_200_object_cut_at_the_cap_is_a_bad_body() -> None:
    assert err(classify_response(raw(200, b"{}", too_large=True), op=Op.PROBE)).probe


def test_a_send_200_object_is_not_a_probe_ok_and_a_probe_list_is_not_a_send_ok() -> None:
    assert isinstance(classify_response(raw(200, b"{}"), op=Op.SEND), ErrorSpec)
    assert isinstance(classify_response(raw(200, b"[]"), op=Op.PROBE), ErrorSpec)


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (401, "auth_required"),
        (403, "auth_required"),
        (404, "wrong_host_response"),
        (405, "wrong_host_response"),
        (500, "upstream_error"),
        (502, "upstream_error"),
        (429, "rate_limited"),
        (400, "host_rejected"),
        (302, "wrong_host_response"),
    ],
)
def test_probe_statuses_map_as_for_send(status: int, code: str) -> None:
    spec = err(classify_response(raw(status, b"{}"), op=Op.PROBE))
    assert spec.code == code
    assert spec.probe


def test_a_probe_delivers_nothing_so_it_has_no_envelope_and_no_unknown_outcome() -> None:
    spec = err(classify_response(raw(200, b"[]"), op=Op.PROBE))
    assert spec.unknown_outcome is False
    with pytest.raises(ValueError):
        spec.build()
    send = err(classify_response(raw(200, b"{}"), op=Op.SEND))
    assert send.unknown_outcome is True


# --- exceptions ---------------------------------------------------------------------------

CERT_FAIL = ssl.SSLCertVerificationError(1, "certificate verify failed")


def refused() -> OSError:
    return ConnectionRefusedError(errno.ECONNREFUSED, "refused")


# (name, factory) for every class of the plan's table plus the families of the interface.
TABLE: list[tuple[str, Any]] = [
    ("ConnectionResetError", lambda: ConnectionResetError(errno.ECONNRESET, "reset")),
    ("BrokenPipeError", lambda: BrokenPipeError(errno.EPIPE, "pipe")),
    ("TimeoutError", lambda: TimeoutError("timed out")),
    ("SSLEOFError", lambda: ssl.SSLEOFError(8, "eof")),
    ("RemoteDisconnected", lambda: http.client.RemoteDisconnected("closed")),
    ("BadStatusLine", lambda: http.client.BadStatusLine("junk")),
    ("LineTooLong", lambda: http.client.LineTooLong("status line")),
    ("IncompleteRead", lambda: http.client.IncompleteRead(b"ab", 5)),
    ("InvalidURL", lambda: http.client.InvalidURL("bad")),
    ("UnknownProtocol", lambda: http.client.UnknownProtocol("HTTP/9")),
    ("HTTPException", lambda: http.client.HTTPException("x")),
    ("CannotSendRequest", lambda: http.client.CannotSendRequest()),
    ("ConnectionRefusedError", refused),
    ("ConnectionAbortedError", lambda: ConnectionAbortedError(errno.ECONNABORTED, "x")),
    ("gaierror", lambda: socket.gaierror(socket.EAI_NONAME, "unknown")),
    ("herror", lambda: socket.herror(1, "x")),
    ("OSError ENETUNREACH", lambda: OSError(errno.ENETUNREACH, "unreachable")),
    ("OSError EHOSTUNREACH", lambda: OSError(errno.EHOSTUNREACH, "no route")),
    ("OSError ETIMEDOUT", lambda: OSError(errno.ETIMEDOUT, "timed out")),
    ("OSError", lambda: OSError("plain")),
    ("SSLError", lambda: ssl.SSLError(1, "handshake failure")),
    ("SSLZeroReturnError", lambda: ssl.SSLZeroReturnError(6, "closed")),
    ("SSLCertVerificationError", lambda: CERT_FAIL),
    ("SSLCertVerificationError host", lambda: ssl.SSLCertVerificationError(1, "mismatch")),
]


def test_the_table_has_the_classes_the_plan_names() -> None:
    names = {n for n, _ in TABLE}
    assert {
        "ConnectionResetError",
        "BrokenPipeError",
        "TimeoutError",
        "SSLEOFError",
        "RemoteDisconnected",
        "BadStatusLine",
        "LineTooLong",
        "IncompleteRead",
        "InvalidURL",
    } <= names


@pytest.mark.parametrize(("name", "make"), TABLE, ids=[n for n, _ in TABLE])
@pytest.mark.parametrize("tag", [False, True], ids=["plain", "tagged"])
@pytest.mark.parametrize("op", [Op.SEND, Op.PROBE])
def test_an_exception_while_idle_is_network_error(name: str, make: Any, tag: bool, op: Op) -> None:
    spec = classify_exception(make(), Gate.IDLE, op=op)
    assert spec.code == "network_error", name
    assert spec.probe is (op is Op.PROBE)
    if op is Op.PROBE:
        return
    error = built(spec, tag=tag)
    assert error["unknown_outcome"] is False
    tls = isinstance(make(), ssl.SSLCertVerificationError)
    assert error["details"]["tls"] is tls
    assert error["retryable"] is (not tls)  # the tag does not matter: nothing was written
    assert spec.retry is (Retry.NONE if tls else Retry.CONNECTION)
    if tls:
        assert "ca_file" in error["message"]


@pytest.mark.parametrize(
    ("name", "make", "timeout"),
    [
        ("TimeoutError", lambda: TimeoutError("t"), True),
        ("OSError ETIMEDOUT", lambda: OSError(errno.ETIMEDOUT, "t"), True),
        ("ConnectionRefusedError", refused, False),
        ("gaierror", lambda: socket.gaierror(socket.EAI_NONAME, "x"), False),
        ("OSError ENETUNREACH", lambda: OSError(errno.ENETUNREACH, "x"), False),
        ("SSLError", lambda: ssl.SSLError(1, "x"), False),
        ("SSLEOFError", lambda: ssl.SSLEOFError(8, "x"), False),
        ("cert", lambda: CERT_FAIL, False),
    ],
)
def test_details_timeout_comes_from_the_class(name: str, make: Any, timeout: bool) -> None:
    spec = classify_exception(make(), Gate.IDLE, op=Op.SEND)
    assert spec.details["timeout"] is timeout, name


@pytest.mark.parametrize(("name", "make"), TABLE, ids=[n for n, _ in TABLE])
@pytest.mark.parametrize("tag", [False, True], ids=["plain", "tagged"])
def test_an_exception_while_writing_is_never_network_error_and_never_retried(
    name: str, make: Any, tag: bool
) -> None:
    exc = make()
    spec = classify_exception(exc, Gate.WRITING, op=Op.SEND)
    error = built(spec, tag=tag)
    assert spec.code != "network_error", name
    assert spec.retry is Retry.NONE
    assert error["unknown_outcome"] is True
    if isinstance(exc, http.client.RemoteDisconnected | http.client.IncompleteRead):
        want = "outcome_unknown"
    elif isinstance(exc, OSError):
        want = "outcome_unknown"
    else:
        assert isinstance(exc, http.client.HTTPException)
        want = "wrong_host_response"
    assert error["code"] == want, name
    if want == "outcome_unknown":
        assert error["retryable"] is tag  # true only with a tag
        assert error["details"] is None
    else:
        assert error["retryable"] is False
        assert error["details"] is None


def test_remote_disconnected_is_a_lost_connection_not_a_non_http_answer() -> None:
    # RemoteDisconnected is both a ConnectionResetError and a BadStatusLine.
    exc = http.client.RemoteDisconnected("Remote end closed connection without response")
    assert isinstance(exc, http.client.BadStatusLine)
    assert classify_exception(exc, Gate.WRITING, op=Op.SEND).code == "outcome_unknown"


@pytest.mark.parametrize(
    "make",
    [
        lambda: http.client.BadStatusLine("x"),
        lambda: http.client.LineTooLong("status line"),
        lambda: http.client.UnknownProtocol("x"),
        lambda: http.client.InvalidURL("x"),
        lambda: http.client.HTTPException("x"),
        lambda: http.client.NotConnected(),
    ],
)
def test_a_non_http_answer_after_writing_is_wrong_host_response_without_a_status(
    make: Any,
) -> None:
    spec = classify_exception(make(), Gate.WRITING, op=Op.SEND)
    assert (spec.code, spec.details) == ("wrong_host_response", {})
    for tag in (False, True):
        error = built(spec, tag=tag)
        assert error["details"] is None
        assert (error["retryable"], error["unknown_outcome"]) == (False, True)


def test_a_timeout_after_writing_is_outcome_unknown_with_no_details() -> None:
    spec = classify_exception(TimeoutError("t"), Gate.WRITING, op=Op.SEND)
    assert spec.code == "outcome_unknown" and spec.details == {}


def test_the_first_request_call_failing_is_outcome_unknown_whatever_class() -> None:
    # The gate is writing before conn.request, so the gate alone decides.
    for exc in (OSError("x"), ssl.SSLError("x"), http.client.InvalidURL("x"), TimeoutError()):
        spec = classify_exception(exc, Gate.WRITING, op=Op.SEND)
        assert spec.code in ("outcome_unknown", "wrong_host_response")
        assert built(spec)["unknown_outcome"] is True


@pytest.mark.parametrize("reason", ["no_trust", "ca_file"])
def test_a_trust_error_is_a_network_error_with_tls_and_not_retryable(reason: str) -> None:
    spec = classify_exception(TrustError(reason), Gate.IDLE, op=Op.SEND)  # type: ignore[arg-type]
    error = built(spec)
    assert error["code"] == "network_error"
    assert error["details"] == {"tls": True, "timeout": False}
    assert (error["retryable"], error["unknown_outcome"]) == (False, False)
    assert spec.retry is Retry.NONE
    assert "ca_file" in error["message"]
    if reason == "no_trust":
        assert "no usable CA certificates" in error["message"]


def test_a_credential_error_is_credential_invalid_with_the_variable_name() -> None:
    spec = classify_exception(CredentialError("HA_TOKEN"), Gate.IDLE, op=Op.SEND)
    error = built(spec)
    assert (error["code"], error["details"]) == ("credential_invalid", {"env": "HA_TOKEN"})
    assert (error["retryable"], error["unknown_outcome"]) == (False, False)
    assert spec.retry is Retry.NONE


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("x"),
        KeyError("x"),
        RuntimeError("x"),
        AttributeError("x"),
        UnicodeEncodeError("latin-1", "", 0, 1, "x"),
        RecursionError(),
        MemoryError(),
        AssertionError(),
        KeyboardInterrupt(),
        SystemExit(3),
    ],
    ids=lambda e: type(e).__name__,
)
@pytest.mark.parametrize("gate", [Gate.IDLE, Gate.WRITING])
def test_an_unexpected_class_is_internal_with_unknown_outcome_from_the_gate(
    exc: BaseException, gate: Gate
) -> None:
    spec = classify_exception(exc, gate, op=Op.SEND)
    error = built(spec)
    assert error["code"] == "internal" and error["message"] == "internal error"
    assert (error["retryable"], error["unknown_outcome"]) == (False, gate is Gate.WRITING)
    assert spec.retry is Retry.NONE


def test_a_credential_or_trust_error_cannot_happen_while_writing() -> None:
    # Both are raised before any I/O; seeing one with the gate writing is a bug: exit 1.
    for exc in (CredentialError("HA_TOKEN"), TrustError("no_trust")):
        spec = classify_exception(exc, Gate.WRITING, op=Op.SEND)
        assert built(spec)["code"] == "internal"
        assert built(spec)["unknown_outcome"] is True


def test_exception_text_is_never_printed() -> None:
    texts = [
        OSError(errno.ECONNRESET, SECRET),
        ssl.SSLError(1, SECRET),
        ssl.SSLCertVerificationError(1, SECRET),
        http.client.BadStatusLine(SECRET),
        http.client.InvalidURL(SECRET),
        http.client.LineTooLong(SECRET),
        ValueError(SECRET),
        socket.gaierror(socket.EAI_NONAME, SECRET),
        TimeoutError(SECRET),
    ]
    for exc in texts:
        for gate in Gate:
            spec = classify_exception(exc, gate, op=Op.SEND)
            assert SECRET not in output.dumps(spec.build().envelope)
            assert SECRET not in repr(spec)


def test_every_table_cell_reaches_a_schema_valid_envelope() -> None:
    cells = 0
    for _, make in TABLE:
        for gate in Gate:
            for tag in (False, True):
                built(classify_exception(make(), gate, op=Op.SEND), tag=tag)
                cells += 1
    assert cells == len(TABLE) * 4


def test_the_gate_and_op_are_enums_and_nothing_else_is_accepted() -> None:
    with pytest.raises(TypeError):
        classify_exception(OSError(), "idle", op=Op.SEND)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        classify_exception(OSError(), Gate.IDLE, op="send")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        classify_response(raw(200), op="send")  # type: ignore[arg-type]
    assert {g.name for g in Gate} == {"IDLE", "WRITING"}


def test_a_spec_is_immutable_and_has_the_closed_codes() -> None:
    spec = err(classify_response(raw(500), op=Op.SEND))
    with pytest.raises(AttributeError):
        spec.code = "x"  # type: ignore[misc]
    assert spec.exit_code == 12


def test_the_retry_marks_cover_the_interface() -> None:
    marks = {
        "429": classify_response(raw(429), op=Op.SEND),
        "refused-idle": classify_exception(refused(), Gate.IDLE, op=Op.SEND),
        "handshake-idle": classify_exception(ssl.SSLEOFError(8, "x"), Gate.IDLE, op=Op.SEND),
        "cert-idle": classify_exception(CERT_FAIL, Gate.IDLE, op=Op.SEND),
        "500": classify_response(raw(500), op=Op.SEND),
        "reset-writing": classify_exception(ConnectionResetError(), Gate.WRITING, op=Op.SEND),
    }
    assert {k: err(v).retry for k, v in marks.items()} == {
        "429": Retry.RATE_LIMIT,
        "refused-idle": Retry.CONNECTION,
        "handshake-idle": Retry.CONNECTION,
        "cert-idle": Retry.NONE,
        "500": Retry.NONE,
        "reset-writing": Retry.NONE,
    }
