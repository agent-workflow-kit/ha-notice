"""Response mapping (issue #23): an answer or an exception to a success or an error spec.

Pure functions, no I/O (docs/interface.md, Home Assistant edge). The caller (the send flow, #27,
and the retry loop, #24) owns the attempts, the waits, the deadline and the writing gate (#25);
this module only classifies one result:

- ``classify_response(raw, op=...)``: the answer of one attempt (``RawResponse``) to ``Success``
  or an ``ErrorSpec``. Only the status and the shape of the body are read; no body text, header
  or exception text is ever put in a spec, and every message is a fixed string of ``output.py``.
- ``classify_exception(exc, gate, op=...)``: the exception of one attempt. The code is chosen by
  the gate state alone (``Gate``), never by the class, except for the families named below.

An ``ErrorSpec`` builds into the envelope through ``output.build_error`` (``build``), which
derives ``retryable`` and ``unknown_outcome`` from the exit-12 table. ``retry`` marks what the
retry loop may do with it: ``RATE_LIMIT`` (a 429: the loop supplies ``retry_after_s``),
``CONNECTION`` (a failure while idle that is not a certificate failure: one retry), else none.

Judgment calls, each the conservative reading of the interface:

- A status outside 200 to 599 is not a status: a non-final 1xx (``http.client`` swallows only 100,
  so 101 to 199 reach the caller) and 600 to 999 (``http.client`` lets them through) are
  ``wrong_host_response`` with no ``http_status`` and ``unknown_outcome`` true, like an answer
  that is not HTTP.
- An exception class outside the families below (``ValueError``, a bug, ``KeyboardInterrupt``) is
  ``internal`` (never retried), with ``unknown_outcome`` true exactly when the gate is writing,
  also when the gate is idle (the interface's "any class" for idle covers the network families).
- ``details.tls`` is true only for a certificate verification failure and a ``TrustError``;
  any other ``ssl.SSLError`` while idle is retryable (``tls`` false), as the interface says.
"""

from __future__ import annotations

import enum
import errno
from dataclasses import dataclass, field
from typing import Any

from ha_notice import output
from ha_notice.config import CredentialError
from ha_notice.gateway import (
    HTTPException,
    IncompleteRead,
    RemoteDisconnected,
    SSLCertVerificationError,
)
from ha_notice.hass import RawResponse, TrustError
from ha_notice.output import ErrorResult, build_error
from ha_notice.payload import hardened_loads

__all__ = [
    "ErrorSpec",
    "Gate",
    "Op",
    "Retry",
    "Success",
    "classify_exception",
    "classify_response",
]


class Gate(enum.Enum):
    """The state of the writing gate when the attempt failed (#25 owns the gate itself)."""

    IDLE = "idle"
    WRITING = "writing"


class Op(enum.Enum):
    SEND = "send"
    PROBE = "probe"


class Retry(enum.Enum):
    NONE = "none"
    RATE_LIMIT = "rate_limit"  # a 429: up to two retries after 2 s and 4 s (#24)
    CONNECTION = "connection"  # a failure while idle: one retry after 2 s (#24)


@dataclass(frozen=True)
class Success:
    """The host accepted the request: a 200 with a JSON list (send) or object (probe)."""

    http_status: int


@dataclass(frozen=True)
class ErrorSpec:
    """One failed attempt: the code, its details and what the retry loop may do."""

    code: str
    details: dict[str, Any] = field(default_factory=dict)
    message: str | None = None
    retry: Retry = Retry.NONE
    probe: bool = False
    after_writing: bool = False  # internal only: the gate was writing

    @property
    def exit_code(self) -> int:
        return output.EXIT_CODES[self.code]

    def _result(self, tag_sent: bool, retry_after_s: int | float | None) -> ErrorResult:
        kwargs: dict[str, Any] = dict(self.details)
        if self.message is not None:
            kwargs["message"] = self.message
        if self.after_writing:
            kwargs["after_writing"] = True
        return build_error(self.code, tag_sent=tag_sent, retry_after_s=retry_after_s, **kwargs)

    @property
    def unknown_outcome(self) -> bool:
        """May the notification have been delivered? A probe delivers nothing: never."""
        if self.probe:
            return False
        wait = 0 if self.code == "rate_limited" else None
        flag = self._result(False, wait).envelope["error"]["unknown_outcome"]
        return bool(flag)

    def build(
        self, *, tag_sent: bool = False, retry_after_s: int | float | None = None
    ) -> ErrorResult:
        """The exit code and envelope. ``retry_after_s`` is required for ``rate_limited`` (the
        wait the retry loop last performed or could not fit) and refused for any other code. A
        probe has no envelope (``validate`` reports the code in its own check): ``ValueError``."""
        if self.probe:
            raise ValueError("a probe has no error envelope")
        return self._result(tag_sent, retry_after_s)


def _status_spec(status: object, op: Op) -> ErrorSpec:
    probe = op is Op.PROBE
    if type(status) is not int or not 200 <= status <= 599:
        return ErrorSpec("wrong_host_response", {}, probe=probe)
    if status == 400:
        return ErrorSpec(
            "host_rejected",
            {"http_status": 400, "hint": output.HOST_REJECTED_HINT},
            probe=probe,
        )
    if status in (401, 403):
        return ErrorSpec("auth_required", {"http_status": status}, probe=probe)
    if status in (404, 405):
        return ErrorSpec(
            "wrong_host_response",
            {"http_status": status},
            message=output.NOT_NOTIFY_API_MESSAGE,
            probe=probe,
        )
    if status == 429:
        return ErrorSpec("rate_limited", {"http_status": 429}, retry=Retry.RATE_LIMIT, probe=probe)
    if status >= 500:
        return ErrorSpec("upstream_error", {"http_status": status}, probe=probe)
    return ErrorSpec("wrong_host_response", {"http_status": status}, probe=probe)


def _body_is(response: RawResponse, kind: type) -> bool:
    """Is the body complete, strict UTF-8 and, by the hardened parse, a ``kind``?"""
    if response.too_large:
        return False
    try:
        value = hardened_loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    return isinstance(value, kind)


def classify_response(response: RawResponse, *, op: Op) -> Success | ErrorSpec:
    """Map one complete answer. Send: a 200 with a JSON list is ``Success``. Probe: a 200 with a
    JSON object is. Any other 200, and every other status, is an ``ErrorSpec`` (the body is read
    only for those two)."""
    if not isinstance(op, Op):
        raise TypeError("op must be an Op")
    status = response.status
    if type(status) is int and status == 200:
        kind = list if op is Op.SEND else dict
        if _body_is(response, kind):
            return Success(200)
        return ErrorSpec("wrong_host_response", {"http_status": 200}, probe=op is Op.PROBE)
    return _status_spec(status, op)


def _is_timeout(exc: BaseException) -> bool:
    return isinstance(exc, TimeoutError) or (
        isinstance(exc, OSError) and exc.errno == errno.ETIMEDOUT
    )


def classify_exception(exc: BaseException, gate: Gate, *, op: Op) -> ErrorSpec:
    """Map the exception of one attempt by the gate state; the text of ``exc`` is never read.

    Callers must not pass ``KeyboardInterrupt`` or ``SystemExit``: the signal handling and the
    Deadline paragraph of docs/interface.md decide what those do. If one is passed anyway it maps
    to ``internal``. The routing is owned by #25 and #27.
    """
    # todo(#27): route KeyboardInterrupt and SystemExit before this call (signal handling).
    if not isinstance(gate, Gate):
        raise TypeError("gate must be a Gate")
    if not isinstance(op, Op):
        raise TypeError("op must be an Op")
    probe = op is Op.PROBE
    writing = gate is Gate.WRITING
    internal = ErrorSpec("internal", after_writing=writing, probe=probe)
    if isinstance(exc, CredentialError):  # raised before any I/O
        if writing:
            return internal
        return ErrorSpec("credential_invalid", {"env": exc.env}, probe=probe)
    if isinstance(exc, TrustError):  # raised before any I/O
        if writing:
            return internal
        text = output.NO_TRUST_MESSAGE if exc.reason == "no_trust" else output.CA_FILE_MESSAGE
        return ErrorSpec(
            "network_error", {"tls": True, "timeout": False}, message=text, probe=probe
        )
    if not isinstance(exc, Exception):
        return internal
    if not writing:
        if not isinstance(exc, OSError | HTTPException):
            return internal
        tls = isinstance(exc, SSLCertVerificationError)
        return ErrorSpec(
            "network_error",
            {"tls": tls, "timeout": _is_timeout(exc)},
            message=output.CERTIFICATE_MESSAGE if tls else None,
            retry=Retry.NONE if tls else Retry.CONNECTION,
            probe=probe,
        )
    # Writing: the connection or the answer was lost (RemoteDisconnected is also a BadStatusLine,
    # so it is tested first), or an answer arrived that is not HTTP.
    if isinstance(exc, RemoteDisconnected | IncompleteRead | OSError):
        return ErrorSpec("outcome_unknown", probe=probe)
    if isinstance(exc, HTTPException):
        # A local InvalidURL or CannotSendRequest is also wrong_host_response with unknown_outcome
        # true by design: no answer arrived, and the safe side is "possibly delivered".
        return ErrorSpec("wrong_host_response", {}, probe=probe)
    return internal
