"""Output sink, exit-code table and error envelope (docs/interface.md: Output, Exit codes).

One place maps an outcome to its exit code, its envelope and its human line.

- ``build_error`` is the only constructor of an error envelope. It takes a code from the closed
  table, picks the fixed message, derives ``retryable`` and ``unknown_outcome`` from the exit-12
  table and refuses (``ValueError``, a programming error that ``cli.main`` turns into exit 1) any
  detail that would not match ``schemas/cli/error.json``. No message is built from input.
- ``safe_pointer`` and ``safe_key`` are the hostile-input rules for ``details.pointer`` and
  ``details.key``: a name that is not plain becomes ``?``.
- ``emit_error`` and ``fail`` print the envelope on stdout (with ``--json``) and then the one
  human line on stderr: stdout is written and flushed before stderr.
- ``write_text`` is the single sink. It writes UTF-8 bytes with errors replaced, never through the
  locale, and ignores every failure (a failed stream is pointed at the null device so that the
  data still buffered cannot fail again at interpreter shutdown). ``flush_streams`` makes one last
  flush attempt of stdout and then stderr.
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, TextIO

EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2
EXIT_FAILED = 12
EXIT_REFUSED = 20
EXIT_DISABLED = 22  # not an error: nothing was sent because the config disables the tool
# 128 + N (129 SIGHUP, 130 SIGINT, 143 SIGTERM) is exit 128+N, no envelope: TODO(#26) signals.

# Exits 10, 11, 13 and 21 are never used (docs/interface.md, Exit codes).
EXIT_CODES: dict[str, int] = {
    "usage": EXIT_USAGE,
    "config_invalid": EXIT_USAGE,
    "internal": EXIT_INTERNAL,
    "refused": EXIT_REFUSED,
    "host_rejected": EXIT_FAILED,
    "auth_required": EXIT_FAILED,
    "credential_invalid": EXIT_FAILED,
    "rate_limited": EXIT_FAILED,
    "upstream_error": EXIT_FAILED,
    "network_error": EXIT_FAILED,
    "outcome_unknown": EXIT_FAILED,
    "wrong_host_response": EXIT_FAILED,
    "unavailable": EXIT_FAILED,
}

# Fixed messages: never a response body, header, exception text, input value or the credential.
MESSAGES: dict[str, str] = {
    "usage": "invalid command line; see ha-notice --help",
    "config_invalid": "invalid configuration",
    "internal": "internal error",
    "host_rejected": "Home Assistant rejected the request",
    "auth_required": "Home Assistant requires authentication",
    "credential_invalid": "the credential is missing or invalid",
    "rate_limited": "rate limited",
    "upstream_error": "Home Assistant reported a server error",
    "network_error": "network error",
    "outcome_unknown": "the outcome of the request is unknown",
    "wrong_host_response": "the host did not answer like the notify API",
    "unavailable": "the input did not arrive in time",
}
REASON_MESSAGES: dict[str, str] = {
    "invalid_payload": "the notification is not valid",
    "empty_message": "the message is empty",
    "command_keyword": "the message is a companion-app command word",
    "link_invalid": "the link is not valid",
    "link_scheme": "the link scheme is not http or https",
}

MESSAGE_MAX = 2048
KEY_MAX = 4096
HINT_MAX = 512
_KEY_RE = re.compile(r"[A-Za-z0-9_]{1,64}")
_FIELD_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_POINTER_RE = re.compile(r"(?:|/(?:[A-Za-z0-9_-]{1,64}|\?))")

# Details allowed per code: (required, optional), in the order of docs/interface.md.
_DETAILS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "config_invalid": (("key",), ()),
    "credential_invalid": (("env",), ()),
    "unavailable": (("phase",), ()),
    "auth_required": (("http_status",), ()),
    "rate_limited": (("http_status",), ()),
    "upstream_error": (("http_status",), ()),
    "wrong_host_response": (("http_status",), ()),
    "host_rejected": (("http_status",), ("hint",)),
    "network_error": (("tls", "timeout"), ()),
}
_DETAIL_ORDER = ("key", "pointer", "env", "phase", "http_status", "hint", "tls", "timeout")


def error_envelope(
    code: str,
    message: str,
    *,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
    retryable: bool | None = None,
    retry_after_s: int | float | None = None,
    unknown_outcome: bool | None = None,
) -> dict[str, Any]:
    """The raw envelope with the keys in document order. Prefer ``build_error``."""
    return {
        "error": {
            "code": code,
            "message": message,
            "reason": reason,
            "details": details,
            "retryable": retryable,
            "retry_after_s": retry_after_s,
            "unknown_outcome": unknown_outcome,
        }
    }


@dataclass(frozen=True)
class ErrorResult:
    exit_code: int
    envelope: dict[str, Any]


def safe_key(name: str) -> str:
    """``details.key`` for a config key name: the name when it is plain, else ``?``."""
    return name if _KEY_RE.fullmatch(name) else "?"


def safe_pointer(field: str | None) -> str:
    """``details.pointer``: ``""`` for the document, ``/<field>`` for a plain field name, else
    ``/?`` (an empty, long or otherwise unusual name is never echoed)."""
    if field is None:
        return ""
    return f"/{field}" if _FIELD_RE.fullmatch(field) else "/?"


def _clean_line(text: Any, limit: int) -> bool:
    return isinstance(text, str) and 0 < len(text) <= limit and text.isprintable()


def _check_details(code: str, reason: str | None, given: dict[str, Any]) -> dict[str, Any]:
    required, optional = _DETAILS.get(code, ((), ()))
    allowed = set(required) | set(optional)
    if code == "refused":
        if reason == "invalid_payload":
            required = ("pointer",)
            allowed = {"pointer"}
        elif reason == "link_invalid":
            allowed = {"pointer"}
    if code == "unavailable":
        given = {**given, "phase": "input"}
    extra = set(given) - allowed
    if extra:
        raise ValueError(f"details not allowed for {code}: {sorted(extra)}")
    missing = [k for k in required if k not in given]
    if missing:
        raise ValueError(f"details required for {code}: {missing}")
    for name, value in given.items():
        if name == "key":
            if not isinstance(value, str):
                raise ValueError("key must be a string")
            if len(value) > KEY_MAX:
                given[name] = "?"
        elif name == "pointer":
            ok = isinstance(value, str) and _POINTER_RE.fullmatch(value)
            if not ok or (reason == "link_invalid" and value != "/link"):
                raise ValueError("pointer does not match the schema")
        elif name == "env":
            if not _clean_line(value, 256):
                raise ValueError("env must be a short printable string")
        elif name == "phase":
            if value != "input":
                raise ValueError("phase is always input")
        elif name == "http_status":
            if type(value) is not int or not 100 <= value <= 599:
                raise ValueError("http_status must be an integer from 100 to 599")
        elif name == "hint":
            if not _clean_line(value, HINT_MAX):
                raise ValueError("hint must be a short printable string")
        elif name in ("tls", "timeout") and type(value) is not bool:
            raise ValueError(f"{name} must be a boolean")
    return {name: given[name] for name in _DETAIL_ORDER if name in given}


def _flags(
    code: str, details: dict[str, Any], tag_sent: bool, after_writing: bool
) -> tuple[bool | None, bool | None]:
    """``(retryable, unknown_outcome)`` per the exit-12 table (docs/interface.md, Exit codes)."""
    if code in ("usage", "config_invalid", "refused"):
        return None, None
    if code == "internal":
        return False, after_writing
    if code in ("host_rejected", "auth_required", "credential_invalid"):
        return False, False
    if code in ("rate_limited", "unavailable"):
        return True, False
    if code == "network_error":
        return (not details["tls"]), False
    if code in ("outcome_unknown", "upstream_error"):
        return tag_sent, True
    # wrong_host_response: a 2xx answer means that the endpoint is not the notify API (possibly
    # delivered, retrying does not help); any other status was a refusal before delivery.
    return False, 200 <= details["http_status"] < 300


def build_error(
    code: str,
    *,
    reason: str | None = None,
    message: str | None = None,
    tag_sent: bool = False,
    after_writing: bool = False,
    retry_after_s: int | float | None = None,
    **details: Any,
) -> ErrorResult:
    """The exit code and the envelope of one error.

    ``details`` are the fields of ``details`` (``key``, ``pointer``, ``env``, ``http_status``,
    ``hint``, ``tls``, ``timeout``; ``phase`` is added for ``unavailable``). ``tag_sent`` says that
    the request carried a dedupe tag; ``after_writing`` that an internal failure happened after
    the gate reached ``writing``. ``message`` overrides the fixed message and must be one printable
    line (callers pass only fixed strings). Raises ``ValueError`` for anything that would not be a
    schema-valid envelope.
    """
    if not isinstance(code, str) or code not in EXIT_CODES:
        raise ValueError("unknown error code")
    if code == "refused":
        if reason not in REASON_MESSAGES:
            raise ValueError("refused needs a known reason")
        text = REASON_MESSAGES[reason]
    elif reason is not None:
        raise ValueError("reason is only for exit 20")
    else:
        text = MESSAGES[code]
    if message is not None:
        text = message
    if not _clean_line(text, MESSAGE_MAX):
        raise ValueError("message must be one printable line")
    if after_writing and code != "internal":
        raise ValueError("after_writing is only for internal")
    if code == "rate_limited":
        if (
            type(retry_after_s) not in (int, float)
            or not math.isfinite(retry_after_s)  # type: ignore[arg-type]
            or retry_after_s < 0  # type: ignore[operator]
        ):
            raise ValueError("rate_limited needs retry_after_s >= 0")
    elif retry_after_s is not None:
        raise ValueError("retry_after_s is only for rate_limited")
    checked = _check_details(code, reason, dict(details))
    retryable, unknown = _flags(code, checked, tag_sent, after_writing)
    envelope = error_envelope(
        code,
        text,
        reason=reason,
        details=checked or None,
        retryable=retryable,
        retry_after_s=retry_after_s,
        unknown_outcome=unknown,
    )
    return ErrorResult(EXIT_CODES[code], envelope)


# --- sink -----------------------------------------------------------------------------------


def _discard_pending(stream: Any) -> None:
    """Point the stream's descriptor at the null device after a failed write, so that the data
    still buffered cannot fail again (and change the exit code) at interpreter shutdown."""
    try:
        fd = stream.fileno()
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, fd)
        finally:
            os.close(devnull)
    except Exception:  # noqa: BLE001 - best effort, never changes the exit code
        pass


def write_text(stream: TextIO | None, text: str) -> None:
    """Write ``text`` as UTF-8 with errors replaced, never through the locale, and flush.

    A failure to write (``BrokenPipeError`` or any ``OSError``, a closed stream, a missing stream)
    never changes the exit code and is not retried.
    """
    if stream is None:
        return
    data = text.encode("utf-8", errors="replace")
    try:
        buffer = getattr(stream, "buffer", None)
        if buffer is not None:
            stream.flush()
            buffer.write(data)
            buffer.flush()
        else:
            stream.write(data.decode("utf-8"))
            stream.flush()
    except Exception:  # noqa: BLE001 - output failures are ignored (OSError, ValueError, ...)
        _discard_pending(stream)


def flush_streams() -> None:
    """The last flush attempt: stdout, then stderr, once each; failures are ignored."""
    for stream in (sys.stdout, sys.stderr):
        if stream is None:
            continue
        try:
            stream.flush()
        except Exception:  # noqa: BLE001 - never changes the exit code
            _discard_pending(stream)


def dumps(obj: Any) -> str:
    """The serialization of every JSON document the tool prints (interface.md, send)."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def emit_error(json_mode: bool, error: ErrorResult | dict[str, Any]) -> None:
    """The envelope on stdout with ``--json``, then one line on stderr: ``<code>: <message>``,
    or ``refused (<reason>): <message>`` for exit 20. Stdout is written and flushed first."""
    envelope = error.envelope if isinstance(error, ErrorResult) else error
    body = envelope["error"]
    if json_mode:
        write_text(sys.stdout, dumps(envelope) + "\n")
    label = f"refused ({body['reason']})" if body["code"] == "refused" else body["code"]
    write_text(sys.stderr, f"{label}: {body['message']}\n")


def fail(json_mode: bool, code: str, **kwargs: Any) -> int:
    """Build and print one error; return its exit code. See ``build_error`` for the arguments."""
    result = build_error(code, **kwargs)
    emit_error(json_mode, result)
    return result.exit_code


def emit_disabled(json_mode: bool) -> int:
    """The disabled outcome (not an error): ``{"outcome":"disabled"}`` on stdout with ``--json``,
    else one line on stderr; exit 22 either way."""
    if json_mode:
        write_text(sys.stdout, dumps({"outcome": "disabled"}) + "\n")
    else:
        write_text(sys.stderr, "disabled in config\n")
    return EXIT_DISABLED
