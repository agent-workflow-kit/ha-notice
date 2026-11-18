"""Input parsing, validation, sanitizer and command keywords.

This module holds, so far, the notification model and its field validation (issue #11): the
fields ``title``, ``message``, ``level`` and ``link``, their types, the level vocabulary, the
100000 character input limit of ``title`` and ``message`` and the unknown-field rule
(docs/interface.md, Notification). Stdin JSON, ``--file`` JSON and the text flags all go through
``validate_notification``, so the same notification gives the same ``Notification`` whichever way
it arrives.

A refusal is a ``PayloadError``; ``PayloadError.to_error`` builds the exit 20 envelope through
``output.build_error``. No refusal carries an input value: the pointer is ``/<field>`` for a plain
field name and ``/?`` otherwise (``output.safe_pointer``), and the reason is a fixed word.

Input reading (issue #12): ``read_notification`` reads the source through the gateway (at most
``INPUT_MAX`` bytes, in slices, against the deadline), decodes it as strict UTF-8 and parses it with
``hardened_loads``; ``parse_notification`` hands the parsed value to ``validate_notification``.
Every parse failure is ``invalid_payload`` with pointer ``""``. A stalled producer is
``InputTimeout`` (exit 12 ``unavailable``, see ``input_timeout_error``); a bad ``--file`` is the
gateway's ``SourceError`` (exit 2 ``usage``), which the caller maps.
TODO(#26): signals during input (exit 128+N); the caller's ``remaining`` returns 0 on a signal,
which today reads as a timeout.
TODO(#13): the sanitizer (also the lone surrogate rule and the whitespace-only message, which is
``empty_message`` after sanitizing) and the title cut.
TODO(#14): the command-keyword check. TODO(#15): the link rule. TODO(#16): ``link_hosts``.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from ha_notice.gateway import Gateway
from ha_notice.output import ErrorResult, build_error, safe_pointer

INPUT_MAX = 1048576  # bytes read from one source (1 MiB)
INT_DIGITS_MAX = 4300  # the interpreter's own default limit; kept here so an env setting cannot lift it
TEXT_MAX = 100000  # characters of input for title and message
LEVELS = ("info", "warn", "action", "error")  # ordered: info < warn < action < error
DEFAULT_LEVEL = "info"
FIELDS = ("title", "message", "level", "link")  # the order in which known fields are checked


class PayloadError(Exception):
    """A refused notification (exit 20). ``reason`` is ``invalid_payload`` or ``empty_message``;
    ``field`` is the offending field name (``None`` for the document itself) and is only ever
    turned into a pointer through ``safe_pointer``. Neither is built from an input value except
    the field name, which is never printed raw."""

    def __init__(self, reason: str, field: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.field = field

    @property
    def pointer(self) -> str | None:
        """``details.pointer``; ``None`` for ``empty_message`` (it has no pointer)."""
        return None if self.reason == "empty_message" else safe_pointer(self.field)

    def to_error(self) -> ErrorResult:
        if self.reason == "empty_message":
            return build_error("refused", reason="empty_message")
        return build_error("refused", reason=self.reason, pointer=self.pointer)


@dataclass(frozen=True)
class Notification:
    """A notification whose fields passed the checks of this module (not yet sanitized: the text
    is as it was received). ``title`` and ``link`` are ``None`` when absent; ``message`` is never
    empty (an absent or empty message is ``empty_message``)."""

    message: str
    level: str = DEFAULT_LEVEL
    title: str | None = None
    link: str | None = None


def _check_text(name: str, value: Any) -> str:
    # ``type`` and not ``isinstance``: a str subclass or a bool is a different value.
    if type(value) is not str or len(value) > TEXT_MAX:
        raise PayloadError("invalid_payload", name)
    return value


def validate_notification(obj: object) -> Notification:
    """Validate a parsed notification (a dict from JSON, or the dict of the flags that were given).

    Checked in a fixed order, so that the refusal does not depend on the order of the keys: a
    value that is not an object (pointer ``""``), then unknown fields (the smallest name), then the
    known fields in the order title, message, level, link (wrong type, over 100000 characters,
    level outside the vocabulary), and last an absent or empty message (``empty_message``).
    ``null`` is a wrong type, never an absent field.
    """
    if not isinstance(obj, Mapping):
        raise PayloadError("invalid_payload", None)
    unknown = [k for k in obj if k not in FIELDS]
    if unknown:
        # A non-string key cannot come from JSON; treat it as unusable rather than sorting it.
        names = [k for k in unknown if isinstance(k, str)]
        raise PayloadError("invalid_payload", min(names) if len(names) == len(unknown) else "?")
    title = _check_text("title", obj["title"]) if "title" in obj else None
    message = _check_text("message", obj["message"]) if "message" in obj else None
    level = DEFAULT_LEVEL
    if "level" in obj:
        value = obj["level"]
        if type(value) is not str or value not in LEVELS:
            raise PayloadError("invalid_payload", "level")
        level = value
    link = None
    if "link" in obj:
        # TODO(#15): the link rule (length, characters, scheme, host, port).
        # TODO(#16): link_hosts.
        if type(obj["link"]) is not str:
            raise PayloadError("invalid_payload", "link")
        link = obj["link"]
    if not message:
        # TODO(#13): also a message that is empty after sanitizing.
        raise PayloadError("empty_message")
    return Notification(message=message, level=level, title=title, link=link)


def notification_from_flags(
    *, title: str | None, message: str | None, level: str | None, link: str | None
) -> Notification:
    """The notification of the text flags, checked like the same JSON fields (same pointers). A
    flag that was not given is absent; a flag that was given empty is an empty string."""
    given = {
        name: value
        for name, value in (
            ("title", title),
            ("message", message),
            ("level", level),
            ("link", link),
        )
        if value is not None
    }
    return validate_notification(given)


# --- input reading and the hardened JSON parse (issue #12) ---------------------------------------


class InputTimeout(Exception):
    """The input did not arrive before the deadline (exit 12 ``unavailable``, phase ``input``)."""


def input_timeout_error() -> ErrorResult:
    """The envelope of ``InputTimeout``: not sent, retryable, outcome known."""
    return build_error("unavailable", phase="input")


def _refuse_constant(_name: str) -> object:
    raise ValueError("NaN and Infinity are not accepted")


def _parse_int(text: str) -> int:
    if len(text) > INT_DIGITS_MAX:
        raise ValueError("integer too long")
    return int(text)


def _parse_float(text: str) -> float:
    if len(text) > INT_DIGITS_MAX:
        raise ValueError("number too long")
    value = float(text)
    if not math.isfinite(value):  # 1e999
        raise ValueError("number out of range")
    return value


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out = dict(pairs)
    if len(out) != len(pairs):
        raise ValueError("duplicate key")
    return out


def hardened_loads(text: str) -> object:
    """Parse JSON text, refusing duplicate keys, NaN and Infinity (also by overflow such as
    ``1e999``), integers and numbers over 4300 characters and nesting the interpreter cannot
    recurse into. Every failure is a ``ValueError`` whose text is fixed (no input is echoed).
    Also used for the Home Assistant response body.
    """
    decoder = json.JSONDecoder(
        object_pairs_hook=_no_duplicates,
        parse_constant=_refuse_constant,
        parse_int=_parse_int,
        parse_float=_parse_float,
        strict=True,
    )
    failed = False
    try:
        return decoder.decode(text)
    except (ValueError, RecursionError, OverflowError):
        failed = True
    if failed:  # raised outside the handler: no context carries the original text
        raise ValueError("invalid JSON")
    raise AssertionError("unreachable")  # pragma: no cover


def parse_notification(data: bytes) -> Notification:
    """Decode and parse the bytes of one input and validate the notification.

    Strict UTF-8 (never the locale); a byte order mark is refused; any parse failure, a top level
    that is not an object included, is ``invalid_payload`` with pointer ``""``.
    """
    if data.startswith(b"\xef\xbb\xbf"):
        raise PayloadError("invalid_payload", None)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is None:
        raise PayloadError("invalid_payload", None)
    try:
        obj = hardened_loads(text)
    except ValueError:
        obj = _FAILED
    if obj is _FAILED:
        raise PayloadError("invalid_payload", None)
    return validate_notification(obj)


_FAILED = object()


def read_notification(
    gateway: Gateway, source: int | str, remaining: Callable[[], float]
) -> Notification:
    """Read one source (a descriptor such as 0, or a ``--file`` path) and return its notification.

    Raises ``InputTimeout`` when the deadline passes first (also with partial data),
    ``PayloadError`` for anything refused (more than ``INPUT_MAX`` bytes included) and the
    gateway's ``SourceError`` for a path that is missing, unreadable or not a regular file.
    """
    result = gateway.read_source(source, INPUT_MAX, remaining)
    if result.status == "timeout":
        raise InputTimeout
    if result.status == "too_large" or len(result.data) > INPUT_MAX:
        raise PayloadError("invalid_payload", None)
    return parse_notification(result.data)
