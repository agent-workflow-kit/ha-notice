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
Signals (issue #26): the caller's ``remaining`` returns 0 on a signal (``SignalState.bound``); the
caller checks the flag before it maps ``InputTimeout`` (``send.run_send``).
The sanitizer (issue #13, docs/interface.md, Sanitizer) runs inside ``validate_notification``, so
``Notification.title`` and ``Notification.message`` hold the sanitized text. The title and message
cut, the prefix and the budget are in ``render.py`` (issue #17).
The command-keyword check (issue #14) runs last inside ``validate_notification``, on the sanitized
message. The link rule (issue #15) is in ``link.py`` and runs before the message checks, followed
by the ``link_hosts`` check (issue #16); the send flow passes ``Config.link_hosts``.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ha_notice.gateway import Gateway, SourceError
from ha_notice.link import link_host_allowed, link_reason
from ha_notice.output import ErrorResult, build_error, safe_pointer

INPUT_MAX = 1048576  # bytes read from one source (1 MiB)
# The interpreter's default int limit, kept here so PYTHONINTMAXSTRDIGITS cannot lift it.
INT_DIGITS_MAX = 4300
DEPTH_MAX = 100  # nesting of arrays and objects accepted by hardened_loads
TEXT_MAX = 100000  # characters of input for title and message
LEVELS = ("info", "warn", "action", "error")  # ordered: info < warn < action < error
DEFAULT_LEVEL = "info"
FIELDS = ("title", "message", "level", "link")  # the order in which known fields are checked


_NO_POINTER = frozenset({"empty_message", "command_keyword", "link_scheme"})


class PayloadError(Exception):
    """A refused notification (exit 20). ``reason`` is ``invalid_payload``, ``empty_message``,
    ``command_keyword``, ``link_invalid`` or ``link_scheme`` (only ``invalid_payload`` and the
    ``link_hosts`` form of ``link_invalid`` have details);
    ``field`` is the offending field name (``None`` for the document itself) and is only ever
    turned into a pointer through ``safe_pointer``. Neither is built from an input value except
    the field name, which is never printed raw."""

    def __init__(self, reason: str, field: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.field = field

    @property
    def pointer(self) -> str | None:
        """``details.pointer``; ``None`` for ``empty_message``, ``command_keyword``,
        ``link_scheme`` and a ``link_invalid`` without a field (a link rule failure; only the
        ``link_hosts`` refusal, which names the field ``link``, has the pointer ``/link``)."""
        if self.reason in _NO_POINTER or (self.reason == "link_invalid" and self.field is None):
            return None
        return safe_pointer(self.field)

    def to_error(self) -> ErrorResult:
        pointer = self.pointer
        if pointer is None:
            return build_error("refused", reason=self.reason)
        return build_error("refused", reason=self.reason, pointer=pointer)


# --- sanitizer (docs/interface.md, Sanitizer) ---------------------------------------------

# The listed Cf and default-ignorable characters of the table, a fixed list (never derived from
# the running Python's tables). Cc, Cs, Co and Cn are removed by category, as the table says; the
# tab and the line breaks are handled before the removal.
_LISTED = frozenset(
    {0x00AD, 0x061C, 0x115F, 0x1160, 0x200B, 0x200E, 0x200F, 0x2800, 0x3164, 0xFEFF, 0xFFA0}
    | set(range(0x180B, 0x1810))  # 180E is Cf; 180B to 180D and 180F are the Mongolian selectors
    | set(range(0x202A, 0x202F))
    | set(range(0x2060, 0x2070))
    | set(range(0xFFF9, 0xFFFC))
    | set(range(0xE0000, 0xE0080))
    | set(range(0xE0100, 0xE01F0))
)
_REMOVED_CATEGORIES = frozenset({"Cc", "Cs", "Co", "Cn"})
_LINE_BREAKS = re.compile("\r\n|[\r\u0085\u2028\u2029]")
_LF_RUNS = re.compile("\n{3,}")
_SPACE_RUNS = re.compile(" {2,}")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
# Mn, Mc and Me: a text of only these and whitespace is empty.
_MARKS = frozenset({"Mn", "Mc", "Me"})


def _is_removed(ch: str) -> bool:
    if ch == "\n":
        return False
    return ord(ch) in _LISTED or unicodedata.category(ch) in _REMOVED_CATEGORIES


def has_lone_surrogate(text: str) -> bool:
    """Step 1: a str from JSON, a flag or a file holds a surrogate only when it is lone (a valid
    pair is one astral character). The refusal itself is ``PayloadError("invalid_payload")``."""
    return _LONE_SURROGATE.search(text) is not None


def _sanitize(text: str, *, title: bool) -> str:
    # Step 2, before the removal: U+0085 is a Cc.
    text = _LINE_BREAKS.sub("\n", text).replace("\t", " ")
    # Step 3. Every character is judged alone, so the cost is linear in the length.
    text = "".join(ch for ch in text if not _is_removed(ch))
    # Step 4: the lines are split on LF only (not ``splitlines``).
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    text = _LF_RUNS.sub("\n\n", text).strip()
    if title:  # step 5
        text = _SPACE_RUNS.sub(" ", text.replace("\n", " ")).strip()
    return text


def sanitize_message(text: str) -> str:
    """Steps 2 to 4 for a message. The caller refuses a lone surrogate first (step 1)."""
    return _sanitize(text, title=False)


def sanitize_title(text: str) -> str:
    """Steps 2 to 5 for a title (one line). Also the rule that ``level_prefix`` entries must
    survive unchanged (docs/interface.md, Configuration)."""
    return _sanitize(text, title=True)


def is_empty_text(text: str) -> bool:
    """No character other than whitespace and Mn, Mc and Me (``text`` is already sanitized)."""
    return all(ch.isspace() or unicodedata.category(ch) in _MARKS for ch in text)


# --- command keywords (docs/interface.md, Command messages) ---------------------------------

# fullmatch on the folded value; the class is bounded and has no nesting, so it is linear.
_COMMAND_FAMILY = re.compile(r"(?:command|kiosk|update|clear|remove|request)_[a-z0-9_]*")


def check_command_keyword(message: str) -> bool:
    """True when the companion apps would take the sanitized ``message`` for a command: after
    NFKC, casefold and strip it equals ``tts`` or is one token of a listed family. Kept Cf
    characters (ZWJ, ZWNJ) are not removed by NFKC, so ``tts`` with one inside is not refused
    (the interface fixes this exact formula)."""
    folded = unicodedata.normalize("NFKC", message).casefold().strip()
    return folded == "tts" or _COMMAND_FAMILY.fullmatch(folded) is not None


@dataclass(frozen=True)
class Notification:
    """A notification whose fields passed the checks of this module. ``title`` and ``message`` are
    sanitized; ``title`` is ``None`` when absent or empty after sanitizing and ``link`` is
    ``None`` when absent; ``message`` is never empty (that is ``empty_message``)."""

    message: str
    level: str = DEFAULT_LEVEL
    title: str | None = None
    link: str | None = None


def _check_text(name: str, value: Any) -> str:
    # ``type`` and not ``isinstance``: a str subclass or a bool is a different value. The limit
    # counts the input, before sanitizing.
    if type(value) is not str or len(value) > TEXT_MAX or has_lone_surrogate(value):
        raise PayloadError("invalid_payload", name)
    return value


def validate_notification(obj: object, link_hosts: Sequence[str] | None = None) -> Notification:
    """Validate a parsed notification (a dict from JSON, or the dict of the flags that were given).

    Checked in a fixed order, so that the refusal does not depend on the order of the keys: a
    value that is not an object (pointer ``""``), then unknown fields (the smallest name), then the
    known fields in the order title, message, level, link (wrong type, over 100000 characters, a
    lone surrogate, level outside the vocabulary), and last a message that is absent or empty after
    sanitizing (``empty_message``) or a command message (``command_keyword``).
    ``null`` is a wrong type, never an absent field.

    ``link_hosts`` is the validated config list (``None`` = unset, no restriction). When set, the
    link's host must match it, else ``PayloadError("link_invalid", "link")`` (pointer ``/link``);
    an empty list allows no host. The send flow passes ``Config.link_hosts`` (``send.py``).
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
    if title is not None:
        title = sanitize_title(title)
        if is_empty_text(title):
            title = None
    if message is not None:
        message = sanitize_message(message)
    level = DEFAULT_LEVEL
    if "level" in obj:
        value = obj["level"]
        if type(value) is not str or value not in LEVELS:
            raise PayloadError("invalid_payload", "level")
        level = value
    link = None
    if "link" in obj:
        link = obj["link"]
        if type(link) is not str:
            raise PayloadError("invalid_payload", "link")
        reason = link_reason(link)
        if reason is not None:
            raise PayloadError(reason)  # no details (docs/interface.md, details by reason)
        if link_hosts is not None and not link_host_allowed(link, link_hosts):
            raise PayloadError("link_invalid", "link")  # the one link refusal with details
    if message is None or is_empty_text(message):
        raise PayloadError("empty_message")
    # Order: link failures, then empty_message, then command_keyword (docs/interface.md).
    if check_command_keyword(message):
        raise PayloadError("command_keyword")
    return Notification(message=message, level=level, title=title, link=link)


def notification_from_flags(
    *,
    title: str | None,
    message: str | None,
    level: str | None,
    link: str | None,
    link_hosts: Sequence[str] | None = None,
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
    return validate_notification(given, link_hosts)


# --- input reading and the hardened JSON parse (issue #12) ---------------------------------------


class InputTimeout(Exception):
    """The input did not arrive before the deadline (exit 12 ``unavailable``, phase ``input``)."""


def input_timeout_error() -> ErrorResult:
    """The envelope of ``InputTimeout``: not sent, retryable, outcome known."""
    return build_error("unavailable", phase="input")


def _refuse_constant(_name: str) -> object:
    raise ValueError("NaN and Infinity are not accepted")


def _parse_int(text: str) -> int:
    if len(text.lstrip("-")) > INT_DIGITS_MAX:  # digits only, as the interpreter counts
        raise ValueError("integer too long")
    return int(text)


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):  # 1e999
        raise ValueError("number out of range")
    return value


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out = dict(pairs)
    if len(out) != len(pairs):
        raise ValueError("duplicate key")
    return out


def _too_deep(text: str) -> bool:
    """Linear scan of the bracket nesting, outside strings, against ``DEPTH_MAX``. Done before the
    decode because the C scanner can overflow a small C stack long before ``RecursionError``."""
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > DEPTH_MAX:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def hardened_loads(text: str) -> object:
    """Parse JSON text, refusing duplicate keys, NaN and Infinity (also by overflow such as
    ``1e999``), integers of more than 4300 digits, and nesting deeper than 100 levels (checked by
    a linear pre-scan before the decode, so a small C stack cannot be overrun; a
    ``RecursionError`` is still caught). Every failure is a ``ValueError`` whose text is fixed (no
    input is echoed). Also used for the Home Assistant response body.
    """
    if _too_deep(text):
        raise ValueError("invalid JSON")
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


def parse_notification(data: bytes, link_hosts: Sequence[str] | None = None) -> Notification:
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
    return validate_notification(obj, link_hosts)


_FAILED = object()


def read_notification(
    gateway: Gateway,
    source: int | str,
    remaining: Callable[[], float],
    link_hosts: Sequence[str] | None = None,
) -> Notification:
    """Read one source (a descriptor such as 0, or a ``--file`` path) and return its notification.

    Raises ``InputTimeout`` when the deadline passes first (also with partial data),
    ``PayloadError`` for anything refused (more than ``INPUT_MAX`` bytes included) and the
    gateway's ``SourceError`` for a path that is missing, unreadable or not a regular file. An
    unreadable descriptor (closed, a directory, write-only) is empty input: ``invalid_payload``.
    """
    result = None
    try:
        result = gateway.read_source(source, INPUT_MAX, remaining)
    except SourceError:
        if isinstance(source, str):
            raise
    if result is None:  # an unreadable descriptor is empty input; raised outside the handler
        raise PayloadError("invalid_payload", None)
    if result.status == "timeout":
        raise InputTimeout
    if result.status == "too_large" or len(result.data) > INPUT_MAX:
        raise PayloadError("invalid_payload", None)
    return parse_notification(result.data, link_hosts)
