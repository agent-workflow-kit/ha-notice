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

TODO(#12): input reading limits and the hardened JSON parse (``details.pointer`` ``""`` for a
parse failure); it hands the parsed value to ``validate_notification``.
The sanitizer (issue #13, docs/interface.md, Sanitizer) runs inside ``validate_notification``, so
``Notification.title`` and ``Notification.message`` hold the sanitized text. TODO(#17): the title
and message cut, the prefix and the budget (rendering).
TODO(#14): the command-keyword check. TODO(#15): the link rule. TODO(#16): ``link_hosts``.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ha_notice.output import ErrorResult, build_error, safe_pointer

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


def validate_notification(obj: object) -> Notification:
    """Validate a parsed notification (a dict from JSON, or the dict of the flags that were given).

    Checked in a fixed order, so that the refusal does not depend on the order of the keys: a
    value that is not an object (pointer ``""``), then unknown fields (the smallest name), then the
    known fields in the order title, message, level, link (wrong type, over 100000 characters, a
    lone surrogate, level outside the vocabulary), and last a message that is absent or empty after
    sanitizing (``empty_message``).
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
        # TODO(#15): the link rule (length, characters, scheme, host, port).
        # TODO(#16): link_hosts.
        if type(obj["link"]) is not str:
            raise PayloadError("invalid_payload", "link")
        link = obj["link"]
    if message is None or is_empty_text(message):
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
