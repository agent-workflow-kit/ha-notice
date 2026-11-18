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
TODO(#13): the sanitizer (also the lone surrogate rule and the whitespace-only message, which is
``empty_message`` after sanitizing) and the title cut.
TODO(#14): the command-keyword check. TODO(#15): the link rule. TODO(#16): ``link_hosts``.
"""

from __future__ import annotations

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
