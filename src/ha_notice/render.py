"""Request body and the data allowlist (docs/interface.md, Rendering; issue #17).

Pure functions on a validated ``Notification`` and config values: no environment, no files, no
clock. ``render`` returns the body for the notify service and whether anything was cut;
``serialize`` is the one JSON form that is sent, hashed and measured.

The title is cut at 256 characters (255 plus an ellipsis), then the level prefix is joined on. The
message is cut to ``max_chars`` code points and 2000 UTF-8 bytes, marker included. ``data`` is
built only from ``url``, ``clickAction``, ``tag`` and ``group``, in that order; no caller text
other than the link and the (already hashed) tag reaches it. The command-keyword rule ran on the
full sanitized message in ``validate_notification`` and is not repeated here: a cut message ends
in the marker and so can never be a keyword.

``tag_from_dedupe_key`` derives the tag from the dedupe key and ``dedupe_key_sha256`` the log's
hash of it (both from one digest helper); ``render`` takes the finished tag.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ha_notice.payload import Notification

__all__ = [
    "MARKER",
    "Rendered",
    "dedupe_key_sha256",
    "message_sha256",
    "render",
    "serialize",
    "tag_from_dedupe_key",
]

TITLE_MAX = 256
MESSAGE_MAX_BYTES = 2000
MARKER = "…[truncated]"
ELLIPSIS = "…"

_DEDUPE_KEY_MAX = 1024
_TAG = re.compile(r"awkit-[0-9a-f]{24}")
_GROUP = re.compile(r"[A-Za-z0-9_-]{1,64}")
_SCHEME = re.compile(r"https?://", re.ASCII | re.IGNORECASE)
MAX_CHARS_RANGE = (100, 2000)


@dataclass(frozen=True)
class Rendered:
    """The request body (keys ``title``, ``message``, ``data``; ``title`` and ``data`` omitted
    when empty) and whether the title or the message was cut."""

    body: dict[str, Any]
    truncated: bool


def _cut_title(title: str) -> tuple[str, bool]:
    if len(title) <= TITLE_MAX:
        return title, False
    return title[: TITLE_MAX - 1] + ELLIPSIS, True


def _cut_message(message: str, max_chars: int) -> tuple[str, bool]:
    """Keep the longest prefix such that it, with trailing whitespace removed, plus the marker
    fits ``max_chars`` code points and 2000 UTF-8 bytes."""
    if len(message) <= max_chars and len(message.encode("utf-8")) <= MESSAGE_MAX_BYTES:
        return message, False
    char_budget = max_chars - len(MARKER)
    byte_budget = MESSAGE_MAX_BYTES - len(MARKER.encode("utf-8"))
    # A message of at most max_chars characters is cut only for bytes, so no slice longer than
    # char_budget characters is ever needed; also bound the scan by bytes (4 bytes per character
    # at most) so a 100000-character message is not walked.
    head = message[: min(char_budget, byte_budget)]
    kept = 0
    used = 0
    for ch in head:
        used += len(ch.encode("utf-8"))
        if used > byte_budget:
            break
        kept += 1
    return head[:kept].rstrip() + MARKER, True


def message_sha256(title: str | None, message: str) -> str:
    """First 16 hex characters of the SHA-256 of the UTF-8 bytes of the sanitized title (empty
    when absent), a LF and the sanitized message, before any cut, prefix or link."""
    raw = f"{title or ''}\n{message}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _key_digest(key: str) -> str:
    """Full SHA-256 hex digest of the key's UTF-8 bytes, with the one validation shared by
    ``tag_from_dedupe_key`` and ``dedupe_key_sha256``.

    The CLI has already refused an empty key, one over 1024 characters and one that is not valid
    UTF-8 (a lone surrogate, as ``surrogateescape`` argv decoding makes of a bad byte), so each
    of those is a ``ValueError`` here, with a fixed message that does not echo the key. ``str``
    methods are called unbound so a subclass cannot change what is measured or hashed."""
    if not isinstance(key, str):
        raise TypeError("dedupe key must be a str")
    size = str.__len__(key)
    if size == 0 or size > _DEDUPE_KEY_MAX:
        raise ValueError("dedupe key is empty or longer than 1024 characters")
    raw: bytes | None
    try:
        raw = str.encode(key, "utf-8")
    except UnicodeEncodeError:
        raw = None
    if raw is None:
        # Raised outside the handler: inside it, __context__ would keep the exception whose
        # ``object`` attribute is the key.
        raise ValueError("dedupe key is not valid UTF-8")
    return hashlib.sha256(raw).hexdigest()


def tag_from_dedupe_key(key: str) -> str:
    """``awkit-`` plus the first 24 lowercase hex characters of the SHA-256 of the key's UTF-8
    bytes (docs/interface.md, Rendering). The level is not part of it. The key is hashed as
    given (no normalization, no case folding) and never appears in the result. 96 bits make a
    collision between two different keys negligible; one would only make the later notification
    replace the earlier one, which is the accepted tag behaviour.

    An empty key, one over 1024 characters or a lone surrogate is a ``ValueError`` with a fixed
    message that does not echo the key; a non-``str`` is a ``TypeError``."""
    return "awkit-" + _key_digest(key)[:24]


def dedupe_key_sha256(key: str) -> str:
    """First 16 hex characters of the SHA-256 of the key's UTF-8 bytes: the log's
    ``dedupe_key_sha256`` (docs/interface.md, send). It is the first 16 characters of the tag's
    digest. Same errors as ``tag_from_dedupe_key``."""
    return _key_digest(key)[:16]


def _link(link: str) -> str:
    m = _SCHEME.match(link)
    if m is None:
        raise ValueError("link is not an http or https link (validate it first)")
    return link[: m.end()].lower() + link[m.end() :]


def render(
    notification: Notification,
    *,
    max_chars: int,
    default_group: str | None,
    level_prefix: Mapping[str, str],
    tag: str | None = None,
) -> Rendered:
    """Build the notify request body. ``tag`` is ``awkit-`` plus 24 hex characters (from
    ``tag_from_dedupe_key``, derived by the send flow); anything else is a ``ValueError``, as are a
    ``max_chars`` outside 100 to 2000, a ``default_group`` outside
    ``[A-Za-z0-9_-]{1,64}``, an unknown level and a link that is not http or https: those are
    checked upstream and are programming errors here."""
    if type(max_chars) is not int or not MAX_CHARS_RANGE[0] <= max_chars <= MAX_CHARS_RANGE[1]:
        raise ValueError("max_chars is not an integer from 100 to 2000")
    if notification.level not in level_prefix:
        raise ValueError("unknown level")
    if tag is not None and _TAG.fullmatch(tag) is None:
        raise ValueError("tag is not awkit- plus 24 lowercase hex characters")
    if default_group is not None and _GROUP.fullmatch(default_group) is None:
        raise ValueError("default_group is not 1 to 64 of [A-Za-z0-9_-]")

    title, title_cut = _cut_title(notification.title or "")
    prefix = level_prefix[notification.level]
    line = f"{prefix} {title}" if prefix and title else prefix or title
    message, message_cut = _cut_message(notification.message, max_chars)

    body: dict[str, Any] = {}
    if line:
        body["title"] = line
    body["message"] = message

    data: dict[str, str] = {}
    if notification.link is not None:
        url = _link(notification.link)
        data["url"] = url
        data["clickAction"] = url
    if tag is not None:
        data["tag"] = tag
    if default_group is not None:
        data["group"] = default_group
    if data:
        body["data"] = data
    return Rendered(body=body, truncated=title_cut or message_cut)


def serialize(body: Mapping[str, Any]) -> bytes:
    """The one JSON form of a document that is sent, hashed or measured (docs/interface.md,
    send): compact separators, keys in insertion order, no ASCII escaping, UTF-8."""
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
