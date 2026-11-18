"""The link rule (issue #15, docs/interface.md, Notification: link rule).

``link_reason`` judges one ``link`` string and returns ``None`` when it is acceptable, else the
refusal reason (``link_invalid`` or ``link_scheme``). The link is never parsed by a URL parser: the
grammar is one anchored regex, a port and an IPv6 literal are read from its groups, and every class
is spelled out in ASCII (no ``(?i:...)``, which would fold ``U+212A`` and ``U+017F``). All of it is
linear in the length, which is capped at 1024 before any pattern runs.

The text is not modified: the scheme is lowercased where the link is rendered (TODO(#17)). The
``link_hosts`` host match is TODO(#16).
"""

from __future__ import annotations

import ipaddress
import re

LINK_MAX = 1024  # characters

# Step 1: printable ASCII only (U+0021 to U+007E). ``fullmatch`` has no end-of-line exception, so a
# trailing LF is not accepted the way ``$`` would accept it.
_PRINTABLE = re.compile(r"[\x21-\x7e]+")
# Step 2: a scheme token. Its lowercase form (ASCII, after step 1) must be ``http`` or ``https``.
_SCHEME_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_WEB_SCHEMES = frozenset({"http", "https"})
# Step 3. ``T`` and ``HOST`` are those of the interface.
_T = r"(?:[A-Za-z0-9\-._~:/?@!$&'()*+,;=]|%[0-9A-Fa-f]{2})"
_HOST = r"(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[(?P<ip>[0-9A-Fa-f:.]+)\])"
_LINK = re.compile(
    r"[Hh][Tt][Tt][Pp][Ss]?://" + _HOST + r"(?::(?P<port>[0-9]{1,5}))?"
    r"(?:[/?]" + _T + r"*)?(?:#" + _T + r"*)?"
)


def link_reason(link: str) -> str | None:
    """``None`` when ``link`` follows the link rule, else ``link_invalid`` or ``link_scheme``."""
    if not 1 <= len(link) <= LINK_MAX or _PRINTABLE.fullmatch(link) is None:
        return "link_invalid"
    token = _SCHEME_TOKEN.match(link)
    if token is not None and token.group()[:-1].lower() not in _WEB_SCHEMES:
        return "link_scheme"
    match = _LINK.fullmatch(link)
    if match is None:
        return "link_invalid"
    port = match.group("port")
    if port is not None and not 1 <= int(port) <= 65535:
        return "link_invalid"
    ip = match.group("ip")
    if ip is not None:
        try:
            ipaddress.IPv6Address(ip)
        except ValueError:
            return "link_invalid"
    return None
