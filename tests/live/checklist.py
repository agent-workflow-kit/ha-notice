"""The live-verification checklist items a live test can settle (issue #36, design.md).

Each id maps to a phrase that must appear in the "Live verification" section of
``docs/design.md``; ``tests/test_live_harness.py`` checks that, so a renamed or invented item
is caught. The ``V<n>`` ids are the ones design.md numbers; the others are the unnumbered items
of #36 and rows of the spike table that a live test regresses.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

import pytest

F = TypeVar("F", bound=Callable[..., object])

ITEMS: dict[str, str] = {
    "V7": "- V7: `GET /api/`",
    "V8": "- V8: the phone's display limit",
    "V9": "- V9: whether both `url` (iOS) and `clickAction` (Android)",
    "V10": "- V10: the command keywords",
    "V18": "(V18;",
    "V20": "- V20: the Android companion app",
    "V21": "- V21: `clear`",
    "wrong-token": "The 401 body for a wrong (not missing) token",
    "unreachable-host": "an unreachable host's timeout",
    "self-signed": "a self-signed certificate through `ca_file`",
    "path-prefix": "a base URL with a path prefix",
    "other-services": "whether other notify services (not companion apps) accept the same body",
    "spike-success": "| Success | 200 with a JSON list",
    "spike-tag": "| Tag | Replaces an earlier notification",
}


def settles(*item_ids: str) -> Callable[[F], F]:
    """Name the checklist item(s) a live test settles; an unknown id fails at import."""
    unknown = [i for i in item_ids if i not in ITEMS]
    if unknown or not item_ids:
        raise ValueError(f"unknown or missing checklist item: {unknown or item_ids}")

    def decorate(func: F) -> F:
        return pytest.mark.settles(*item_ids)(func)  # type: ignore[return-value]

    return decorate
