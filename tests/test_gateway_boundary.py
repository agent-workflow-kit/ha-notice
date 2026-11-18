"""Only gateway.py may touch HTTP, the clock or subprocesses (issue #3)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "ha_notice"
# Module paths nobody but the gateway imports.
FORBIDDEN = ("http.client", "urllib", "time", "subprocess")


def _imports(source: str) -> set[str]:
    """Every dotted name a module imports, including ``from x import y`` as ``x.y``."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{a.name}" for a in node.names)
    return found


def _violations(names: set[str]) -> set[str]:
    return {n for n in names for bad in FORBIDDEN if n == bad or n.startswith(bad + ".")}


def test_scanner_flags_each_forbidden_import_shape() -> None:
    assert _violations(_imports("import time")) == {"time"}
    assert _violations(_imports("import urllib.request")) == {"urllib.request"}
    assert _violations(_imports("from http import client")) == {"http.client"}
    assert _violations(_imports("from http.client import HTTPConnection")) >= {"http.client"}
    assert _violations(_imports("import subprocess")) == {"subprocess"}
    assert _violations(_imports("import timeit, http, json")) == set()
    assert _violations(_imports("from time import monotonic")) >= {"time"}


@pytest.mark.parametrize("path", sorted(SRC.glob("*.py")), ids=lambda p: p.name)
def test_only_the_gateway_imports_http_time_or_subprocess(path: Path) -> None:
    violations = _violations(_imports(path.read_text(encoding="utf-8")))
    if path.name == "gateway.py":
        # The gateway owns http.client and time; it never uses urllib or subprocess.
        assert not any(v.startswith(("urllib", "subprocess")) for v in violations)
        return
    assert not violations, f"{path.name} imports {sorted(violations)}"
