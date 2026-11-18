"""Only gateway.py may touch the outside world (issue #3).

The scan is static (AST). It covers every ``*.py`` under ``src/ha_notice`` and flags: forbidden
imports, dynamic imports, ``os`` calls that reach the process or the user database, and imports
of names the gateway does not export.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ha_notice import gateway as gateway_module

SRC = Path(__file__).resolve().parent.parent / "src" / "ha_notice"
# Module paths nobody but the gateway imports (a package name covers its submodules).
FORBIDDEN = (
    "http",
    "urllib",
    "time",
    "subprocess",
    "socket",
    "ssl",
    "pwd",
    "select",
    "fcntl",
)
# The gateway itself never uses these.
FORBIDDEN_EVERYWHERE = ("urllib", "subprocess")
# ``importlib.metadata`` (the packaged version lookup) is the only importlib use that is allowed.
ALLOWED_IMPORTLIB = "importlib.metadata"
FORBIDDEN_OS_ATTRS = ("getuid", "system", "popen")
GATEWAY_NAMES = set(gateway_module.__all__)


def _is_under(name: str, bad: str) -> bool:
    return name == bad or name.startswith(bad + ".")


def _imports(source: str, *, package: str = "ha_notice") -> set[str]:
    """Every dotted name a module imports, including ``from x import y`` as ``x.y``.

    A relative import is resolved against the top package (the scan only reads files there).
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package + (f".{node.module}" if node.module else "")
            elif node.module:
                base = node.module
            else:
                continue
            found.add(base)
            found.update(f"{base}.{a.name}" for a in node.names)
    return found


def _importlib_violations(names: set[str]) -> set[str]:
    return {
        n
        for n in names
        if _is_under(n, "importlib") and not _is_under(n, ALLOWED_IMPORTLIB) and n != "importlib"
    } | ({"importlib"} if "importlib" in names else set())


def _dynamic_violations(source: str) -> set[str]:
    """``__import__``, ``import_module`` and ``os.getuid`` / ``os.system`` / ``os.popen``."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name) and node.id in ("__import__", "import_module"):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            if node.attr in ("__import__", "import_module"):
                found.add(node.attr)
            if (
                node.attr in FORBIDDEN_OS_ATTRS
                and isinstance(node.value, ast.Name)
                and node.value.id == "os"
            ):
                found.add(f"os.{node.attr}")
        elif isinstance(node, ast.ImportFrom) and node.module == "os" and node.level == 0:
            found.update(f"os.{a.name}" for a in node.names if a.name in FORBIDDEN_OS_ATTRS)
    return found


def _private_gateway_names(names: set[str]) -> set[str]:
    """``from ha_notice.gateway import X`` where X is not a public gateway name."""
    prefix = "ha_notice.gateway."
    return {
        n
        for n in names
        if n.startswith(prefix)
        and "." not in n[len(prefix) :]
        and n[len(prefix) :] not in GATEWAY_NAMES
    }


def _violations(source: str, *, is_gateway: bool = False) -> set[str]:
    names = _imports(source)
    bad = FORBIDDEN_EVERYWHERE if is_gateway else FORBIDDEN
    found = {n for n in names for b in bad if _is_under(n, b)}
    if is_gateway:
        return found | {
            v for v in _dynamic_violations(source) if v in ("__import__", "os.system", "os.popen")
        }
    return (
        found
        | _importlib_violations(names)
        | _dynamic_violations(source)
        | _private_gateway_names(names)
    )


def test_scanner_flags_each_forbidden_import_shape() -> None:
    assert _violations("import time") == {"time"}
    assert _violations("import urllib.request") == {"urllib.request"}
    assert _violations("from http import client") == {"http", "http.client"}
    assert _violations("from http.client import HTTPConnection") >= {"http.client"}
    assert _violations("import subprocess") == {"subprocess"}
    assert _violations("import timeit, json") == set()
    assert _violations("from time import monotonic") >= {"time"}
    for module in ("socket", "ssl", "pwd", "select", "fcntl", "http"):
        assert _violations(f"import {module}") == {module}, module
    assert _violations("import http.server") >= {"http.server"}


def test_scanner_flags_dynamic_imports() -> None:
    assert _violations("__import__('socket')") == {"__import__"}
    assert _violations("import importlib") == {"importlib"}
    assert _violations("import importlib.util") >= {"importlib.util"}
    assert _violations("from importlib import import_module") >= {"importlib.import_module"}
    assert "import_module" in _violations("x = m.import_module('socket')")
    assert _violations("from importlib.metadata import version") == set()


def test_scanner_flags_os_escape_hatches() -> None:
    assert _violations("import os\nos.getuid()") == {"os.getuid"}
    assert _violations("import os\nos.system('x')") == {"os.system"}
    assert _violations("import os\nos.popen('x')") == {"os.popen"}
    assert _violations("from os import getuid") == {"os.getuid"}
    assert _violations("import os\nos.getcwd()") == set()


def test_scanner_flags_non_public_gateway_names() -> None:
    assert _violations("from ha_notice.gateway import Gateway, RealGateway") == set()
    assert _violations("from ha_notice.gateway import _RealConnection") == {
        "ha_notice.gateway._RealConnection"
    }
    assert _violations("from ha_notice.gateway import STATE_DIR_PARTS") == {
        "ha_notice.gateway.STATE_DIR_PARTS"
    }
    assert _violations("from .gateway import _plain_name") == {"ha_notice.gateway._plain_name"}
    assert _violations("from ha_notice import gateway") == set()


def test_scanner_gateway_rules_are_narrower_but_firm() -> None:
    assert _violations("import socket, ssl, time, os\nos.getuid()", is_gateway=True) == set()
    assert _violations("import subprocess", is_gateway=True) == {"subprocess"}
    assert _violations("import urllib.request", is_gateway=True) == {"urllib.request"}
    assert _violations("import os\nos.system('x')", is_gateway=True) == {"os.system"}
    assert _violations("__import__('x')", is_gateway=True) == {"__import__"}


def test_the_scan_walks_every_python_file_under_src() -> None:
    names = {p.name for p in SRC.rglob("*.py")}
    assert {"gateway.py", "cli.py", "__init__.py"} <= names


@pytest.mark.parametrize("path", sorted(SRC.rglob("*.py")), ids=lambda p: str(p.relative_to(SRC)))
def test_only_the_gateway_touches_the_outside_world(path: Path) -> None:
    violations = _violations(
        path.read_text(encoding="utf-8"),
        is_gateway=path.name == "gateway.py" and path.parent == SRC,
    )
    assert not violations, f"{path.name}: {sorted(violations)}"
