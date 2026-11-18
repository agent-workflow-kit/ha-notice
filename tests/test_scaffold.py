"""Scaffold checks: version golden, module map, dependency policy."""

from __future__ import annotations

import ast
import importlib
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import ha_notice
from ha_notice.cli import main

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
MODULES = ["gateway", "cli", "payload", "render", "config", "log", "hass"]


def test_version_is_the_packaged_version() -> None:
    assert ha_notice.__version__ == PYPROJECT["project"]["version"]


def test_version_output_golden(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr()
    assert out.out == f"ha-notice {PYPROJECT['project']['version']}\n"
    assert out.err == ""


def test_version_output_from_a_real_process() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "ha_notice", "--version"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout == f"ha-notice {PYPROJECT['project']['version']}\n"


def test_version_ignores_other_arguments_after_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version", "--bogus"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("ha-notice ")


@pytest.mark.parametrize("name", MODULES)
def test_module_map_module_imports(name: str) -> None:
    assert importlib.import_module(f"ha_notice.{name}")


def test_runtime_dependencies_are_only_pydantic_and_pyyaml() -> None:
    allowed = {"pydantic", "pyyaml"}
    for dep in PYPROJECT["project"]["dependencies"]:
        name = dep.split("[")[0]
        for sep in "<>=!~; ":
            name = name.split(sep)[0]
        assert name.lower() in allowed, dep


def test_source_never_imports_urllib_or_a_third_party_http_library() -> None:
    banned = {"urllib", "urllib3", "requests", "httpx", "aiohttp", "httplib2", "pycurl"}
    for path in (ROOT / "src" / "ha_notice").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                roots = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots = {node.module.split(".")[0]}
            else:
                continue
            assert not roots & banned, f"{path.name} imports {roots & banned}"


def test_live_marker_is_excluded_by_default() -> None:
    opts = PYPROJECT["tool"]["pytest"]["ini_options"]
    assert "not live" in opts["addopts"]
    assert any(m.startswith("live:") for m in opts["markers"])
