"""Scaffold checks: version golden, module map, dependency policy."""

from __future__ import annotations

import ast
import importlib
import importlib.metadata
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
    assert main(["--version"]) == 0
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
    assert main(["--version", "--bogus"]) == 0
    assert capsys.readouterr().out.startswith("ha-notice ")


@pytest.mark.parametrize("name", MODULES)
def test_module_map_module_imports(name: str) -> None:
    assert importlib.import_module(f"ha_notice.{name}")


def test_runtime_dependencies_are_only_pyyaml() -> None:
    allowed = {"pyyaml"}
    for dep in PYPROJECT["project"]["dependencies"]:
        name = dep.split("[")[0]
        for sep in "<>=!~; ":
            name = name.split(sep)[0]
        assert name.lower() in allowed, dep


def test_source_imports_only_stdlib_and_allowed_dependencies() -> None:
    allowed = {"ha_notice", "yaml"}
    for path in (ROOT / "src" / "ha_notice").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                roots = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots = {node.module.split(".")[0]}
            else:
                continue
            assert "urllib" not in roots, f"{path.name} imports urllib"
            unexpected = roots - allowed - set(sys.stdlib_module_names)
            assert not unexpected, f"{path.name} imports {unexpected}"


def test_version_falls_back_when_the_package_is_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    with monkeypatch.context() as patch:
        patch.setattr(importlib.metadata, "version", missing)
        try:
            importlib.reload(ha_notice)
            assert ha_notice.__version__ == "0.0.0+unknown"
        finally:
            patch.undo()
            importlib.reload(ha_notice)
    assert ha_notice.__version__ == PYPROJECT["project"]["version"]


def test_live_marker_is_excluded_by_default() -> None:
    opts = PYPROJECT["tool"]["pytest"]["ini_options"]
    assert "not live" in opts["addopts"]
    assert any(m.startswith("live:") for m in opts["markers"])
