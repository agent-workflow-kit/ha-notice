"""Live-suite wiring: every test here is a ``live`` test, skipped unless LIVE_HA_* is set.

The ``live`` marker is added to every item under ``tests/live`` here (so a new test cannot forget
it); ``pyproject.toml`` excludes the marker by default. Tests also need ``-s`` because their
instructions for the person are printed.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.live.support import LiveConfig, new_run_id, scratch_dir

LIVE_DIR = Path(__file__).resolve().parent


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if LIVE_DIR in item.path.parents:
            item.add_marker(pytest.mark.live)


@pytest.fixture(scope="session")
def run_id() -> str:
    return new_run_id()


@pytest.fixture
def live(request: pytest.FixtureRequest) -> LiveConfig:
    """The maintainer's configuration, or a skip that says what to set."""
    cfg, reason = LiveConfig.from_env(os.environ)
    if cfg is None:
        pytest.skip(f"live suite {reason} (see docs/live-tests.md)")
    if request.config.getoption("capture") != "no":
        pytest.skip("run with -s: the instructions for the person are printed")
    return cfg


@pytest.fixture
def workdir() -> Iterator[Path]:
    path = scratch_dir()
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
