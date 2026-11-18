"""Shared fixtures: a self-signed certificate made once per session (issue #4) and the
golden-file harness wiring (tests/harness.py)."""

from __future__ import annotations

import shutil
import signal
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.fake_ha import make_self_signed_cert
from tests.harness import Golden

pytest_plugins = ["pytester"]  # tests/test_conftest.py runs inner pytest sessions


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--update-golden",
        action="store_true",
        default=False,
        help="rewrite golden files from the actual output (never in CI; off by default)",
    )


@pytest.fixture
def golden(request: pytest.FixtureRequest) -> Golden:
    """The golden-file checker; update mode only with --update-golden, refused when CI is set."""
    return Golden(update=bool(request.config.getoption("--update-golden")))


@pytest.fixture(scope="session")
def self_signed_cert(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Path, Path]]:
    """``(cert, key)`` valid for 127.0.0.1 and localhost; the cert is its own trust anchor."""
    directory = tmp_path_factory.mktemp("fake-ha-cert")
    try:
        yield make_self_signed_cert(directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture(scope="session")
def other_cert(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Path, Path]]:
    """A second certificate for another name only (never matches 127.0.0.1)."""
    directory = tmp_path_factory.mktemp("fake-ha-other")
    try:
        yield make_self_signed_cert(directory, sans=("DNS:elsewhere.invalid",), name="other")
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture(autouse=True)
def _keep_signal_handlers() -> Iterator[None]:
    """``cli.main`` leaves its flag-only handlers installed (the process is ending); in-process
    tests with the real gateway must not leave them in the pytest process."""
    saved = {n: signal.getsignal(n) for n in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for number, handler in saved.items():
            signal.signal(number, handler)
