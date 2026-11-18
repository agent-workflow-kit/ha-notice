"""pytest wiring for the golden-file harness (see tests/harness.py)."""

from __future__ import annotations

import pytest

from tests.harness import Golden


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
