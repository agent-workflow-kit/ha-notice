"""Shared fixtures: a self-signed certificate made once per session (issue #4)."""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.fake_ha import make_self_signed_cert


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
