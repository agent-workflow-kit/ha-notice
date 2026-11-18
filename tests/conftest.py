"""Shared fixtures: a self-signed certificate made once per session (issue #4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fake_ha import make_self_signed_cert


@pytest.fixture(scope="session")
def self_signed_cert(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """``(cert, key)`` valid for 127.0.0.1 and localhost; the cert is its own trust anchor."""
    return make_self_signed_cert(tmp_path_factory.mktemp("fake-ha-cert"))


@pytest.fixture(scope="session")
def other_cert(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A second certificate for another name only (never matches 127.0.0.1)."""
    return make_self_signed_cert(
        tmp_path_factory.mktemp("fake-ha-other"), sans=("DNS:elsewhere.invalid",), name="other"
    )
