from __future__ import annotations

from ha_notice.cli import main

# The --version golden lives in test_scaffold.py (it follows the packaged version, which the
# release job bumps, so a hard-coded string would break on every release).


def test_no_arguments_returns_usage_exit_code() -> None:
    assert main([]) == 2
