from __future__ import annotations

import pytest

from ha_notice.cli import main


def test_no_arguments_returns_usage_exit_code() -> None:
    assert main([]) == 2


def test_abbreviated_long_option_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--vers"])
    assert exc.value.code == 2
    assert "ha-notice " not in capsys.readouterr().out
