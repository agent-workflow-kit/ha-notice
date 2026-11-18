"""The pytest wiring in tests/conftest.py: --update-golden and the `golden` fixture.

Each test runs an inner pytest session (pytester, in-process; pytester points HOME at its own
temporary directory) whose conftest re-exports the real one. The inner tests only look at the
fixture's mode; they never write a golden file.
"""

from __future__ import annotations

import pytest

INNER_CONFTEST = "from tests.conftest import golden, pytest_addoption  # noqa: F401\n"
INNER_TEST = """
def test_mode(golden):
    assert golden.update is {expected}
"""


def _run(pytester: pytest.Pytester, expected: bool, *args: str) -> pytest.RunResult:
    pytester.makeconftest(INNER_CONFTEST)
    pytester.makepyfile(INNER_TEST.format(expected=expected))
    return pytester.runpytest(*args)


def test_update_golden_is_off_by_default(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CI", raising=False)
    _run(pytester, False).assert_outcomes(passed=1)


def test_update_golden_flag_turns_update_mode_on(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CI", raising=False)
    _run(pytester, True, "--update-golden").assert_outcomes(passed=1)


@pytest.mark.parametrize("value", ["true", "1", "false", "0"])
def test_update_golden_is_refused_when_ci_is_set(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("CI", value)
    result = _run(pytester, True, "--update-golden")
    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(["*golden update mode is refused when CI is set*"])


def test_ci_set_without_the_flag_is_fine(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CI", "true")
    _run(pytester, False).assert_outcomes(passed=1)
