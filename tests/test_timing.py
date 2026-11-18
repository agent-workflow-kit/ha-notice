"""The load slack must stay generous and below the hang the bounds guard against."""

from tests.timing import LOAD_SLACK_S


def test_the_load_slack_is_generous_but_shorter_than_a_ten_second_hang() -> None:
    assert 5.0 <= LOAD_SLACK_S < 10.0
