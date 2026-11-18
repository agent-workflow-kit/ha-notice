"""Slack for the wall-clock upper bounds in tests that use a real clock (issue #75)."""

from __future__ import annotations

# Seconds added to an upper bound on real elapsed time. It guards against a hang or a missed
# deadline (every regression it catches takes far longer, usually 10 s or more or forever), not
# against scheduling jitter: a loaded CI host can stall a test for several seconds, and a bound
# of "the product limit plus 3 s" then fails a correct build. Never use it to widen a lower bound,
# and never widen a bound whose point is to tell two sub-second behaviours apart.
LOAD_SLACK_S = 8.0
