"""Slack for the wall-clock upper bounds in tests that use a real clock (issue #75)."""

from __future__ import annotations

# Seconds added to an upper bound on real elapsed time, as a hang guard: a loaded CI host can
# stall a test for several seconds, and a tight "limit plus 3 s" bound then fails a correct build.
# Rules: each `+ LOAD_SLACK_S` bound must stay below the hang it guards (for example the time a
# test's worker stays blocked), so the regression it targets still fails the test. The result is
# deliberately looser than the documented `timeout + 3` worst case (docs/interface.md): the +3
# contract is not asserted at wall-clock precision here. Never use the slack to widen a lower
# bound, or a bound whose point is to tell two sub-second behaviours apart; those keep tight
# bounds or deterministic checks (recorded poll or wait arguments, fake clocks).
LOAD_SLACK_S = 8.0
