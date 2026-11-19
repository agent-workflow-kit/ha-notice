"""V10, DANGEROUS and opt-in: companion-app command words sent as whole messages.

The tool refuses these (exit 20 ``command_keyword``) before it sends. This test bypasses the
tool through ``send_command_word`` to see whether a phone acts on each family. It is skipped
unless ``LIVE_HA_ALLOW_COMMANDS=1`` is set AND it is selected explicitly with
``-m live_commands`` (the plain ``-m live`` run never sends a word, even with the opt-in set).
A phone may clear its notifications, speak, wake its screen or report its location.
"""

from __future__ import annotations

import pytest

from tests.live.checklist import settles
from tests.live.support import (
    LiveConfig,
    banner,
    countdown,
    marker,
    out,
    pause,
    raw_post_notify,
    record,
    see,
    send_command_word,
)

# One word per family, in the order of docs/interface.md (Command messages). Each family is
# sent as the whole message; the title names the word so the person can tell them apart. This is
# a SAMPLE, not an exhaustive list of what the companion apps accept; effects vary by app version
# and platform and are unverified here. The maintainer reviews the list. The kiosk_ family is
# left out until its companion-app documentation is confirmed; the tool still refuses it.
FAMILY_WORDS = (
    "tts",
    "clear_notification",
    "clear_badge",
    "remove_channel",
    "request_location_update",
    "update_complications",
    "update_widgets",
    "command_screen_on",
)


_EFFECTS = {
    "tts": "  (may speak the text aloud)",
    "request_location_update": "  (the phone may report its location to Home Assistant)",
    "command_screen_on": "  (may wake the screen)",
    "clear_notification": "  (may clear notifications)",
}


@pytest.mark.live_commands
@settles("V10")
def test_command_word_families(
    live: LiveConfig, run_id: str, request: pytest.FixtureRequest
) -> None:
    """Each family word as the whole message, then a prefixed control that must show as text."""
    banner("command word families (DANGEROUS)", ("V10",), run_id)
    if request.config.getoption("markexpr") != "live_commands":
        pytest.skip("opt-in only: select it explicitly with -m live_commands -s")
    if not live.allow_commands:
        pytest.skip("opt-in only: set LIVE_HA_ALLOW_COMMANDS=1 to send command words")
    out("!" * 78)
    out("!! SENDING COMPANION-APP COMMAND WORDS TO YOUR PHONE. IT MAY ACT ON THEM.")
    out("!! The words below are a sample; their effects vary by app version and platform and")
    out("!! are unverified here. Keep the phone in view. Words, one per notification, in order:")
    for number, word in enumerate(FAMILY_WORDS, 1):
        out(f"!!   {number}. {word}{_EFFECTS.get(word, '')}")
    out("!" * 78)
    countdown(live)
    see(
        "Per notification, titled 'V10 <n>/<N> <word>': does the phone ACT (a spoken or silent "
        "command, a cleared list, the screen waking, a location update) or does it SHOW the "
        "word as ordinary text? Note which, per word.",
        "The last notification, titled '... control', has the text "
        "'<run>: update_widgets' and must show as plain text.",
    )
    total = len(FAMILY_WORDS)
    for number, word in enumerate(FAMILY_WORDS, 1):
        title = marker(run_id, f"V10 {number}/{total} {word}")
        out(f"sending {number}/{total}: {word}")
        reply = send_command_word(live, word, title)
        out(f"  {reply.describe(live.token)}")
        assert reply.status == 200
        pause(live)
    control = marker(run_id, "V10 control")
    reply = raw_post_notify(live, {"title": control, "message": f"{run_id}: update_widgets"})
    out(f"control: {reply.describe(live.token)}")
    assert reply.status == 200
    record(
        "per word: acted or shown as text, per platform (a family that does nothing visible is "
        "still refused by the tool; the default stays)",
        "any word that is NOT a command on any platform (the refusal may be too broad)",
    )
