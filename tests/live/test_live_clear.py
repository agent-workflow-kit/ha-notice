"""Live ``clear`` (issue #38): a person checks that the notification disappears."""

from __future__ import annotations

from pathlib import Path

from tests.live.checklist import settles
from tests.live.support import (
    LiveConfig,
    ToolRun,
    banner,
    marker,
    out,
    pause,
    record,
    run_tool,
    see,
    send,
    write_config,
)


def _clear(config: Path, live: LiveConfig, key: str) -> ToolRun:
    return run_tool(config, ["clear", "--actor", "auto:live-test", f"--dedupe-key={key}"], live)


@settles("V21")
def test_clear_removes_the_notification(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """Send a tagged notification, give the person time to see it, then ``clear`` its key."""
    banner("clear by tag", ("V21",), run_id)
    config = write_config(workdir, live)
    key = f"ha-notice-live-clear-{run_id}"
    title = marker(run_id, "clear")
    shown = send(
        config, live, {"title": title, "message": "I should vanish"}, f"--dedupe-key={key}"
    )
    out(f"tool result: {shown.describe()}")
    assert shown.code == 0, shown.describe()
    out(f"LOOK AT THE PHONE NOW: a notification titled '{title}' is shown. Waiting for you.")
    pause(live)
    cleared = _clear(config, live, key)
    out(f"tool result: {cleared.describe()}")
    envelope = cleared.envelope
    assert cleared.code == 0 and envelope is not None, cleared.describe()
    assert envelope["outcome"] == "sent" and envelope["http_status"] == 200, cleared.describe()
    assert envelope["tag_set"] is True
    see(
        f"The notification titled '{title}' (text 'I should vanish') was shown first and is "
        "gone from the notification shade and the lock screen a moment after the clear.",
        "No new notification appeared for the clear itself.",
        "If it is still listed, the app version does not clear by tag from this command.",
    )
    record("platform and app version; whether the notification disappeared; how long it took")
