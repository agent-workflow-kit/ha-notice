"""Live sends that a person checks on the phone (issue #31). Each names the item it settles."""

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
    position_text,
    raw_post_notify,
    record,
    see,
    send,
    validate,
    write_config,
)


def assert_sent(run: ToolRun) -> dict[str, object]:
    out(f"tool result: {run.describe()}")
    envelope = run.envelope
    assert run.code == 0 and envelope is not None, run.describe()
    assert envelope["outcome"] == "sent" and envelope["http_status"] == 200, run.describe()
    return envelope


@settles("spike-success")
def test_plain_send(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """A plain notification through the tool, then the same body raw to record the 200 reply."""
    banner("plain send", ("spike-success",), run_id)
    config = write_config(workdir, live)
    title = marker(run_id, "plain")
    assert_sent(send(config, live, {"title": title, "message": "plain send through the tool"}))
    raw = raw_post_notify(live, {"title": marker(run_id, "plain raw"), "message": "raw twin"})
    out(f"raw notify reply: {raw.describe(live.token)}")
    assert raw.status == 200
    see(
        f"Two notifications. First titled '{title}', text 'plain send through the tool'.",
        f"Second titled '{marker(run_id, 'plain raw')}', text 'raw twin' (sent without the tool).",
    )
    record(
        "the raw reply line above: status, content type and body of a successful notify call "
        "(design assumes 200, JSON, a list such as [])"
    )


@settles("spike-success")
def test_validate_test_message(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """``validate --test-message``: one fixed-text notification that a person must see."""
    banner("validate --test-message", ("spike-success",), run_id)
    config = write_config(workdir, live)
    run = validate(config, live, "--test-message")
    out(f"tool result: exit {run.code}")
    assert run.code == 0, run.describe()
    see(
        "One notification titled 'ha-notice' with the text 'validate: test message' "
        "(fixed text; it carries no run id).",
        "The tool itself says that delivery is not observable; this look is the check.",
    )
    record("whether it arrived, and how long after the run")


@settles("spike-tag")
def test_tag_replacement(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """Two sends with one dedupe key: the second replaces the first on the phone."""
    banner("tag replacement", ("spike-tag",), run_id)
    config = write_config(workdir, live)
    key = f"ha-notice-live-{run_id}"
    title = marker(run_id, "tag")
    first = assert_sent(
        send(config, live, {"title": title, "message": "FIRST send"}, f"--dedupe-key={key}")
    )
    pause(live)
    second = assert_sent(
        send(config, live, {"title": title, "message": "SECOND send"}, f"--dedupe-key={key}")
    )
    assert first["tag_set"] is True and second["tag_set"] is True
    see(
        f"Exactly ONE notification titled '{title}'.",
        "Its text is 'SECOND send'; 'FIRST send' was replaced (it may have shown briefly).",
        "If two notifications are listed, replacement does not work through this path.",
    )
    record("one notification or two; whether the replacement was silent")


@settles("V9")
def test_link_tap(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """A link: the tool sends both ``url`` (iOS) and ``clickAction`` (Android)."""
    banner("link tap", ("V9",), run_id)
    config = write_config(workdir, live)
    link = f"https://example.org/ha-notice-live-{run_id}"
    title = marker(run_id, "link")
    assert_sent(send(config, live, {"title": title, "message": "tap me", "link": link}))
    see(
        f"One notification titled '{title}', text 'tap me'.",
        f"Tap it on each platform you have: the browser opens {link} (a page that does not "
        "exist is fine).",
        "Android: note whether the tap opens the link. iOS: note the same.",
    )
    record(
        "per platform: tap opened the link yes or no (decides whether both url and "
        "clickAction are needed)"
    )


@settles("V8")
def test_long_message_through_the_tool(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """A 100000-character input is cut to ``max_chars`` (1000 and 2000 here) by the tool."""
    banner("long message through the tool", ("V8",), run_id)
    text = marker(run_id, "tool-long") + " " + position_text(100000)
    for limit in (1000, 2000):
        config = write_config(workdir, live, max_chars=limit, name=f"config-{limit}.yaml")
        run = send(
            config,
            live,
            {"title": marker(run_id, f"tool max_chars {limit}"), "message": text[:100000]},
        )
        envelope = assert_sent(run)
        assert envelope["truncated"] is True
        pause(live)
    see(
        "Two notifications, 'tool max_chars 1000' and 'tool max_chars 2000'.",
        "Each text is numbers counting up (000000 000007 ...) and ends with '…[truncated]'.",
        "Expand each one (long press or pull down) and read the last number visible.",
    )
    record("for each: whether the whole text and the truncation marker are visible, or cut")


@settles("V8")
def test_long_message_raw_api(live: LiveConfig, run_id: str) -> None:
    """The API accepts 1000, 10000 and 100000 characters; what does the phone show?"""
    banner("long message, raw API (no tool cap)", ("V8",), run_id)
    for size in (1000, 10000, 100000):
        title = marker(run_id, f"raw {size}")
        body = {"title": title, "message": position_text(size)}
        raw = raw_post_notify(live, body)
        out(f"{size} characters: {raw.describe(live.token)}")
        assert raw.status == 200
        pause(live)
    see(
        "Three notifications, titles ending 'raw 1000', 'raw 10000' and 'raw 100000'.",
        "Each text counts up in steps of 7 (000000 000007 ...), so the last visible number "
        "tells how many characters the phone shows.",
        "A notification that is missing entirely also counts: note it.",
    )
    record(
        "per size: arrived yes or no, and the last number visible when expanded (the display "
        "limit that sets the max_chars and byte defaults)"
    )


@settles("V20")
def test_android_markup_look(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """One notification with a small HTML subset in the message (Android may render it)."""
    banner("Android markup look", ("V20",), run_id)
    config = write_config(workdir, live)
    message = '<b>x</b> <a href="https://example.org">y</a>'
    title = marker(run_id, "markup")
    assert_sent(send(config, live, {"title": title, "message": message}))
    see(
        f"One notification titled '{title}' with the text: {message}",
        "Android: is 'x' bold and 'y' a link (markup rendered), or do you see the tags "
        "literally (escaped)? iOS: the same question.",
        "If 'y' is a tappable link to example.org on a notification that names another site, "
        "that is the link_hosts bypass described in design.md.",
    )
    record("per platform: rendered or literal; whether the link is tappable")
