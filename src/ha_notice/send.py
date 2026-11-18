"""The ``send`` command up to and including the dry run (docs/interface.md, send, steps 2 to 4).

Step 1 (flags) is ``cli.parse``. Here: load the config (exit 2 ``config_invalid``), the disabled
check (exit 22), for a real send only the destination checks (``base_url``, ``service``,
``ca_file``, before any input is read), then the input is read and validated (exit 2 ``usage`` for
a ``--file`` problem, 20, or 12 ``unavailable``), the tag is derived and the request body is
rendered. With ``--dry-run`` the body is printed and the exit code is 0: no destination, no token,
no network, no state directory, no log. The environment is never consulted here.

TODO(#27): everything after ``deliver`` is called (token, POST, result mapping, output, log).
TODO(#26): signals during input (exit 128+N); the deadline below is only the input deadline.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ha_notice.config import Config, ConfigError, load
from ha_notice.gateway import SourceError
from ha_notice.output import (
    EXIT_OK,
    ErrorResult,
    dumps,
    emit_disabled,
    emit_error,
    fail,
    record_emitted,
    write_text,
)
from ha_notice.payload import (
    InputTimeout,
    Notification,
    PayloadError,
    input_timeout_error,
    notification_from_flags,
    read_notification,
)
from ha_notice.render import Rendered, render, serialize, tag_from_dedupe_key

if TYPE_CHECKING:
    from ha_notice.cli import Invocation

__all__ = ["Plan", "deliver", "run_send"]

TOOL = "ha-notice"


@dataclass(frozen=True)
class Plan:
    """What step 4 hands to step 5: the rendered request and what the output and the log need."""

    notification: Notification
    rendered: Rendered
    body: bytes  # the request body in its one serialized form (``bytes`` is its length)
    tag_set: bool
    dedupe_key: str | None
    started: float  # gateway.monotonic() at the start of step 3


def deliver(inv: Invocation, config: Config, plan: Plan) -> int:
    """Steps 5 to 7: token, POST, result mapping, output and log. TODO(#27)."""
    return fail(inv.json, "internal", message="command not implemented")


def _refuse(json_mode: bool, error: ErrorResult) -> int:
    emit_error(json_mode, error)
    return error.exit_code


def _verbose(inv: Invocation, phase: str, started: float, now: float) -> None:
    if inv.verbose:
        write_text(sys.stderr, f"{phase}: {int((now - started) * 1000)} ms\n")


def run_send(inv: Invocation) -> int:
    args = inv.send
    if args is None:
        raise ValueError("send without send arguments")
    gateway = inv.gateway

    # Step 2: config, then the disabled check, then (real send only) the destination.
    try:
        config = load(gateway, inv.config)
    except ConfigError as exc:
        return fail(inv.json, "config_invalid", key=exc.key)
    if not config.enabled:
        return emit_disabled(inv.json)
    if not inv.dry_run:
        try:
            config.check_destination()
            config.check_ca_file(gateway)
        except ConfigError as exc:
            return fail(inv.json, "config_invalid", key=exc.key)

    # Step 3: input. The deadline starts here.
    started = gateway.monotonic()
    deadline = started + config.timeout

    def remaining() -> float:
        return max(0.0, deadline - gateway.monotonic())

    try:
        if args.message is None:
            # --stdin-json, --file, or the default (stdin is not a terminal; step 1 checked).
            path = args.file is not None and args.file != "-" and not args.stdin_json
            source: int | str = str(args.file) if path else 0
            notification = read_notification(gateway, source, remaining, config.link_hosts)
        else:
            notification = notification_from_flags(
                title=args.title,
                message=args.message,
                level=args.level,
                link=args.link,
                link_hosts=config.link_hosts,
            )
    except PayloadError as exc:
        return _refuse(inv.json, exc.to_error())
    except InputTimeout:
        return _refuse(inv.json, input_timeout_error())
    except SourceError:
        return fail(inv.json, "usage", message="the --file source cannot be read")
    after_input = gateway.monotonic()
    _verbose(inv, "input", started, after_input)

    # Step 4: render. The tag is derived only when a dedupe key was given.
    tag = None if args.dedupe_key is None else tag_from_dedupe_key(args.dedupe_key)
    rendered = render(
        notification,
        max_chars=config.max_chars,
        default_group=config.default_group,
        level_prefix=config.level_prefix,
        tag=tag,
    )
    body = serialize(rendered.body)
    plan = Plan(notification, rendered, body, tag is not None, args.dedupe_key, started)
    _verbose(inv, "render", after_input, gateway.monotonic())
    if not inv.dry_run:
        return deliver(inv, config, plan)
    return _print_dry_run(inv, plan)


def _print_dry_run(inv: Invocation, plan: Plan) -> int:
    duration_ms = int((inv.gateway.monotonic() - plan.started) * 1000)
    if inv.json:
        output: dict[str, Any] = {
            "outcome": "dry_run",
            "tool": TOOL,
            "level": plan.notification.level,
            "truncated": plan.rendered.truncated,
            "bytes": len(plan.body),
            "duration_ms": duration_ms,
            "http_status": None,
            "tag_set": plan.tag_set,
            "dedupe_key": plan.dedupe_key,
            "warnings": [],
            "rendered": plan.rendered.body,
        }
        write_text(sys.stdout, dumps(output) + "\n")
    elif not inv.quiet:
        # The one stderr line that carries input-derived text: it is the rendered request.
        write_text(sys.stderr, plan.body.decode("utf-8") + "\n")
    record_emitted(EXIT_OK)
    return EXIT_OK
