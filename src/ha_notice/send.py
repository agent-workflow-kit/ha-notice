"""The ``send`` command (docs/interface.md, send, steps 2 to 7).

Step 1 (flags) is ``cli.parse``. Here: load the config (exit 2 ``config_invalid``), the disabled
check (exit 22), for a real send only the destination checks (``base_url``, ``service``,
``ca_file``, before any input is read), then the input is read and validated (exit 2 ``usage`` for
a ``--file`` problem, 20, or 12 ``unavailable``), the tag is derived and the request body is
rendered. With ``--dry-run`` the body is printed and the exit code is 0: no destination, no token,
no network, no state directory, no log. The environment is never consulted before ``deliver``.

``deliver`` is steps 5 to 7: the token and trust (``hass.make_target``), the POST in the deadline
worker (``deadline.run_with_deadline`` over ``retry.run_attempts``), the result on stdout and
stderr (written and flushed), then the log step, then ``finish``. A refusal (20) or an input
timeout (12 ``unavailable``) of a real send is logged too (they reach step 3).

Signals (``signals.py``): a signal before the send starts is exit 128+N with no envelope and no
log record (a 128+N exit is never logged), noticed at the checkpoints below
(``inv.signals.check()``, the last one immediately before the worker starts) and, during input,
through ``remaining`` returning 0. During the send ``SignalState.stopped`` is the ``stop`` of
``run_with_deadline``: the gate decides, as at the deadline, and that result is printed and
logged like a deadline result. A result already reported wins over later signals.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from ha_notice.config import Config, ConfigError, CredentialError, load
from ha_notice.deadline import Verdict, WritingGate, finish, run_with_deadline
from ha_notice.gateway import SourceError
from ha_notice.hass import RawResponse, TrustError, make_target, send_once
from ha_notice.log import RunFacts, write_log_record
from ha_notice.output import (
    EXIT_OK,
    INSECURE_HTTP_WARNING,
    ErrorResult,
    dumps,
    emit_disabled,
    emit_error,
    emitted_exit,
    fail,
    flush_streams,
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
from ha_notice.render import (
    Rendered,
    dedupe_key_sha256,
    message_sha256,
    render,
    serialize,
    tag_from_dedupe_key,
)
from ha_notice.response import Gate, Op, Success, classify_exception
from ha_notice.state import StateWarner

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


INSECURE_HTTP = "insecure_http"  # the one value of ``warnings`` in 0.x
MIN_IO_S = 0.01  # a socket timeout of 0 would mean non-blocking


@dataclass(frozen=True)
class _Result:
    """What step 6 fixed: an error (``None``: sent, with ``http_status``) and how it came about."""

    error: ErrorResult | None
    http_status: int | None
    writing: bool  # the gate reached ``writing``
    fixed_at: float  # gateway.monotonic() when the result was fixed
    send_started: float
    verdict: Verdict | None  # None when no worker ran (a token or trust failure)


def _ms(since: float, now: float) -> int:
    return max(0, int((now - since) * 1000))


def _facts(
    inv: Invocation,
    plan: Plan | None,
    *,
    exit_code: int,
    unknown_outcome: bool,
    code: str | None,
    reason: str | None,
    duration_ms: int,
    http_status: int | None,
) -> RunFacts:
    """The facts of a logged run. ``plan`` is ``None`` for a refusal before rendering: then the
    request-derived fields are null."""
    return RunFacts(
        exit_code=exit_code,
        unknown_outcome=unknown_outcome,
        code=code,
        reason=reason,
        level=None if plan is None else plan.notification.level,
        bytes=None if plan is None else len(plan.body),
        truncated=None if plan is None else plan.rendered.truncated,
        duration_ms=duration_ms,
        http_status=http_status,
        message_sha256=None
        if plan is None
        else message_sha256(plan.notification.title, plan.notification.message),
        dedupe_key_sha256=None
        if plan is None or plan.dedupe_key is None
        else dedupe_key_sha256(plan.dedupe_key),
        tag_set=None if plan is None else plan.tag_set,
        actor=inv.actor,
        actor_source=inv.actor_source,
    )


def _log(inv: Invocation, config: Config, facts: RunFacts) -> None:
    """The log step (step 7), after the result was printed and flushed. Never for a dry run or
    with config ``log`` false; ``write_log_record`` never raises and prints the one fixed warning
    on any state problem. A run that the outcome rule does not log (exit 1 before the gate reached
    ``writing``) is skipped there."""
    if inv.dry_run or not config.log:
        return
    gateway = inv.gateway
    before = gateway.monotonic()
    write_log_record(gateway, facts, StateWarner())
    _verbose(inv, "log", before, gateway.monotonic())


def _log_early(
    inv: Invocation,
    config: Config,
    started: float,
    exit_code: int,
    code: str | None,
    reason: str | None,
) -> None:
    """Log a refusal (20) or an input timeout (12 ``unavailable``): they reach step 3, but no
    request was built, so only the exit, the code or reason, the time and the actor are known."""
    if inv.dry_run or not config.log:
        return
    duration_ms = _ms(started, inv.gateway.monotonic())
    facts = _facts(
        inv,
        None,
        exit_code=exit_code,
        unknown_outcome=False,
        code=code,
        reason=reason,
        duration_ms=duration_ms,
        http_status=None,
    )
    _log(inv, config, facts)


def _error_facts(inv: Invocation, plan: Plan, result: _Result, error: ErrorResult) -> RunFacts:
    body = error.envelope["error"]
    details = body["details"] or {}
    status = details.get("http_status")
    return _facts(
        inv,
        plan,
        exit_code=error.exit_code,
        unknown_outcome=bool(body["unknown_outcome"]),
        code=body["code"],
        reason=None,
        duration_ms=_ms(plan.started, result.fixed_at),
        http_status=status if type(status) is int else None,
    )


def _present(inv: Invocation, config: Config, plan: Plan, result: _Result) -> int:
    """Print the result (stdout is written and flushed first), then run the log step."""
    error = result.error
    if error is None:
        duration_ms = _ms(plan.started, result.fixed_at)
        warnings = [INSECURE_HTTP] if _is_http(config) else []
        if inv.json:
            output: dict[str, Any] = {
                "outcome": "sent",
                "tool": TOOL,
                "level": plan.notification.level,
                "truncated": plan.rendered.truncated,
                "bytes": len(plan.body),
                "duration_ms": duration_ms,
                "http_status": result.http_status,
                "tag_set": plan.tag_set,
                "dedupe_key": plan.dedupe_key,
                "warnings": warnings,
            }
            write_text(sys.stdout, dumps(output) + "\n")
        record_emitted(EXIT_OK)
        if not inv.json and not inv.quiet:
            write_text(sys.stderr, f"sent ({plan.notification.level}, {duration_ms} ms)\n")
        code = EXIT_OK
        facts = _facts(
            inv,
            plan,
            exit_code=EXIT_OK,
            unknown_outcome=False,
            code=None,
            reason=None,
            duration_ms=duration_ms,
            http_status=result.http_status,
        )
    else:
        emit_error(inv.json, error)
        code = error.exit_code
        facts = _error_facts(inv, plan, result, error)
    _verbose(inv, "send", result.send_started, result.fixed_at)
    _log(inv, config, facts)
    flush_streams()
    return code


def _is_http(config: Config) -> bool:
    base = config.base_url
    return base is not None and base.scheme == "http"


def _conclude(inv: Invocation, config: Config, plan: Plan, result: _Result) -> int:
    """Report ``result`` and end the run. A failure while reporting never prints a second
    envelope: what was printed already decides the code."""
    try:
        code = _present(inv, config, plan, result)
    except Exception:  # noqa: BLE001 - nothing of it is printed
        done = emitted_exit()
        code = (
            done if done is not None else fail(inv.json, "internal", after_writing=result.writing)
        )
    if result.verdict is None:
        return code
    # The process ends here when the worker may still run (a deadline or a stop); the streams
    # were flushed above and ``finish`` does not flush.
    flush_streams()
    return finish(inv.gateway, result.verdict, code)


def deliver(inv: Invocation, config: Config, plan: Plan) -> int:
    """Steps 5 to 7: token, POST, result mapping, output and log."""
    gateway = inv.gateway
    service = config.service
    if service is None:
        raise ValueError("service is not set")
    send_started = gateway.monotonic()
    deadline = plan.started + config.timeout
    left = max(deadline - send_started, MIN_IO_S)

    # Step 5: the token and the trust. Neither opens a socket. Both failures are classified by
    # ``response.py`` (credential_invalid, or network_error with details.tls) and reported
    # without a worker; any other exception is a bug (exit 1, not logged).
    try:
        target = make_target(gateway, config, inv.env, io_timeout=left)
    except (CredentialError, TrustError) as exc:
        inv.signals.check()
        spec = classify_exception(exc, Gate.IDLE, op=Op.SEND)
        error = spec.build(tag_sent=plan.tag_set)
        result = _Result(error, None, False, gateway.monotonic(), send_started, None)
        return _conclude(inv, config, plan, result)
    # connect_timeout never exceeds the time that remains (io_timeout was capped above).
    target = replace(target, connect_timeout=min(target.connect_timeout, left))

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        return send_once(gateway, target, service, plan.body, before_write=before_write)

    if _is_http(config):  # one line on every real request; --quiet does not suppress it
        write_text(sys.stderr, INSECURE_HTTP_WARNING + "\n")

    # Step 6. The last checkpoint is immediately before the worker starts; from here on a signal
    # is the stop path (the gate decides, as at the deadline).
    gate = WritingGate()
    inv.signals.check()
    try:
        verdict = run_with_deadline(
            gateway,
            attempt,
            op=Op.SEND,
            deadline=deadline,
            stop=inv.signals.stopped,
            gate=gate,
        )
    except Exception:
        # For example "can't start new thread": exit 1 ``internal error`` (cli prints it), with
        # unknown_outcome only if the gate reached writing. Close the gate so that no worker that
        # did start can write after this.
        inv.progress.writing = gate.state() is Gate.WRITING
        try:
            gate.settle()
        except Exception:  # noqa: BLE001
            pass
        raise
    fixed_at = gateway.monotonic()
    writing = verdict.gate is Gate.WRITING
    inv.progress.writing = writing
    outcome = verdict.result
    if isinstance(outcome, Success):
        result = _Result(None, outcome.http_status, writing, fixed_at, send_started, verdict)
    else:
        error = verdict.error(tag_sent=plan.tag_set)
        result = _Result(error, None, writing, fixed_at, send_started, verdict)
    return _conclude(inv, config, plan, result)


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
    signals = inv.signals
    signals.check()

    # Step 2: config, then the disabled check, then (real send only) the destination.
    try:
        config = load(gateway, inv.config)
    except ConfigError as exc:
        signals.check()
        return fail(inv.json, "config_invalid", key=exc.key)
    signals.check()
    if not config.enabled:
        return emit_disabled(inv.json)
    if not inv.dry_run:
        try:
            config.check_destination()
            config.check_ca_file(gateway)
        except ConfigError as exc:
            signals.check()
            return fail(inv.json, "config_invalid", key=exc.key)

    # Step 3: input. The deadline starts here.
    started = gateway.monotonic()
    deadline = started + config.timeout

    def input_left() -> float:
        return max(0.0, deadline - gateway.monotonic())

    # A signal makes it 0, so a blocked read ends; the checks below run before a timeout is mapped.
    remaining = signals.bound(input_left)

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
        signals.check()
        code = _refuse(inv.json, exc.to_error())
        _log_early(inv, config, started, code, None, exc.reason)
        return code
    except InputTimeout:
        signals.check()  # a signal reads as a timeout; it wins
        error = input_timeout_error()
        _refuse(inv.json, error)
        _log_early(inv, config, started, error.exit_code, "unavailable", None)
        return error.exit_code
    except SourceError:
        signals.check()
        return fail(inv.json, "usage", message="the --file source cannot be read")
    signals.check()
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
    signals.check()
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
