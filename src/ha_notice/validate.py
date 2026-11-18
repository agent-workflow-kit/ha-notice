"""The ``validate`` command (docs/interface.md, validate; Home Assistant edge, Probe).

``validate [--probe] [--test-message]`` runs checks in a fixed order and stops at the first one
that fails: ``config``, ``credential``, ``probe`` (only with ``--probe``) and ``test_message``
(only with ``--test-message``, issue #29). ``ok`` is true only when every printed check is ok; the
exit code is 0, or the exit code of the failing check (``config`` 2, every other check 12).

- A config that cannot be loaded is not a check: it is the ``config_invalid`` envelope (exit 2),
  as for ``send``. A missing ``base_url`` or ``service`` and an unusable ``ca_file`` are the
  ``config`` check, in that order, with the same ``Config`` methods ``send`` uses.
- ``validate`` never prompts and never reads stdin. Plain ``validate`` makes no call, ignores
  ``enabled`` except to report it, and neither logs nor touches the state directory.
- With ``enabled`` false, ``--probe`` and ``--test-message`` make no call: ``{"outcome":
  "disabled"}`` and exit 22 right after the config loaded, before any check (so also before an
  unset credential is noticed).
- The probe is ``GET /api/`` through the send machinery (``hass.probe_once`` in
  ``deadline.run_with_deadline`` over ``retry.run_attempts`` with ``op=Op.PROBE``). Its deadline
  starts when the probe check starts. A probe has no envelope and no ``unknown_outcome``: the code
  of the failure is named in the message of the ``probe`` check. A probe is not logged.
- ``--dry-run`` has no effect. Signals behave as in ``send`` (``signals.py``): a signal before the
  probe starts is exit 128+N with no output; during the probe it is decided like the deadline.
- No check message contains the token, a header, a URL, a host or any response text.

The ``test_message`` check is issue #29's: ``_test_message_check`` is the seam. Until it lands the
flag fails closed (exit 1) after the earlier checks, and sends nothing.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from ha_notice.config import Config, ConfigError, CredentialError, load, token_env_ok
from ha_notice.deadline import WritingGate, finish, run_with_deadline
from ha_notice.hass import RawResponse, TrustError, make_target, probe_once
from ha_notice.output import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_USAGE,
    INSECURE_HTTP_WARNING,
    dumps,
    emit_disabled,
    fail,
    flush_streams,
    record_emitted,
    write_text,
)
from ha_notice.response import ErrorSpec, Gate, Op, Success, classify_exception

if TYPE_CHECKING:
    from ha_notice.cli import Invocation

__all__ = ["Check", "run_validate"]

MIN_IO_S = 0.01  # a socket timeout of 0 would mean non-blocking
CONFIG_MESSAGES = {
    "base_url": "base_url is missing or invalid",
    "service": "service is missing or invalid",
    "ca_file": "ca_file is not a readable regular file of at most 4 MiB",
}


@dataclass(frozen=True)
class Check:
    """One printed check. ``exit_code`` is that of a failed check (0 when ok)."""

    name: str
    ok: bool
    message: str
    exit_code: int = EXIT_OK

    def as_json(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "message": self.message}


def _passed(name: str, message: str) -> Check:
    return Check(name, True, message)


def _failed(name: str, message: str, exit_code: int) -> Check:
    return Check(name, False, message, exit_code)


class _Run:
    """What the checks of one run share. The ``insecure_http`` warning is printed once per run,
    before the first request (the probe now, the test message in #29)."""

    def __init__(self, inv: Invocation, config: Config) -> None:
        self.inv = inv
        self.config = config
        self.warned = False

    def warn_insecure(self, deadline: float) -> None:
        base = self.config.base_url
        if self.warned or base is None or base.scheme != "http":
            return
        if deadline - self.inv.gateway.monotonic() > 0:  # a request will be made
            self.warned = True
            write_text(sys.stderr, INSECURE_HTTP_WARNING + "\n")


# --- the checks -----------------------------------------------------------------------------


def _config_check(run: _Run) -> Check:
    try:
        run.config.check_destination()
        run.config.check_ca_file(run.inv.gateway)
    except ConfigError as exc:
        run.inv.signals.check()
        message = CONFIG_MESSAGES.get(exc.key, "the configuration is not usable")
        return _failed("config", message, EXIT_USAGE)
    return _passed("config", "the configuration is usable")


def _credential_message(env: str) -> str:
    named = f" ({env})" if token_env_ok(env) else ""
    return f"credential_invalid: the token variable{named} is missing or malformed"


def _credential_check(run: _Run) -> Check:
    try:
        run.config.read_token(run.inv.env)
    except CredentialError as exc:
        run.inv.signals.check()
        return _failed("credential", _credential_message(exc.env), EXIT_FAILED)
    run.inv.signals.check()
    return _passed("credential", "the token is set and well formed")


def _probe_message(spec: ErrorSpec) -> str:
    """The code of a failed probe and the fixed hint that goes with it. Never a body, a header, a
    URL or exception text."""
    text = spec.code
    status = spec.details.get("http_status")
    if type(status) is int:
        text += f" (HTTP {status})"
    if spec.code == "wrong_host_response" and status in (404, 405):
        text += "; base_url or its path prefix is probably wrong"
    elif spec.code == "network_error":
        if spec.details.get("tls") is True:
            text += "; check ca_file"
        elif spec.details.get("timeout") is True:
            text += "; the host did not answer in time"
    return text


def _probe_failure(spec: ErrorSpec) -> Check:
    if spec.code == "internal":  # a bug, not a verdict about the host: exit 1 (cli prints it)
        raise RuntimeError("internal probe failure")
    return _failed("probe", _probe_message(spec), spec.exit_code)


def _probe_check(run: _Run) -> tuple[Check, Callable[[], int] | None]:
    """The probe. Returns the check and, when the worker may still run (the deadline or a stop
    decided), the ``finish`` step the caller must take after the output is flushed."""
    inv, config = run.inv, run.config
    gateway = inv.gateway
    started = gateway.monotonic()
    deadline = started + config.timeout
    left = max(deadline - started, MIN_IO_S)
    try:
        target = make_target(gateway, config, inv.env, io_timeout=left)
    except (CredentialError, TrustError) as exc:
        inv.signals.check()
        return _probe_failure(classify_exception(exc, Gate.IDLE, op=Op.PROBE)), None
    target = replace(target, connect_timeout=min(target.connect_timeout, left))

    def attempt(before_write: Callable[[], None]) -> RawResponse:
        return probe_once(gateway, target, before_write=before_write)

    gate = WritingGate()
    inv.signals.check()  # the last checkpoint: from here on a signal is the stop path
    run.warn_insecure(deadline)
    try:
        verdict = run_with_deadline(
            gateway,
            attempt,
            op=Op.PROBE,
            deadline=deadline,
            stop=inv.signals.stopped,
            gate=gate,
        )
    except Exception:
        try:
            gate.settle(probe=True)  # no worker that did start may go on after this
        except Exception:  # noqa: BLE001
            pass
        raise
    outcome = verdict.result
    if isinstance(outcome, Success):
        check = _passed("probe", "GET /api/ answered with a JSON object")
    else:
        check = _probe_failure(outcome)
    if verdict.worker_may_run:
        return check, lambda: finish(gateway, verdict, check.exit_code)
    return check, None


def _test_message_check(run: _Run) -> Check:
    """The ``test_message`` check (``--test-message``).

    TODO(#29): send the test message through the normal render and send path (level info, title
    ``ha-notice``, message ``validate: test message``, no dedupe key, no tag), log it like a send,
    use ``run.warn_insecure`` before its request, start its deadline here, and return the check
    (a failure carries exit 12 and says that delivery is not observable). Until then the flag
    fails closed: exit 1 ``internal``, nothing sent."""
    raise NotImplementedError("--test-message is not implemented")


# --- output ---------------------------------------------------------------------------------


def _report(inv: Invocation, config: Config, checks: list[Check], api_ok: bool | None) -> int:
    """Print the checks (stdout is written and flushed first), return the exit code."""
    failed = next((c for c in checks if not c.ok), None)
    code = EXIT_OK if failed is None else failed.exit_code
    if inv.json:
        document: dict[str, Any] = {"ok": failed is None, "enabled": config.enabled}
        if api_ok is not None:
            document["probe"] = {"api_ok": api_ok}
        document["checks"] = [c.as_json() for c in checks]
        write_text(sys.stdout, dumps(document) + "\n")
    record_emitted(code)
    if not inv.json:
        for check in checks:
            if check.ok and inv.quiet:  # --quiet keeps errors and warnings only
                continue
            state = "ok" if check.ok else "failed"
            write_text(sys.stderr, f"{check.name}: {state}: {check.message}\n")
    return code


def run_validate(inv: Invocation) -> int:
    args = inv.validate
    if args is None:
        raise ValueError("validate without validate arguments")
    signals = inv.signals
    signals.check()
    try:
        config = load(inv.gateway, inv.config)
    except ConfigError as exc:
        signals.check()
        return fail(inv.json, "config_invalid", key=exc.key)
    signals.check()
    if not config.enabled and (args.probe or args.test_message):
        return emit_disabled(inv.json)

    run = _Run(inv, config)
    checks: list[Check] = []
    api_ok: bool | None = None
    pending_finish: Callable[[], int] | None = None
    steps: list[Callable[[], Check]] = [lambda: _config_check(run), lambda: _credential_check(run)]
    for step in steps:
        checks.append(step())
        if not checks[-1].ok:
            break
    else:
        if args.probe:
            check, pending_finish = _probe_check(run)
            checks.append(check)
            api_ok = check.ok
        if all(c.ok for c in checks) and args.test_message:
            signals.check()
            checks.append(_test_message_check(run))
    code = _report(inv, config, checks, api_ok)
    if pending_finish is not None:
        flush_streams()
        return pending_finish()
    return code
