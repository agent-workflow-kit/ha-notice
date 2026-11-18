"""Command-line entry point for ha-notice: parsing, step 1 checks, dispatch and error output.

Parsing rules (docs/interface.md, Global flags, Input and Output):

- Flags are exact: no abbreviations, on the main parser and on every subparser.
- ``--flag=value`` and ``--flag value`` are the same, but a separate value that starts with ``-``
  (other than a lone ``-``) is refused, whatever argparse would make of it: such a value must use
  the ``=`` form. ``--`` and single-dash tokens other than ``-h`` are refused: there are no
  positional arguments and no short options. ``-h`` and ``--help`` work before or after the
  subcommand. An empty ``--actor`` or ``--dedupe-key`` is refused; an empty ``--config`` or
  ``--file`` is passed through (later steps judge it).
- Global flags are accepted before and after the subcommand; a value flag given twice (also once
  on each side) is refused. Repeating a boolean flag is harmless. ``--verbose`` with ``--quiet``
  is refused.
- A usage error prints one fixed line on stderr and, when ``--json`` is in argv (looked for before
  anything is parsed), the error envelope on stdout. Messages never contain input.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ha_notice import __version__
from ha_notice.gateway import Gateway, RealGateway
from ha_notice.output import (
    EXIT_DISABLED,
    EXIT_FAILED,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_USAGE,
    dumps,
    emit_error,
    emitted_exit,
    fail,
    flush_streams,
    reset_emitted,
    write_text,
)
from ha_notice.send import run_send
from ha_notice.signals import SignalReceived, SignalState, install, signal_exit_code
from ha_notice.validate import run_validate

__all__ = ["dumps", "emit_error", "write_text"]  # re-exported (see output.py)

# interface.md, send: the whole string must match (re.fullmatch, never re.match or a `$`).
ACTOR_RE = re.compile(r"(?:human|auto):[A-Za-z0-9._@/-]{1,64}")
_LOGIN_BAD_CHARS = re.compile(r"[^A-Za-z0-9._@-]")
DEDUPE_KEY_MAX = 1024

# Long flags that take a value (used to refuse a separate value that starts with "-").
VALUE_FLAGS = frozenset(
    {
        "--config",
        "--actor",
        "--file",
        "--title",
        "--message",
        "--level",
        "--link",
        "--dedupe-key",
        "--decision-id",
    }
)


class UsageError(Exception):
    """Exit 2 ``usage``. ``message`` is a fixed string: it never contains input."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class _ParserExit(Exception):
    """``--help`` or ``--version`` finished (argparse's ``exit``, without ``SystemExit``)."""

    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


# --- parser ---------------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    """argparse with the tool's output rules: no SystemExit, no input in messages."""

    def error(self, message: str) -> Any:
        raise UsageError("invalid command line; see ha-notice --help")

    def exit(self, status: int = 0, message: str | None = None) -> Any:
        raise _ParserExit(status)

    def print_help(self, file: Any = None) -> None:
        write_text(sys.stdout if file is None else file, self.format_help())


class _Once(argparse.Action):
    """A value flag that may be given once (an empty value is accepted)."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            raise UsageError("a flag was given more than once")
        setattr(namespace, self.dest, values)


class _OnceNonEmpty(_Once):
    """Once, and not empty (--actor, --dedupe-key)."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        if values == "":
            raise UsageError("a flag value is empty")
        super().__call__(parser, namespace, values, option_string)


class _Version(argparse.Action):
    def __init__(self, option_strings: Sequence[str], dest: str, **kwargs: Any) -> None:
        super().__init__(
            option_strings, dest, nargs=0, default=argparse.SUPPRESS, help=kwargs["help"]
        )

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        write_text(sys.stdout, f"ha-notice {__version__}\n")
        parser.exit(0)


def _add_global_flags(parser: argparse.ArgumentParser, prefix: str) -> None:
    """The global flags. The main parser and each subparser use different dests (``prefix``), so
    that a flag on one side never overwrites the other and both can be compared."""
    parser.add_argument(
        "--json",
        dest=f"{prefix}_json",
        action="store_true",
        help="machine-readable output on stdout",
    )
    parser.add_argument(
        "--config",
        dest=f"{prefix}_config",
        action=_Once,
        metavar="PATH",
        help="config file instead of the default",
    )
    parser.add_argument(
        "--dry-run",
        dest=f"{prefix}_dry_run",
        action="store_true",
        help="send only: build and print, send nothing",
    )
    parser.add_argument(
        "--actor",
        dest=f"{prefix}_actor",
        action=_OnceNonEmpty,
        metavar="ACTOR",
        help="actor recorded in the log: (human|auto):NAME",
    )
    parser.add_argument(
        "--verbose", dest=f"{prefix}_verbose", action="store_true", help="one stderr line per phase"
    )
    parser.add_argument(
        "--quiet",
        dest=f"{prefix}_quiet",
        action="store_true",
        help="suppress stderr lines except errors and warnings",
    )
    parser.add_argument("--version", action=_Version, help="print the version")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="ha-notice",
        allow_abbrev=False,
        description="Send a notification through the Home Assistant REST notify service.",
    )
    _add_global_flags(parser, "m")
    commands = parser.add_subparsers(dest="command", metavar="<command>", parser_class=_Parser)

    send = commands.add_parser("send", allow_abbrev=False, help="send one notification")
    _add_global_flags(send, "s")
    send.add_argument("--stdin-json", action="store_true", help="read the notification from stdin")
    send.add_argument(
        "--file",
        action=_Once,
        metavar="PATH",
        help="read the notification from a file (- is stdin)",
    )
    send.add_argument("--title", action=_Once, metavar="TEXT", help="notification title")
    send.add_argument("--message", action=_Once, metavar="TEXT", help="notification message")
    send.add_argument("--level", action=_Once, metavar="LEVEL", help="info, warn, action or error")
    send.add_argument("--link", action=_Once, metavar="URL", help="http or https link")
    send.add_argument(
        "--dedupe-key",
        action=_OnceNonEmpty,
        metavar="KEY",
        help="replacement key (use the = form for a value starting with -)",
    )
    send.add_argument(
        "--decision-id", action="append", metavar="ID", help="accepted and ignored (repeatable)"
    )

    validate = commands.add_parser(
        "validate",
        allow_abbrev=False,
        help="check the config, credential and, optionally, the host",
    )
    _add_global_flags(validate, "s")
    validate.add_argument("--probe", action="store_true", help="call GET /api/ (sends nothing)")
    validate.add_argument("--test-message", action="store_true", help="send one test notification")
    return parser


@dataclass(frozen=True)
class SendArgs:
    stdin_json: bool
    file: str | None
    title: str | None
    message: str | None
    level: str | None
    link: str | None
    dedupe_key: str | None
    decision_ids: list[str]


@dataclass(frozen=True)
class ValidateArgs:
    probe: bool
    test_message: bool


class Progress:
    """How far a handler got. The send flow sets ``writing`` when the gate reaches ``writing``;
    after that, an internal failure is reported with ``unknown_outcome`` true (interface.md,
    Exit codes). ``send.deliver`` sets it from the verdict's gate state."""

    def __init__(self) -> None:
        self.writing = False


@dataclass(frozen=True)
class Invocation:
    """Everything a command handler gets: the parsed flags, the environment and the gateway."""

    command: str
    json: bool
    config: str | None
    dry_run: bool
    verbose: bool
    quiet: bool
    actor: str
    actor_source: str  # flag | tty | default
    env: Mapping[str, str]
    gateway: Gateway
    send: SendArgs | None = None
    validate: ValidateArgs | None = None
    progress: Progress = field(default_factory=Progress)
    signals: SignalState = field(default_factory=SignalState)


def resolve_actor(flag: str | None, gateway: Gateway) -> tuple[str, str]:
    """The actor and how it was obtained (interface.md, send)."""
    if flag is not None:
        return flag, "flag"
    if not gateway.isatty(0):
        return "auto:unknown", "default"
    login = gateway.login_name()
    user = _LOGIN_BAD_CHARS.sub("_", login)[:64] if login else ""
    return f"human:{user or 'unknown'}", "tty"


def wants_json(argv: Sequence[str]) -> bool:
    """``--json`` is looked for in argv before anything is parsed."""
    return any(tok == "--json" or tok.startswith("--json=") for tok in argv)


def _precheck(argv: Sequence[str]) -> None:
    for i, tok in enumerate(argv):
        if tok == "--":
            raise UsageError("unexpected --")
        if tok.startswith("-") and not tok.startswith("--") and tok not in ("-", "-h"):
            raise UsageError("single-dash options are not accepted")
        if tok in VALUE_FLAGS and i + 1 < len(argv):
            nxt = argv[i + 1]
            if nxt.startswith("-") and nxt != "-":
                raise UsageError("a value that starts with - needs the --flag=value form")


def _one(main_value: str | None, sub_value: str | None) -> str | None:
    if main_value is not None and sub_value is not None:
        raise UsageError("a flag was given more than once")
    return main_value if main_value is not None else sub_value


def _check_send(args: SendArgs, stdin_is_tty: Callable[[], bool]) -> None:
    """Step 1 flag combinations (interface.md, Input): exit 2 before the config is consulted."""
    text_flags = (args.title, args.message, args.level, args.link)
    has_json_source = args.stdin_json or args.file is not None
    if has_json_source and any(v is not None for v in text_flags):
        raise UsageError("a JSON source cannot be combined with text flags")
    if args.stdin_json and args.file is not None and args.file != "-":
        raise UsageError("--stdin-json cannot be combined with --file")
    if args.dedupe_key is not None:
        if len(args.dedupe_key) > DEDUPE_KEY_MAX:
            raise UsageError("--dedupe-key is too long")
        try:
            args.dedupe_key.encode("utf-8")
        except UnicodeEncodeError:
            raise UsageError("--dedupe-key is not valid UTF-8") from None
    if not has_json_source:
        if args.message is None and any(v is not None for v in text_flags):
            raise UsageError("text flags need --message")
        if args.message is None and stdin_is_tty():
            raise UsageError("no input: stdin is a terminal and no source was given")
    elif (args.stdin_json or args.file == "-") and stdin_is_tty():
        raise UsageError("stdin is a terminal")


def parse(
    argv: Sequence[str],
    env: Mapping[str, str],
    gateway: Gateway,
    signals: SignalState | None = None,
) -> Invocation:
    """Parse argv and run the step 1 checks. Raises ``UsageError`` or ``_ParserExit``."""
    _precheck(argv)
    ns = build_parser().parse_args(list(argv))
    if ns.command is None:
        raise UsageError("no command given")
    get = lambda name: getattr(ns, name, None)  # noqa: E731
    verbose = bool(get("m_verbose") or get("s_verbose"))
    quiet = bool(get("m_quiet") or get("s_quiet"))
    if verbose and quiet:
        raise UsageError("--verbose and --quiet cannot be combined")
    config = _one(get("m_config"), get("s_config"))
    actor_flag = _one(get("m_actor"), get("s_actor"))
    if actor_flag is not None and ACTOR_RE.fullmatch(actor_flag) is None:
        raise UsageError("--actor does not match (human|auto):NAME")

    tty: list[bool] = []

    def stdin_is_tty() -> bool:
        if not tty:
            tty.append(gateway.isatty(0))
        return tty[0]

    send: SendArgs | None = None
    validate: ValidateArgs | None = None
    if ns.command == "send":
        send = SendArgs(
            stdin_json=ns.stdin_json,
            file=ns.file,
            title=ns.title,
            message=ns.message,
            level=ns.level,
            link=ns.link,
            dedupe_key=ns.dedupe_key,
            decision_ids=list(ns.decision_id or []),
        )
        _check_send(send, stdin_is_tty)
    else:
        validate = ValidateArgs(probe=ns.probe, test_message=ns.test_message)
    actor, actor_source = resolve_actor(actor_flag, gateway)
    return Invocation(
        command=ns.command,
        json=bool(get("m_json") or get("s_json")),
        config=config,
        dry_run=bool(get("m_dry_run") or get("s_dry_run")),
        verbose=verbose,
        quiet=quiet,
        actor=actor,
        actor_source=actor_source,
        env=env,
        gateway=gateway,
        send=send,
        validate=validate,
        signals=SignalState() if signals is None else signals,
    )


# --- dispatch -------------------------------------------------------------------------------


def _send(inv: Invocation) -> int:
    return run_send(inv)


def _validate(inv: Invocation) -> int:
    return run_validate(inv)


HANDLERS: dict[str, Callable[[Invocation], int]] = {"send": _send, "validate": _validate}


# Exit codes a handler may return (docs/interface.md, Exit codes); 128+N is SignalReceived's.
HANDLER_EXIT_CODES = frozenset(
    {EXIT_OK, EXIT_INTERNAL, EXIT_USAGE, EXIT_FAILED, EXIT_REFUSED, EXIT_DISABLED}
)


def _flush_quietly() -> None:
    """The last flush. A KeyboardInterrupt here (a SIGINT that beat the handler) is ignored: the
    result was already reported, so the exit code stays."""
    try:
        flush_streams()
    except KeyboardInterrupt:
        pass


def _run(args: list[str], environment: Mapping[str, str], gw: Gateway) -> int:
    reset_emitted()  # a direct call must not see state leaked from an earlier run
    try:
        inv = parse(args, environment, gw)
    except _ParserExit as done:
        return done.status
    except UsageError as err:
        return fail(wants_json(args), "usage", message=err.message)
    except (Exception, SystemExit):  # noqa: BLE001 - e.g. gateway.isatty; nothing of it is printed
        return fail(wants_json(args), "internal")
    # Installed after parsing: a usage error touches no gateway method. A signal during the parse
    # has the OS default action (SIGINT: KeyboardInterrupt, mapped in ``main``). The handlers stay
    # (flag-only) for the rest of the process, never restored (``keep``): a late signal, also one
    # after the flush and before the interpreter exits, cannot kill the process after the result.
    with install(gw, inv.signals, keep=True):
        try:
            inv.signals.check()
            code = HANDLERS[inv.command](inv)
            if type(code) is not int or code not in HANDLER_EXIT_CODES:
                raise ValueError("a handler returned something that is not an exit code")
        except (Exception, SystemExit):  # noqa: BLE001 - the class and text are never printed
            # SignalReceived and KeyboardInterrupt are not caught here: main maps them to 128+N.
            done = emitted_exit()
            if done is None:  # a result already reported wins over a later signal
                inv.signals.check()  # otherwise a signal wins over whatever it interrupted
            if done is not None:  # one envelope per run: the handler already printed its own
                code = done
            else:
                code = fail(inv.json, "internal", after_writing=inv.progress.writing)
        _flush_quietly()
    return code


def main(
    argv: list[str] | None = None,
    env: Mapping[str, str] | None = None,
    gateway: Gateway | None = None,
) -> int:
    """Run the CLI and return the exit code. ``env`` and ``gateway`` default to the process
    environment and the real gateway; process tests pass their own (no test-only environment seam
    exists). Both are threaded to the command handlers through ``Invocation``.

    An unexpected exception (also from parsing) is exit 1 ``internal``: the envelope and the line
    carry the fixed message only, never the exception's class or text, so that nothing that was
    read (input, config, credential) can leak. If even printing that fails, the exit code is
    still 1 (the envelope on exit 1 is best effort). Both streams get one last flush attempt."""
    reset_emitted()
    try:
        args = sys.argv[1:] if argv is None else list(argv)
        environment = dict(os.environ) if env is None else env
        gw = RealGateway() if gateway is None else gateway
        code = _run(args, environment, gw)
    except SignalReceived as received:  # exit 128+N: no envelope, no log record
        code = received.code
    except KeyboardInterrupt:  # SIGINT before the handlers were installed
        code = signal_exit_code(2)  # 130, the shell's code for SIGINT
    except Exception:  # noqa: BLE001 - last resort
        code = EXIT_INTERNAL
    _flush_quietly()  # a late SIGINT (handlers gone) must not change the code
    return code
