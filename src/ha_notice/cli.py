"""Command-line entry point for ha-notice."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Mapping

from ha_notice import __version__
from ha_notice.gateway import Gateway, RealGateway


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ha-notice",
        allow_abbrev=False,
        description="Send a notification through the Home Assistant REST notify service.",
    )
    parser.add_argument("--version", action="version", version=f"ha-notice {__version__}")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_subparsers(dest="command", metavar="<command>")
    return parser


def main(
    argv: list[str] | None = None,
    env: Mapping[str, str] | None = None,
    gateway: Gateway | None = None,
) -> int:
    """Run the CLI. ``env`` and ``gateway`` default to the process environment and the real
    gateway; process tests pass their own (no test-only environment seam exists).

    TODO(#6): thread ``env`` and ``gateway`` into the command handlers; they are unused until
    the commands exist.
    """
    _env = dict(os.environ) if env is None else env
    _gateway = RealGateway() if gateway is None else gateway
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(sys.stderr)
        return 2
    return 0
