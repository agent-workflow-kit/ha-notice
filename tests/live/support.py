"""Helpers for the live suite: configuration from LIVE_HA_*, the tool run, raw HTTP, printing.

Everything here is test-harness code. The LIVE_HA_* variables are read only here (never by
``src/``), the token is only ever held in ``LiveConfig.token`` and in the child environment
under the variable named by ``LIVE_HA_TOKEN_ENV`` (never in argv, a file or any output), and the
two raw helpers that bypass the tool's own checks are guarded: ``raw_post_notify`` refuses
companion-app command words, and ``send_command_word`` needs the explicit opt-in
``LIVE_HA_ALLOW_COMMANDS=1``.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from ha_notice.payload import check_command_keyword

ROOT = Path(__file__).resolve().parent.parent.parent
TOKEN_ENV_RE = re.compile(r"HA_[A-Z0-9_]{1,60}")
DEFAULT_BLACKHOLE_URL = "https://192.0.2.1:8123"  # RFC 5737 TEST-NET-1: documentation only
RAW_TIMEOUT_S = 20
RAW_BODY_CAP = 1 << 20
REQUIRED = ("LIVE_HA_BASE_URL", "LIVE_HA_SERVICE", "LIVE_HA_TOKEN_ENV")


class CommandWordRefused(Exception):
    """``raw_post_notify`` was asked to send a companion-app command word."""


class CommandsNotAllowed(Exception):
    """``send_command_word`` was called without ``LIVE_HA_ALLOW_COMMANDS=1``."""


@dataclass(frozen=True)
class LiveConfig:
    base_url: str
    service: str
    token_env: str
    token: str = field(repr=False)
    ca_file: str | None = None
    allow_insecure_http: bool = False
    prefix_base_url: str | None = None
    other_service: str | None = None
    blackhole_url: str = DEFAULT_BLACKHOLE_URL
    timeout: str = "10s"
    pause: float = 5.0
    allow_commands: bool = False

    def __repr__(self) -> str:  # never show the token, the host or the service
        return "LiveConfig(<hidden>)"

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> tuple[LiveConfig | None, str]:
        """``(config, "")`` or ``(None, reason)``; the reason names variables, never values."""
        missing = [name for name in REQUIRED if not env.get(name)]
        if missing:
            return None, "not configured: set " + ", ".join(missing)
        token_env = env["LIVE_HA_TOKEN_ENV"]
        if not TOKEN_ENV_RE.fullmatch(token_env):
            return None, "LIVE_HA_TOKEN_ENV must name a variable matching HA_[A-Z0-9_]{1,60}"
        token = env.get(token_env, "").strip()
        if not token or not all("!" <= c <= "~" for c in token):
            return None, f"the variable named by LIVE_HA_TOKEN_ENV ({token_env}) holds no token"
        try:
            pause = float(env.get("LIVE_HA_PAUSE", "5"))
        except ValueError:
            return None, "LIVE_HA_PAUSE must be a number of seconds"
        if not 0 <= pause <= 60:
            return None, "LIVE_HA_PAUSE must be between 0 and 60 seconds"
        return (
            cls(
                base_url=env["LIVE_HA_BASE_URL"],
                service=env["LIVE_HA_SERVICE"],
                token_env=token_env,
                token=token,
                ca_file=env.get("LIVE_HA_CA_FILE") or None,
                allow_insecure_http=env.get("LIVE_HA_ALLOW_INSECURE_HTTP") == "1",
                prefix_base_url=env.get("LIVE_HA_PREFIX_BASE_URL") or None,
                other_service=env.get("LIVE_HA_OTHER_SERVICE") or None,
                blackhole_url=env.get("LIVE_HA_BLACKHOLE_URL") or DEFAULT_BLACKHOLE_URL,
                timeout=env.get("LIVE_HA_TIMEOUT") or "10s",
                pause=pause,
                allow_commands=env.get("LIVE_HA_ALLOW_COMMANDS") == "1",
            ),
            "",
        )


# --- printing --------------------------------------------------------------------------------


def new_run_id() -> str:
    return secrets.token_hex(3)


def marker(run_id: str, label: str = "") -> str:
    """The unique text every live notification carries so the person can find it."""
    return f"ha-notice live test {run_id}" + (f" {label}" if label else "")


def out(text: str = "") -> None:
    print(text, flush=True)


def banner(test: str, items: tuple[str, ...], run_id: str) -> None:
    out()
    out(f"=== LIVE {test}  [settles {', '.join(items)}]  run {run_id} ===")


def see(*lines: str) -> None:
    """Numbered instructions for the person: what the phone should show."""
    out("WHAT YOU SHOULD SEE ON THE PHONE:")
    for number, line in enumerate(lines, 1):
        out(f"  {number}. {line}")


def record(*lines: str) -> None:
    out("RECORD ON ISSUE #36:")
    for line in lines:
        out(f"  - {line}")


def pause(cfg: LiveConfig) -> None:
    time.sleep(cfg.pause)


# --- the tool --------------------------------------------------------------------------------


def write_config(
    directory: Path,
    cfg: LiveConfig,
    *,
    base_url: str | None = None,
    service: str | None = None,
    use_ca_file: bool = True,
    max_chars: int | None = None,
    timeout: str | None = None,
    name: str = "config.yaml",
) -> Path:
    """A config file with no token in it (the token stays in the environment)."""
    url = cfg.base_url if base_url is None else base_url
    lines = [
        f"base_url: {json.dumps(url)}",
        f"service: {json.dumps(cfg.service if service is None else service)}",
        f"token_env: {json.dumps(cfg.token_env)}",
        "log: false",
        f"timeout: {json.dumps(cfg.timeout if timeout is None else timeout)}",
    ]
    if url.startswith("http://"):
        if not cfg.allow_insecure_http:
            raise ValueError("an http:// URL needs LIVE_HA_ALLOW_INSECURE_HTTP=1")
        lines.append("allow_insecure_http: true")
    if use_ca_file and cfg.ca_file:
        lines.append(f"ca_file: {json.dumps(cfg.ca_file)}")
    if max_chars is not None:
        lines.append(f"max_chars: {max_chars}")
    path = directory / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@dataclass(frozen=True)
class ToolRun:
    code: int
    stdout: str
    stderr: str
    elapsed: float

    @property
    def envelope(self) -> dict[str, object] | None:
        """The one JSON object on stdout, or None."""
        try:
            value = json.loads(self.stdout)
        except ValueError:
            return None
        return value if isinstance(value, dict) else None

    def error(self) -> dict[str, object]:
        env = self.envelope or {}
        err = env.get("error")
        return err if isinstance(err, dict) else {}

    def describe(self) -> str:
        """A fixed-field summary: never the text of the output, never a header or the token."""
        env = self.envelope or {}
        if "error" in env:
            err = self.error()
            return (
                f"exit {self.code}, error code {err.get('code')!r}, reason {err.get('reason')!r}, "
                f"details {json.dumps(err.get('details'), sort_keys=True)}"
            )
        fields = ("outcome", "http_status", "truncated", "bytes", "tag_set", "ok", "probe")
        shown = ", ".join(f"{k} {env[k]!r}" for k in fields if k in env)
        return f"exit {self.code}, {shown or 'no JSON object on stdout'}"


def run_tool(
    config: Path,
    argv: list[str],
    cfg: LiveConfig,
    *,
    stdin: str = "",
    token: str | None = None,
    limit_s: float = 120,
) -> ToolRun:
    """Run ``python -m ha_notice`` as a real process.

    The environment is built from scratch: PATH, a fixed locale and the one token variable (the
    real token unless ``token`` overrides it; the unreachable-host test passes a dummy so the
    real token never goes to any other address). The text travels on stdin, never argv.
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        cfg.token_env: cfg.token if token is None else token,
    }
    sent = env[cfg.token_env]
    start = time.monotonic()
    done = subprocess.run(
        [sys.executable, "-m", "ha_notice", *argv, "--json", "--config", str(config)],
        input=stdin.encode("utf-8"),
        env=env,
        cwd=ROOT,
        capture_output=True,
        timeout=limit_s,
        check=False,
    )
    run = ToolRun(
        done.returncode,
        done.stdout.decode("utf-8", "replace"),
        done.stderr.decode("utf-8", "replace"),
        time.monotonic() - start,
    )
    assert sent not in run.stdout and sent not in run.stderr, "the tool printed the token"
    return run


def send(
    config: Path,
    cfg: LiveConfig,
    payload: Mapping[str, object],
    *extra: str,
    token: str | None = None,
) -> ToolRun:
    return run_tool(
        config,
        ["send", "--stdin-json", "--actor", "auto:live-test", *extra],
        cfg,
        stdin=json.dumps(payload),
        token=token,
    )


def validate(config: Path, cfg: LiveConfig, *flags: str, token: str | None = None) -> ToolRun:
    return run_tool(config, ["validate", *flags], cfg, token=token)


# --- raw HTTP (the harness's own client; never the tool's) ----------------------------------


@dataclass(frozen=True)
class RawReply:
    status: int
    content_type: str | None
    body: bytes

    def describe(self, token: str) -> str:
        text = self.body[:200].decode("utf-8", "replace").replace(token, "<token>")
        return f"HTTP {self.status}, content-type {self.content_type!r}, body {text!r}"


def raw_request(
    cfg: LiveConfig,
    method: str,
    path: str,
    *,
    body: object | None = None,
    base_url: str | None = None,
    token: str | None = None,
    use_ca_file: bool = True,
) -> RawReply:
    """One request with the harness's own ``http.client`` (no redirects, no proxy)."""
    parts = urlsplit(cfg.base_url if base_url is None else base_url)
    host = parts.hostname or ""
    prefix = parts.path.rstrip("/")
    headers = {"Authorization": f"Bearer {cfg.token if token is None else token}"}
    payload: bytes | None = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    conn: http.client.HTTPConnection
    if parts.scheme == "https":
        ctx = ssl.create_default_context(cafile=cfg.ca_file if use_ca_file else None)
        conn = http.client.HTTPSConnection(
            host, parts.port or 443, timeout=RAW_TIMEOUT_S, context=ctx
        )
    else:
        conn = http.client.HTTPConnection(host, parts.port or 80, timeout=RAW_TIMEOUT_S)
    try:
        conn.request(method, prefix + path, body=payload, headers=headers)
        resp = conn.getresponse()
        return RawReply(resp.status, resp.getheader("Content-Type"), resp.read(RAW_BODY_CAP))
    finally:
        conn.close()


def _post_notify_unchecked(cfg: LiveConfig, body: Mapping[str, object]) -> RawReply:
    return raw_request(cfg, "POST", f"/api/services/notify/{cfg.service}", body=body)


def raw_post_notify(cfg: LiveConfig, body: Mapping[str, object]) -> RawReply:
    """POST a notify body without the tool (for sizes the tool caps). Refuses command words."""
    message = body.get("message")
    if not isinstance(message, str) or check_command_keyword(message):
        raise CommandWordRefused("raw_post_notify does not send a command word or a non-string")
    return _post_notify_unchecked(cfg, body)


def send_command_word(cfg: LiveConfig, word: str, title: str) -> RawReply:
    """DANGEROUS: send ``word`` as the whole message, bypassing the tool's refusal.

    Only the V10 test calls this, only after the opt-in ``LIVE_HA_ALLOW_COMMANDS=1``; a phone
    may act on the word (clear notifications, speak, change the screen, report its location).
    """
    if not cfg.allow_commands:
        raise CommandsNotAllowed("set LIVE_HA_ALLOW_COMMANDS=1 to send command words")
    return _post_notify_unchecked(cfg, {"title": title, "message": word})


def position_text(length: int) -> str:
    """Filler whose position can be read off the phone: ``000000 000007 000014 ...``."""
    return "".join(f"{i * 7:06d} " for i in range(length // 7 + 1))[:length]


def scratch_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="ha-notice-live-"))
