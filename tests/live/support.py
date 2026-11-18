"""Helpers for the live suite: configuration from LIVE_HA_*, the tool run, raw HTTP, printing.

Everything here is test-harness code. The LIVE_HA_* variables are read only here (never by
``src/``), the token is only ever held in ``LiveConfig.token`` and in the child environment
under the variable named by ``LIVE_HA_TOKEN_ENV`` (never in argv, a file or any output), and the
raw senders that bypass the tool's own checks are guarded: ``raw_post_notify`` (the intended
sender) refuses companion-app command words, unknown body keys and unknown ``data`` keys,
``_raw_request`` refuses any POST to a notify service, and ``send_command_word`` needs the
explicit opt-in ``LIVE_HA_ALLOW_COMMANDS=1``. Errors from the raw client and from the tool run
are re-raised without the original frames, so ``pytest -l`` never shows the token.
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

import pytest

from ha_notice.config import DURATION_RE, duration_ok
from ha_notice.payload import check_command_keyword, sanitize_message, sanitize_title

ROOT = Path(__file__).resolve().parent.parent.parent
TOKEN_ENV_RE = re.compile(r"HA_[A-Z0-9_]{1,60}")
DEFAULT_BLACKHOLE_URL = "https://192.0.2.1:8123"  # RFC 5737 TEST-NET-1: documentation only
RAW_TIMEOUT_S = 20
RAW_BODY_CAP = 1 << 20
REQUIRED = ("LIVE_HA_BASE_URL", "LIVE_HA_SERVICE", "LIVE_HA_TOKEN_ENV")
NOTIFY_PREFIX = "/api/services/notify/"
BODY_KEYS = frozenset({"title", "message", "data"})
DATA_KEYS = frozenset({"tag", "url", "clickAction"})
_UNIT_SECONDS = {None: 1.0, "s": 1.0, "ms": 0.001, "m": 60.0}


class CommandWordRefused(Exception):
    """``raw_post_notify`` was asked to send a command word or a body key it does not allow."""


class NotifyPostRefused(CommandWordRefused):
    """``_raw_request`` was asked to POST to a notify service (use ``raw_post_notify``)."""


class RawRequestError(Exception):
    """A raw request failed; the message is the exception type only (no host, token or path)."""


class ToolTimeout(Exception):
    """The tool process did not end within the harness limit."""


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
    timeout_seconds: float = 10.0
    pause: float = 5.0
    countdown: float = 10.0
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
        pause, reason = _seconds_var(env, "LIVE_HA_PAUSE", "5")
        if pause is None:
            return None, reason
        countdown, reason = _seconds_var(env, "LIVE_HA_COUNTDOWN", "10")
        if countdown is None:
            return None, reason
        timeout = env.get("LIVE_HA_TIMEOUT") or "10s"
        timeout_seconds = parse_timeout(timeout)
        if timeout_seconds is None:
            return None, "LIVE_HA_TIMEOUT must be a duration of 1s to 120s such as 10s or 1.5s"
        base_url = env["LIVE_HA_BASE_URL"]
        prefix_base_url = env.get("LIVE_HA_PREFIX_BASE_URL") or None
        blackhole_url = env.get("LIVE_HA_BLACKHOLE_URL") or DEFAULT_BLACKHOLE_URL
        taken = {base_url.rstrip("/")}
        if prefix_base_url:
            taken.add(prefix_base_url.rstrip("/"))
        if blackhole_url.rstrip("/") in taken:
            return None, (
                "LIVE_HA_BLACKHOLE_URL must differ from LIVE_HA_BASE_URL and "
                "LIVE_HA_PREFIX_BASE_URL (it must be an address that does not answer)"
            )
        return (
            cls(
                base_url=base_url,
                service=env["LIVE_HA_SERVICE"],
                token_env=token_env,
                token=token,
                ca_file=env.get("LIVE_HA_CA_FILE") or None,
                allow_insecure_http=env.get("LIVE_HA_ALLOW_INSECURE_HTTP") == "1",
                prefix_base_url=prefix_base_url,
                other_service=env.get("LIVE_HA_OTHER_SERVICE") or None,
                blackhole_url=blackhole_url,
                timeout=timeout,
                timeout_seconds=timeout_seconds,
                pause=pause,
                countdown=countdown,
                allow_commands=env.get("LIVE_HA_ALLOW_COMMANDS") == "1",
            ),
            "",
        )


def any_live_variable(env: Mapping[str, str]) -> bool:
    """True when at least one ``LIVE_HA_*`` variable is set (even to an empty value)."""
    return any(name.startswith("LIVE_HA_") for name in env)


def parse_timeout(value: str) -> float | None:
    """Seconds of a ``timeout`` in the interface duration grammar (the tool's 1s to 120s range)."""
    if len(value) > 64 or not duration_ok("timeout", value):
        return None
    match = DURATION_RE.fullmatch(value)
    if match is None:
        return None
    return float(match.group(1)) * _UNIT_SECONDS[match.group(2)]


def _seconds_var(env: Mapping[str, str], name: str, default: str) -> tuple[float | None, str]:
    try:
        value = float(env.get(name, default))
    except ValueError:
        return None, f"{name} must be a number of seconds"
    if not 0 <= value <= 60:
        return None, f"{name} must be between 0 and 60 seconds"
    return value, ""


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


def countdown(cfg: LiveConfig) -> None:
    """Give the person time to read the banner and press Ctrl-C before anything is sent."""
    remaining = int(cfg.countdown)
    out(f"Ctrl-C aborts. The first word is sent in {cfg.countdown:g} s.")
    for left in range(remaining, 0, -1):
        out(f"  {left}...")
        time.sleep(1)
    time.sleep(cfg.countdown - remaining)


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

    def failed_check(self) -> tuple[str, str] | None:
        """``(name, message)`` of the failed check of a ``validate`` run (fixed text), or None."""
        checks = (self.envelope or {}).get("checks")
        for check in checks if isinstance(checks, list) else []:
            if isinstance(check, dict) and check.get("ok") is False:
                return str(check.get("name")), str(check.get("message"))
        return None

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
        failed = self.failed_check()
        if failed:
            shown += f", failed check {failed[0]!r}: {failed[1]!r}"
        return f"exit {self.code}, {shown or 'no JSON object on stdout'}"


def _spawn_inner(
    config: Path, argv: list[str], cfg: LiveConfig, stdin: str, token: str | None, limit_s: float
) -> subprocess.CompletedProcess[bytes]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        cfg.token_env: cfg.token if token is None else token,
    }
    return subprocess.run(
        [sys.executable, "-m", "ha_notice", *argv, "--json", "--config", str(config)],
        input=stdin.encode("utf-8"),
        env=env,
        cwd=ROOT,
        capture_output=True,
        timeout=limit_s,
        check=False,
    )


def _spawn(
    config: Path, argv: list[str], cfg: LiveConfig, stdin: str, token: str | None, limit_s: float
) -> subprocess.CompletedProcess[bytes]:
    """Run the child; any failure is re-raised from a frame that holds no child environment."""
    timed_out = False
    failure = ""
    try:
        return _spawn_inner(config, argv, cfg, stdin, token, limit_s)
    except subprocess.TimeoutExpired:
        timed_out = True
    except Exception as exc:
        failure = type(exc).__name__
    if timed_out:
        raise ToolTimeout(f"the tool did not end within {limit_s:g} s")
    raise RuntimeError(f"the tool could not be started: {failure}")


def _fail_if_token_printed(cfg: LiveConfig, token: str | None, run: ToolRun) -> None:
    sent = cfg.token if token is None else token
    if sent in run.stdout or sent in run.stderr:
        pytest.fail("the tool printed the token", pytrace=False)


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
    real token never goes to any other address). The text travels on stdin, never argv. No local
    of this function holds the token, so ``pytest -l`` cannot show it.
    """
    start = time.monotonic()
    done = _spawn(config, argv, cfg, stdin, token, limit_s)
    run = ToolRun(
        done.returncode,
        done.stdout.decode("utf-8", "replace"),
        done.stderr.decode("utf-8", "replace"),
        time.monotonic() - start,
    )
    _fail_if_token_printed(cfg, token, run)
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


def _exchange(
    cfg: LiveConfig,
    method: str,
    path: str,
    body: object | None,
    base_url: str | None,
    token: str | None,
    use_ca_file: bool,
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


def _http(
    cfg: LiveConfig,
    method: str,
    path: str,
    body: object | None,
    base_url: str | None,
    token: str | None,
    use_ca_file: bool,
) -> RawReply:
    """``_exchange`` with any error re-raised as a ``RawRequestError`` that names only its type.

    The raise is outside the ``except`` and ``_exchange`` (which builds the headers) is not in
    the new traceback, so ``pytest -l`` shows no header, host or service. ``token`` here is only
    ever the dummy token or None (the real token stays inside ``cfg``, whose repr is hidden).
    """
    failure = ""
    try:
        return _exchange(cfg, method, path, body, base_url, token, use_ca_file)
    except Exception as exc:
        failure = type(exc).__name__
    raise RawRequestError(failure) from None


def _raw_request(
    cfg: LiveConfig,
    method: str,
    path: str,
    *,
    body: object | None = None,
    base_url: str | None = None,
    token: str | None = None,
    use_ca_file: bool = True,
) -> RawReply:
    """Unguarded-by-word but never a notify POST: those go through ``raw_post_notify``."""
    if method.upper() != "GET" and "/services/notify" in path.lower():
        raise NotifyPostRefused("POST to a notify service goes through raw_post_notify")
    return _http(cfg, method, path, body, base_url, token, use_ca_file)


def raw_get(
    cfg: LiveConfig,
    path: str,
    *,
    base_url: str | None = None,
    token: str | None = None,
    use_ca_file: bool = True,
) -> RawReply:
    return _raw_request(cfg, "GET", path, base_url=base_url, token=token, use_ca_file=use_ca_file)


def _post_notify_unchecked(
    cfg: LiveConfig, body: Mapping[str, object], token: str | None = None
) -> RawReply:
    return _http(cfg, "POST", f"{NOTIFY_PREFIX}{cfg.service}", body, None, token, True)


def _is_command(text: object) -> bool:
    """True for a non-string and for a command word, raw or after the tool's sanitizing."""
    if not isinstance(text, str):
        return True
    return any(
        check_command_keyword(candidate)
        for candidate in (text, sanitize_message(text), sanitize_title(text))
    )


def raw_post_notify(
    cfg: LiveConfig, body: Mapping[str, object], *, token: str | None = None
) -> RawReply:
    """POST a notify body without the tool (for sizes the tool caps, link variants).

    Refuses command words (raw or sanitized, in the title too), any top-level key other than
    ``title``, ``message`` and ``data``, and any ``data`` key other than ``tag``, ``url`` and
    ``clickAction``. This is the intended raw sender.
    """
    if not set(body) <= BODY_KEYS or "message" not in body:
        raise CommandWordRefused("raw_post_notify allows only title, message and data")
    if _is_command(body["message"]) or ("title" in body and _is_command(body["title"])):
        raise CommandWordRefused("raw_post_notify does not send a command word or a non-string")
    data = body.get("data", {})
    if not isinstance(data, Mapping) or not set(data) <= DATA_KEYS:
        raise CommandWordRefused("raw_post_notify allows only tag, url and clickAction in data")
    if not all(isinstance(v, str) for v in data.values()):
        raise CommandWordRefused("raw_post_notify allows only string values in data")
    return _post_notify_unchecked(cfg, body, token)


def send_command_word(cfg: LiveConfig, word: str, title: str) -> RawReply:
    """DANGEROUS: send ``word`` as the whole message, bypassing the tool's refusal.

    Only the V10 test calls this, only after the opt-in ``LIVE_HA_ALLOW_COMMANDS=1``; a phone
    may act on the word (clear notifications, speak, change the screen, report its location).
    """
    if not cfg.allow_commands:
        raise CommandsNotAllowed("set LIVE_HA_ALLOW_COMMANDS=1 to send command words")
    return _post_notify_unchecked(cfg, {"title": title, "message": word})


def trust_location_state(path: str, *, directory: bool) -> str:
    """Whether a CA location is unset, missing, present but unusable, or present and loads."""
    if not path:
        return "unset"
    if not os.path.exists(path):
        return "missing"
    try:
        if directory:
            ssl.create_default_context(capath=path)
        else:
            ssl.create_default_context(cafile=path)
    except (ssl.SSLError, OSError):
        return "exists, does not load"
    return "exists, loads"


def position_text(length: int) -> str:
    """Filler whose position can be read off the phone: ``000000 000007 000014 ...``."""
    return "".join(f"{i * 7:06d} " for i in range(length // 7 + 1))[:length]


def scratch_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="ha-notice-live-"))
