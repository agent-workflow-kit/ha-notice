"""The send flow against a real socket (issue #27): ``cli.main`` with the real gateway's network.

A local plain-HTTP server (``allow_insecure_http``) and a local HTTPS server with a self-signed
certificate (``ca_file``) from ``tests/fake_ha.py``. The gateway is the real one except for three
test seams: the home directory (a private directory), ``exit_process`` (raises instead of ending
the test process) and ``sleep`` (a retry wait is recorded and not performed; the short polls of
the log lock really wait). Deadlines are short and real. Every thread, server and subprocess a
test starts is torn down by that test.
"""

from __future__ import annotations

import fcntl
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ha_notice import __version__
from ha_notice.cli import main
from ha_notice.gateway import AddrInfo, RealGateway
from ha_notice.output import INSECURE_HTTP_WARNING
from ha_notice.render import serialize, tag_from_dedupe_key
from ha_notice.state import STATE_WARNING
from tests.fake_gateway import FakeExit
from tests.fake_ha import EDGE_ROWS, FakeHA, Reply
from tests.harness import schema_errors
from tests.timing import LOAD_SLACK_S

TOKEN = "HA_SECRET_tok_5a4b3c2d1e0f9876"
OTHER_TOKEN_ENV = "HA_OTHER"
SERVICE = "mobile_app_x"
BODY_FLAGS = ["--message=hi", "--dedupe-key=k"]


class RealIO(RealGateway):
    """The real gateway with a private home, an ``exit_process`` that raises and no long sleeps."""

    def __init__(self, home: Path) -> None:
        super().__init__()
        self.home = str(home)
        self.waits: list[float] = []
        self.release = threading.Event()  # releases a blocked name resolution
        self.block_resolve = False
        self.stdout_at_lock: list[str] = []
        self.capture: Any = None

    def home_dir(self) -> str:
        return self.home

    def sleep(self, seconds: float) -> None:
        if seconds >= 1:  # a retry wait: recorded, not performed
            self.waits.append(seconds)
            return
        time.sleep(seconds)

    def resolve(self, host: str, port: int) -> list[AddrInfo]:
        if self.block_resolve:
            self.release.wait(30)
        return super().resolve(host, port)

    def try_lock(self, fd: int) -> bool:
        if self.capture is not None:  # what was on stdout when the log step began to lock
            self.stdout_at_lock.append(self.capture.readouterr().out)
        return super().try_lock(fd)

    def exit_process(self, code: int) -> Any:
        raise FakeExit(code)


@pytest.fixture
def io(tmp_path: Path) -> Iterator[RealIO]:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    gateway = RealIO(home)
    try:
        yield gateway
    finally:
        gateway.release.set()


def state_dir(io: RealIO) -> Path:
    return Path(io.home) / ".local" / "state" / "ha-notice"


def records(io: RealIO) -> list[dict[str, Any]]:
    path = state_dir(io) / "log.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def config(tmp: Path, ha: FakeHA, extra: str = "", ca: Path | None = None) -> str:
    http = ha.scheme == "http"
    text = f"base_url: {ha.base_url}\nservice: {SERVICE}\ntimeout: 10s\n{extra}"
    if http:
        text += "allow_insecure_http: true\n"
    if ca is not None:
        text += f"ca_file: {ca}\n"
    path = tmp / f"c{abs(hash(text))}.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def run(
    capsys: pytest.CaptureFixture[str],
    io: RealIO,
    cfg: str,
    argv: list[str],
    env: dict[str, str] | None = None,
) -> tuple[int, str, str, bool]:
    exited = False
    try:
        code = main(["--config", cfg, *argv], {"HA_TOKEN": TOKEN} if env is None else env, io)
    except FakeExit as done:
        code, exited = done.code, True
    out = capsys.readouterr()
    return code, out.out, out.err, exited


def test_sent_over_plain_http_with_the_token_only_in_the_header(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    with FakeHA(token=TOKEN, services={SERVICE}) as ha:
        code, out, err, exited = run(
            capsys, io, config(tmp_path, ha), ["--json", "--verbose", "send", *BODY_FLAGS]
        )
        assert code == 0 and not exited
        [request] = ha.requests
        assert request.method == "POST" and request.path == f"/api/services/notify/{SERVICE}"
        assert request.header("Authorization") == f"Bearer {TOKEN}"
        expected = serialize({"message": "hi", "data": {"tag": tag_from_dedupe_key("k")}})
        assert request.body == expected
        body = json.loads(out)
        assert schema_errors("cli/send", body) == [] and body["warnings"] == ["insecure_http"]
        assert body["bytes"] == len(expected) and body["http_status"] == 200
        assert INSECURE_HTTP_WARNING in err.splitlines()
        log = (state_dir(io) / "log.jsonl").read_text(encoding="utf-8")
        for text in (out, err, log):
            assert TOKEN not in text
        [rec] = records(io)
        assert rec["outcome"] == "sent" and rec["version"] == __version__
        assert schema_errors("log", rec) == []
        assert (state_dir(io) / "log.jsonl").stat().st_mode & 0o777 == 0o600


def test_sent_over_tls_with_ca_file(
    tmp_path: Path,
    io: RealIO,
    capsys: pytest.CaptureFixture[str],
    self_signed_cert: tuple[Path, Path],
) -> None:
    cert, key = self_signed_cert
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key) as ha:
        cfg = config(tmp_path, ha, ca=cert)
        code, out, err, _ = run(capsys, io, cfg, ["--json", "send", "--message=hi"])
        assert code == 0 and json.loads(out)["warnings"] == [] and err == ""
        assert len(ha.requests) == 1 and ha.handshake_failures == []


def test_a_certificate_that_does_not_verify_is_network_error_tls(
    tmp_path: Path,
    io: RealIO,
    capsys: pytest.CaptureFixture[str],
    self_signed_cert: tuple[Path, Path],
    other_cert: tuple[Path, Path],
) -> None:
    cert, key = self_signed_cert
    with FakeHA(token=TOKEN, certfile=cert, keyfile=key) as ha:
        cfg = config(tmp_path, ha, ca=other_cert[0])  # trusts a different certificate
        code, out, _, _ = run(capsys, io, cfg, ["--json", "send", "--message=hi"])
        body = json.loads(out)["error"]
        assert code == 12 and body["code"] == "network_error" and body["details"]["tls"] is True
        assert body["retryable"] is False and ha.requests == []


EXPECTED = {
    "200_list": (0, None),
    "200_list_with_content": (0, None),
    "200_object": (12, "wrong_host_response"),
    "200_not_json": (12, "wrong_host_response"),
    "200_empty": (12, "wrong_host_response"),
    "201": (12, "wrong_host_response"),
    "204": (12, "wrong_host_response"),
    "301": (12, "wrong_host_response"),
    "302": (12, "wrong_host_response"),
    "307": (12, "wrong_host_response"),
    "400": (12, "host_rejected"),
    "401": (12, "auth_required"),
    "403": (12, "auth_required"),
    "404": (12, "wrong_host_response"),
    "405": (12, "wrong_host_response"),
    "429": (12, "rate_limited"),
    "500": (12, "upstream_error"),
    "502": (12, "upstream_error"),
    "503": (12, "upstream_error"),
    "504": (12, "upstream_error"),
    "418": (12, "wrong_host_response"),
}


@pytest.mark.parametrize("name", list(EDGE_ROWS))
def test_every_edge_row_through_the_cli(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    exit_code, code = EXPECTED[name]
    reply = EDGE_ROWS[name]
    with FakeHA(script=[reply] * 3) as ha:
        got, out, _, _ = run(capsys, io, config(tmp_path, ha), ["--json", "send", "--message=hi"])
        assert got == exit_code
        if code is not None:
            assert json.loads(out)["error"]["code"] == code
        assert len(ha.requests) == (3 if name == "429" else 1)
        assert io.waits == ([2, 4] if name == "429" else [])
        assert len(records(io)) == 1 and schema_errors("log", records(io)[0]) == []


@pytest.mark.parametrize(
    "value", ["nan", "-5", "1e999", "Wed, 21 Oct 2015 07:28:00 GMT", "5", "45", "0", "²"]
)
def test_retry_after_is_ignored(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    reply = Reply(status=429, headers=(("Retry-After", value),))
    with FakeHA(script=[reply] * 3) as ha:
        code, out, _, _ = run(capsys, io, config(tmp_path, ha), ["--json", "send", "--message=a"])
        assert code == 12 and io.waits == [2, 4] and len(ha.requests) == 3
        assert json.loads(out)["error"]["retry_after_s"] == 4


def test_429_twice_then_connection_refused_counts_are_independent(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    with FakeHA(script=[Reply(status=429)] * 2) as ha:
        cfg = config(tmp_path, ha)
    # the server is closed: every further connection is refused; one connection retry, 2 s wait
    code, out, _, _ = run(capsys, io, cfg, ["--json", "send", "--message=a"])
    body = json.loads(out)["error"]
    assert code == 12 and body["code"] == "network_error" and body["details"]["timeout"] is False
    assert io.waits == [2] and len(ha.requests) == 0


def test_a_redirect_is_not_followed_and_a_proxy_is_not_used(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    with FakeHA() as other, FakeHA(script=[Reply(status=302, headers=(("Location", "x"),))]) as ha:
        script = Reply(
            status=302, headers=(("Location", other.base_url + "/api/services/notify/x"),)
        )
        ha.script = [script]
        env = {
            "HA_TOKEN": TOKEN,
            "HTTP_PROXY": other.base_url,
            "http_proxy": other.base_url,
            "HTTPS_PROXY": other.base_url,
            "ALL_PROXY": other.base_url,
            "SSL_CERT_FILE": "/nonexistent",
        }
        code, out, err, _ = run(
            capsys, io, config(tmp_path, ha), ["--json", "send", "--message=a"], env
        )
        assert code == 12 and json.loads(out)["error"]["code"] == "wrong_host_response"
        assert other.connections == 0 and other.requests == [] and len(ha.requests) == 1
        assert other.base_url not in out + err


def test_the_token_goes_to_no_other_host(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    for reply in (Reply(), Reply(status=401), Reply(status=500), Reply(raw=b"junk\r\n\r\n")):
        with FakeHA(script=[reply]) as ha, FakeHA() as other:
            env = {"HA_TOKEN": TOKEN, "HTTP_PROXY": other.base_url}
            code, out, err, _ = run(
                capsys,
                io,
                config(tmp_path, ha),
                ["--json", "--verbose", "send", "--message=a"],
                env,
            )
            assert code in (0, 12)
            assert other.connections == 0
            for request in ha.requests:
                assert [k for k, v in request.headers if TOKEN in v] == ["Authorization"]
                assert TOKEN not in request.path and TOKEN.encode() not in request.body
            log = (state_dir(io) / "log.jsonl").read_text(encoding="utf-8")
            assert TOKEN not in out + err + log


def test_a_stalled_host_ends_at_the_deadline_with_outcome_unknown(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    with FakeHA(script=[Reply(truncate_after=10, hang=True)]) as ha:
        cfg = config(tmp_path, ha).replace("timeout: 10s", "timeout: 1s")
        Path(cfg).write_text(Path(cfg).read_text().replace("timeout: 10s", "timeout: 1s"))
        started = time.monotonic()
        code, out, err, exited = run(capsys, io, cfg, ["--json", "send", "--message=a"])
        elapsed = time.monotonic() - started
        # The product bound is timeout + 3 s; LOAD_SLACK_S keeps a loaded host from failing a
        # correct build (a missed deadline hangs for 10 s or more).
        assert code == 12 and exited and elapsed < 1 + 3 + LOAD_SLACK_S
        body = json.loads(out)["error"]
        assert body["code"] == "outcome_unknown" and body["unknown_outcome"] is True
        [rec] = records(io)
        assert (
            rec["outcome"] == "outcome_unknown"
            and 1000 <= rec["duration_ms"] < (1 + 3 + LOAD_SLACK_S) * 1000
        )
        assert err.splitlines()[-1].startswith("outcome_unknown:")


def _one_second_config(tmp_path: Path, ha: FakeHA) -> str:
    cfg = config(tmp_path, ha)
    Path(cfg).write_text(Path(cfg).read_text().replace("timeout: 10s", "timeout: 1s"))
    return cfg


def test_a_byte_by_byte_response_ends_at_the_deadline_with_outcome_unknown(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    # Every read succeeds within the socket timeout, so only the send deadline can end it.
    with FakeHA(script=[Reply(trickle=0.2, body=b"[" + b" " * 200 + b"]")]) as ha:
        started = time.monotonic()
        cfg = _one_second_config(tmp_path, ha)
        code, out, _, exited = run(capsys, io, cfg, ["--json", "send", "--message=a"])
        assert code == 12 and exited and time.monotonic() - started < 1 + 3 + LOAD_SLACK_S
        assert json.loads(out)["error"]["code"] == "outcome_unknown"
        assert [r["outcome"] for r in records(io)] == ["outcome_unknown"]


def test_an_endless_100_continue_stream_ends_at_the_deadline_with_outcome_unknown(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    stop = threading.Event()

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            conn.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            while not stop.is_set():
                conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                stop.wait(0.05)
            conn.close()
        except OSError:
            pass

    server = threading.Thread(target=serve, daemon=True)
    server.start()
    cfg = tmp_path / "c.yaml"
    port = listener.getsockname()[1]
    cfg.write_text(
        f"base_url: http://127.0.0.1:{port}\nservice: {SERVICE}\ntimeout: 1s\n"
        "allow_insecure_http: true\n",
        encoding="utf-8",
    )
    try:
        started = time.monotonic()
        code, out, _, exited = run(capsys, io, str(cfg), ["--json", "send", "--message=a"])
        assert code == 12 and exited and time.monotonic() - started < 1 + 3 + LOAD_SLACK_S
        assert json.loads(out)["error"]["code"] == "outcome_unknown"
    finally:
        stop.set()
        listener.close()
        server.join(10)


def test_a_stalled_name_resolution_ends_at_the_deadline_and_writes_nothing(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    io.block_resolve = True
    with FakeHA() as ha:
        cfg = config(tmp_path, ha)
        Path(cfg).write_text(Path(cfg).read_text().replace("timeout: 10s", "timeout: 1s"))
        started = time.monotonic()
        code, out, _, exited = run(capsys, io, cfg, ["--json", "send", "--message=a"])
        assert code == 12 and exited and time.monotonic() - started < 1 + 3 + LOAD_SLACK_S
        body = json.loads(out)["error"]
        assert body["code"] == "network_error" and body["details"]["timeout"] is True
        assert ha.requests == [] and ha.connections == 0
        io.release.set()


def test_a_log_lock_held_by_another_process_delays_only_the_log(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    state = state_dir(io)
    state.mkdir(parents=True, mode=0o700)
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import fcntl,os,sys\n"
            "fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600)\n"
            "fcntl.flock(fd,fcntl.LOCK_EX)\n"
            "print('locked',flush=True)\n"
            "sys.stdin.read()\n",
            str(state / "log.lock"),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "locked"
        io.capture = capsys
        with FakeHA() as ha:
            started = time.monotonic()
            code, out, err, exited = run(
                capsys, io, config(tmp_path, ha), ["--json", "send", "--message=a"]
            )
            elapsed = time.monotonic() - started
        assert code == 0 and not exited
        assert (
            0.9 <= elapsed < 10 + 3 + LOAD_SLACK_S
        )  # the lock poll costs about one second, no more
        assert err.count(STATE_WARNING) == 1 and records(io) == []
        # the result was already on stdout when the log step first tried to lock
        assert json.loads(io.stdout_at_lock[0])["outcome"] == "sent"
        assert out == "" and "".join(io.stdout_at_lock).count("\n") == 1
    finally:
        if holder.stdin is not None:
            holder.stdin.close()
        holder.wait(10)
        if holder.stdout is not None:
            holder.stdout.close()


def test_a_released_lock_lets_the_log_through(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    state = state_dir(io)
    state.mkdir(parents=True, mode=0o700)
    fd = os.open(state / "log.lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    timer = threading.Timer(0.3, lambda: os.close(fd))
    timer.start()
    try:
        with FakeHA() as ha:
            code, _, err, _ = run(capsys, io, config(tmp_path, ha), ["send", "--message=a"])
    finally:
        timer.join(5)
    assert code == 0 and len(records(io)) == 1 and STATE_WARNING not in err
