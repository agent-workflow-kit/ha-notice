"""A scripted gateway for process tests (issue #3).

``FakeGateway`` has the same methods, signatures and exceptions as ``ha_notice.gateway``'s real
gateway (``tests/test_gateway_conformance.py`` pins that). It scripts the clock, name resolution,
the home directory and uid, input sources, CA path candidates and each connection. State
directory and TLS context methods delegate to the real implementation, so a test points them at
a private temporary home.

Nothing here opens a network connection. Blocking steps wait on ``threading.Event`` objects
that the test sets, with a hard cap so a broken test fails instead of hanging.
"""

from __future__ import annotations

import http.client
import os
import re
import threading
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn

from ha_notice import gateway as gw
from ha_notice.gateway import (
    AddrInfo,
    CaCandidates,
    ConnectSpec,
    HomeLookupError,
    SourceError,
    SourceResult,
    StateDirError,
)

WAIT_CAP_SECONDS = 10.0
LOOPBACK: AddrInfo = (2, 1, 6, "", ("127.0.0.1", 0))


class FakeExit(BaseException):
    """Raised by ``FakeGateway.exit_process`` instead of ending the test process."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class StallingSource:
    """Input that delivers ``data`` and then never ends (a producer that stalls)."""

    data: bytes = b""


@dataclass
class ConnectionScript:
    """What one fake connection does. Every field is optional; the default is a 200 ``[]``."""

    resolve: bool = True  # call the gateway's resolver in connect(), as the real one does
    connect_delay: float = 0.0  # seconds the fake clock advances inside connect()
    # One entry per address the name resolves to: seconds until that address refuses, or None
    # for a blackhole. Replaces ``connect_delay``; every wait is cut off by the connect deadline.
    address_delays: tuple[float | None, ...] = ()
    connect_block: threading.Event | None = None  # connect() waits for this event
    connect_error: BaseException | None = None
    request_error: BaseException | None = None  # raised by request() after the partial write
    request_bytes_before_error: int = 0
    status: int = 200
    body: bytes = b"[]"
    response_error: BaseException | None = None  # raised by getresponse()
    read_error: BaseException | None = None  # raised by read() once read_error_after bytes are out
    read_error_after: int = 0
    declared_length: int | None = None  # Content-Length; fewer body bytes is IncompleteRead
    stall_after_first_byte: threading.Event | None = None  # read() waits after byte one


@dataclass
class RecordedRequest:
    method: str
    path: str
    body: bytes | None
    headers: dict[str, str]


class FakeResponse:
    def __init__(self, script: ConnectionScript) -> None:
        self.status = script.status
        self._body = script.body
        self._pos = 0
        self._stall = script.stall_after_first_byte
        self._read_error = script.read_error
        self._read_error_after = script.read_error_after
        self._declared = script.declared_length

    def read(self, amt: int) -> bytes:
        if self._read_error is not None and self._pos >= self._read_error_after:
            raise self._read_error
        if amt < 0:
            amt = len(self._body) - self._pos
        if self._stall is not None and self._pos >= 1:
            self._stall.wait(WAIT_CAP_SECONDS)
        if self._stall is not None and self._pos == 0:
            amt = min(amt, 1)
        if self._read_error is not None:
            amt = min(amt, self._read_error_after - self._pos)
        chunk = self._body[self._pos : self._pos + amt]
        self._pos += len(chunk)
        if not chunk and amt > 0 and self._declared is not None and self._pos < self._declared:
            raise http.client.IncompleteRead(b"", self._declared - self._pos)
        return chunk


# Mirrors http.client's own checks (the messages are never copied: they echo the input).
_BAD_PATH = re.compile(r"[\x00-\x20\x7f]")
_BAD_HEADER_NAME = re.compile(r"^[^:\s][^:\r\n]*$")
_BAD_HEADER_VALUE = re.compile(r"\n(?![ \t])|\r(?![ \t\n])")


class FakeConnection:
    def __init__(self, gateway: FakeGateway, spec: ConnectSpec, script: ConnectionScript) -> None:
        self._gateway = gateway
        self.spec = spec
        self.script = script
        self.connected = False
        self.closed = False
        self.requests: list[RecordedRequest] = []
        self.bytes_written = 0
        self._request_sent = False  # a request is written and its response not yet taken

    def connect(self) -> None:
        gateway = self._gateway
        deadline = gateway.monotonic() + self.spec.connect_timeout
        if self.script.resolve:
            host = self.spec.host
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]  # http.client strips the brackets of an IPv6 literal
            gateway.resolve(host, self.spec.port)
        if self.script.connect_block is not None:
            self.script.connect_block.wait(WAIT_CAP_SECONDS)
        self._spend(deadline, self.script.connect_delay)
        if self.script.address_delays:
            for delay in self.script.address_delays:
                # None is a blackhole: it outlasts any deadline.
                self._spend(deadline, self.spec.connect_timeout + 1 if delay is None else delay)
            raise ConnectionRefusedError(111, "Connection refused")
        if self.script.connect_error is not None:
            raise self.script.connect_error
        self.connected = True

    def _spend(self, deadline: float, seconds: float) -> None:
        """Advance the clock, but never past the connect deadline (that is a TimeoutError)."""
        left = deadline - self._gateway.monotonic()
        if seconds >= left:
            self._gateway.advance(max(left, 0.0))
            raise TimeoutError("timed out")
        self._gateway.advance(seconds)

    def request(
        self, method: str, path: str, body: bytes | None, headers: Mapping[str, str]
    ) -> None:
        if not self.connected:
            self.connect()
        if self._request_sent:
            raise http.client.CannotSendRequest("Request-sent")
        self._validate(path, headers)
        if self.script.request_error is not None:
            self.bytes_written += self.script.request_bytes_before_error
            raise self.script.request_error
        self.bytes_written += len(body or b"") + len(path) + len(method)
        self.requests.append(RecordedRequest(method, path, body, dict(headers)))
        self._request_sent = True

    @staticmethod
    def _validate(path: str, headers: Mapping[str, str]) -> None:
        """What the real connection rejects, with the same classes and fixed messages."""
        if _BAD_PATH.search(path):
            raise http.client.InvalidURL("invalid request path")
        for name, value in headers.items():
            if not _BAD_HEADER_NAME.fullmatch(name):
                raise ValueError("invalid header")
            if _BAD_HEADER_VALUE.search(value):
                raise ValueError("invalid header")
            try:
                value.encode("latin-1")
            except UnicodeEncodeError:
                pass
            else:
                continue
            raise UnicodeEncodeError("latin-1", "", 0, 1, "header value is not latin-1")

    def getresponse(self) -> FakeResponse:
        if not self._request_sent:
            raise http.client.ResponseNotReady("no request was sent")
        self._request_sent = False
        if self.script.response_error is not None:
            raise self.script.response_error
        return FakeResponse(self.script)

    def close(self) -> None:
        self.closed = True


@dataclass
class FakeGateway:
    """Implements ``ha_notice.gateway.Gateway`` with scripted behaviour."""

    now: float = 1000.0
    wall: float = 1_700_000_000.0
    hosts: dict[str, list[AddrInfo]] = field(default_factory=dict)
    resolve_errors: dict[str, BaseException] = field(default_factory=dict)
    resolve_block: threading.Event | None = None
    resolve_delay: float = 0.0  # seconds the fake clock advances inside resolve()
    home: str | HomeLookupError = "/nonexistent-fake-home"
    user_id: int = field(default_factory=lambda: os.getuid())
    login: str | None = "fakeuser"
    tty_fds: set[int] = field(default_factory=set)
    sources: dict[int | str, bytes | StallingSource | SourceError] = field(default_factory=dict)
    state_error: StateDirError | None = None
    ca: CaCandidates = field(default_factory=lambda: CaCandidates("", "", ()))
    scripts: deque[ConnectionScript] = field(default_factory=deque)
    default_script: ConnectionScript = field(default_factory=ConnectionScript)
    # Records, for assertions.
    sleeps: list[float] = field(default_factory=list)
    resolve_calls: list[tuple[str, int]] = field(default_factory=list)
    connections: list[FakeConnection] = field(default_factory=list)
    exits: list[int] = field(default_factory=list)
    _real: gw.RealGateway = field(default_factory=gw.RealGateway)

    # Clock
    def monotonic(self) -> float:
        return self.now

    def wall_time(self) -> float:
        return self.wall + (self.now - 1000.0)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.advance(seconds)

    def advance(self, seconds: float) -> None:
        if seconds > 0:
            self.now += seconds

    # Names
    def resolve(self, host: str, port: int) -> list[AddrInfo]:
        self.resolve_calls.append((host, port))
        if self.resolve_block is not None:
            self.resolve_block.wait(WAIT_CAP_SECONDS)
        self.advance(self.resolve_delay)
        if host in self.resolve_errors:
            raise self.resolve_errors[host]
        if host in self.hosts:
            return list(self.hosts[host])
        return [LOOPBACK]

    # Identity
    def home_dir(self) -> str:
        if isinstance(self.home, HomeLookupError):
            raise self.home
        return self.home

    def uid(self) -> int:
        return self.user_id

    def login_name(self) -> str | None:
        return self.login

    # Input
    def isatty(self, fd: int) -> bool:
        return fd in self.tty_fds

    def read_source(
        self, source: int | str, max_bytes: int, remaining: Callable[[], float]
    ) -> SourceResult:
        if isinstance(source, str) and (source == "" or source not in self.sources):
            raise SourceError  # like the real gateway: a missing path or "" cannot be opened
        scripted = self.sources.get(source, b"")
        if isinstance(scripted, SourceError):
            raise scripted
        if isinstance(scripted, StallingSource):
            if len(scripted.data) > max_bytes:
                return SourceResult(scripted.data[:max_bytes], "too_large")
            left = remaining()
            while left > 0:
                self.advance(min(gw.SLICE_SECONDS, left))
                left = remaining()
            return SourceResult(scripted.data, "timeout")
        if remaining() <= 0:
            return SourceResult(b"", "timeout")
        if len(scripted) > max_bytes:
            return SourceResult(scripted[:max_bytes], "too_large")
        return SourceResult(scripted, "ok")

    # Config files (delegate to the real code, on files the test writes)
    def read_config(self, path: str, max_bytes: int) -> bytes | None:
        return self._real.read_config(path, max_bytes)

    def list_config_dir(self, path: str) -> list[str]:
        return self._real.list_config_dir(path)

    # State directory (delegates to the real code, on whatever home the test passes)
    def open_state_dir(self, home: str) -> int:
        if self.state_error is not None:
            raise self.state_error
        return _OwnedBy(self.user_id).open_state_dir(home)

    def open_state_file(self, dir_fd: int, name: str, *, append: bool = False) -> int:
        return self._real.open_state_file(dir_fd, name, append=append)

    def try_lock(self, fd: int) -> bool:
        return self._real.try_lock(fd)

    def rename_state_file(
        self, dir_fd: int, src: str, dst: str, *, missing_ok: bool = False
    ) -> None:
        self._real.rename_state_file(dir_fd, src, dst, missing_ok=missing_ok)

    def state_file_size(self, fd: int) -> int:
        return self._real.state_file_size(fd)

    def state_file_truncate(self, fd: int, size: int) -> None:
        self._real.state_file_truncate(fd, size)

    def write_fd(self, fd: int, data: bytes) -> int:
        return self._real.write_fd(fd, data)

    def close_fd(self, fd: int) -> None:
        self._real.close_fd(fd)

    # TLS and HTTP
    def ca_candidates(self) -> CaCandidates:
        return self.ca

    def new_tls_context(
        self,
        ca_files: Sequence[str],
        ca_dirs: Sequence[str] = (),
        ca_pems: Sequence[bytes] = (),
    ) -> gw.ssl.SSLContext:
        return gw.build_tls_context(ca_files, ca_dirs, ca_pems)

    def has_entries(self, path: str) -> bool:
        return self._real.has_entries(path)

    def connect(self, spec: ConnectSpec) -> FakeConnection:
        if spec.scheme == "https" and spec.tls is None:
            raise ValueError("https needs a TLS context")
        script = self.scripts.popleft() if self.scripts else self.default_script
        conn = FakeConnection(self, spec, script)
        self.connections.append(conn)
        return conn

    # Process
    def exit_process(self, code: int) -> NoReturn:
        self.exits.append(code)
        raise FakeExit(code)


class _OwnedBy(gw.RealGateway):
    """The real state-directory code with the injected uid, so the owner check is the real one."""

    def __init__(self, uid: int) -> None:
        super().__init__()
        self._uid = uid

    def uid(self) -> int:
        return self._uid


def private_home(tmp_path: Path) -> str:
    """A home directory for state-directory tests, created with a private mode."""
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    return str(home)
