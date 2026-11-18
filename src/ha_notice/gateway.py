"""Gateway: the single boundary for everything the outside world provides.

HTTP, the clocks, name resolution, the home directory and uid, input reading, state-directory
access, CA path candidates and process exit all live here. No other module imports
``http.client``, ``time`` or ``subprocess`` (``tests/test_gateway_boundary.py`` scans for it),
this tool never runs a subprocess, and ``urllib`` is not used at all. Process tests pass a fake
(``tests/fake_gateway.py``) to ``cli.main(argv, env, gateway)``; there is no test-only
environment seam.

``Gateway`` is the interface other modules code against; ``RealGateway`` implements it.

Rules kept here (docs/interface.md, Home Assistant edge, Config and Log):

- The home directory comes from the password database only. ``HOME``, ``XDG_CONFIG_HOME`` and
  ``XDG_STATE_HOME`` are never read; a failed lookup raises ``HomeLookupError`` (the caller maps
  it to exit 2 ``config_invalid`` with key ``home``); there is no fallback.
- HTTP uses ``http.client`` only, with no proxy (the proxy variables are never read) and no
  redirect handling (the response exposes a status and a body, never a header).
- The TLS context is our own and loads no trust from ``SSL_CERT_FILE`` or ``SSL_CERT_DIR``.
- Exception messages here never contain a path, a name or any input.
"""

from __future__ import annotations

import errno
import fcntl
import http.client
import os
import pwd
import select
import socket
import ssl
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from http.client import (
    BadStatusLine,
    HTTPException,
    IncompleteRead,
    InvalidURL,
    LineTooLong,
    RemoteDisconnected,
    UnknownProtocol,
)
from typing import Literal, NoReturn, Protocol

__all__ = [
    "SLICE_SECONDS",
    "FILE_CHUNK",
    "AddrInfo",
    "BadStatusLine",
    "CaCandidates",
    "ConnectSpec",
    "Connection",
    "Gateway",
    "GatewayError",
    "HTTPException",
    "HomeLookupError",
    "IncompleteRead",
    "InvalidURL",
    "LineTooLong",
    "RealGateway",
    "RemoteDisconnected",
    "Response",
    "SourceError",
    "SourceResult",
    "StateDirError",
    "UnknownProtocol",
    "build_tls_context",
]

# Input is read in slices of at most 100 ms so the caller notices a deadline between slices.
SLICE_SECONDS = 0.1
FILE_CHUNK = 64 * 1024

STATE_DIR_PARTS = (".local", "state", "ha-notice")
CA_FALLBACK_FILES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
)

# One ``socket.getaddrinfo`` result: (family, type, proto, canonname, sockaddr).
AddrInfo = tuple[int, int, int, str, tuple[object, ...]]


class GatewayError(Exception):
    """Base class of the gateway's own errors. Messages are fixed strings."""


class HomeLookupError(GatewayError):
    """The password-database home is missing, empty, relative or not a directory."""


class SourceError(GatewayError):
    """An input path does not exist, cannot be read or is not a regular file."""


class StateDirError(GatewayError):
    """The state directory or a file in it is unusable (unsafe, missing, wrong type)."""


@dataclass(frozen=True)
class SourceResult:
    """Bytes read from an input source and how the read ended.

    ``timeout``: the deadline passed first (``data`` is what arrived). ``too_large``: more than
    ``max_bytes`` were available (``data`` is the first ``max_bytes``).
    """

    data: bytes
    status: Literal["ok", "timeout", "too_large"]


@dataclass(frozen=True)
class ConnectSpec:
    """Where and how to connect. ``host`` and ``port`` are validated by the caller.

    ``connect_timeout`` covers name resolution, TCP and TLS; ``io_timeout`` is the per-operation
    socket timeout afterwards. ``tls`` is required for ``https`` (built by ``new_tls_context``).
    """

    scheme: Literal["http", "https"]
    host: str
    port: int
    connect_timeout: float
    io_timeout: float
    tls: ssl.SSLContext | None = None


@dataclass(frozen=True)
class CaCandidates:
    """The compiled default trust locations (never the ones that follow SSL_CERT_*)."""

    cafile: str
    capath: str
    fallback_files: tuple[str, ...]


class Response(Protocol):
    """A response: the status and the body. Headers are deliberately not exposed."""

    status: int

    def read(self, amt: int) -> bytes: ...


class Connection(Protocol):
    """One HTTP connection. ``connect()`` completes TCP and TLS before ``request()`` is called."""

    def connect(self) -> None: ...

    def request(
        self, method: str, path: str, body: bytes | None, headers: Mapping[str, str]
    ) -> None: ...

    def getresponse(self) -> Response: ...

    def close(self) -> None: ...


class Gateway(Protocol):
    """Everything that touches the outside world."""

    # Clocks
    def monotonic(self) -> float: ...
    def wall_time(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...

    # Names
    def resolve(self, host: str, port: int) -> list[AddrInfo]: ...

    # Identity
    def home_dir(self) -> str: ...
    def uid(self) -> int: ...
    def login_name(self) -> str | None: ...

    # Input
    def isatty(self, fd: int) -> bool: ...
    def read_source(
        self, source: int | str, max_bytes: int, remaining: Callable[[], float]
    ) -> SourceResult: ...

    # State directory
    def open_state_dir(self, home: str) -> int: ...
    def open_state_file(self, dir_fd: int, name: str, *, append: bool = False) -> int: ...
    def try_lock(self, fd: int) -> bool: ...
    def rename_state_file(self, dir_fd: int, src: str, dst: str) -> None: ...
    def write_fd(self, fd: int, data: bytes) -> int: ...
    def close_fd(self, fd: int) -> None: ...

    # TLS and HTTP
    def ca_candidates(self) -> CaCandidates: ...
    def new_tls_context(self, ca_files: Sequence[str]) -> ssl.SSLContext: ...
    def connect(self, spec: ConnectSpec) -> Connection: ...

    # Process
    def exit_process(self, code: int) -> NoReturn: ...


def build_tls_context(ca_files: Sequence[str]) -> ssl.SSLContext:
    """A strict client context that loads trust only from ``ca_files``.

    ``load_default_certs`` and ``set_default_verify_paths`` are never called, because they
    follow ``SSL_CERT_FILE`` and ``SSL_CERT_DIR``. Which files to pass (the compiled defaults
    that are usable, plus the config ``ca_file``) is decided by the HTTP client.
    TODO(#22): trust selection (usable bundle, non-empty directory, fallback files).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    for path in ca_files:
        ctx.load_verify_locations(cafile=path)
    return ctx


def _plain_name(name: str) -> None:
    if not name or "/" in name or "\0" in name or name in (".", ".."):
        raise ValueError("state file names must be plain names")


class _RealResponse:
    def __init__(self, response: http.client.HTTPResponse) -> None:
        self._response = response
        self.status: int = response.status

    def read(self, amt: int) -> bytes:
        return self._response.read(amt)


class _RealConnection:
    """``http.client`` connection that resolves through the gateway and sets its own timeouts."""

    def __init__(self, gateway: RealGateway, spec: ConnectSpec) -> None:
        self._gateway = gateway
        self._spec = spec
        if spec.scheme == "https":
            if spec.tls is None:
                raise ValueError("https needs a TLS context")
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                spec.host, spec.port, timeout=spec.connect_timeout, context=spec.tls
            )
        else:
            conn = http.client.HTTPConnection(spec.host, spec.port, timeout=spec.connect_timeout)
        # http.client's connect() calls this to open the TCP socket (and wraps it in TLS
        # afterwards); ours resolves through the gateway instead of the socket module.
        conn._create_connection = self._open_socket  # pyright: ignore[reportAttributeAccessIssue]
        self._conn = conn

    def _open_socket(
        self,
        address: tuple[str, int],
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
    ) -> socket.socket:
        host, port = address
        last: OSError | None = None
        for family, kind, proto, _canon, sockaddr in self._gateway.resolve(host, port):
            sock = socket.socket(family, kind, proto)
            try:
                sock.settimeout(self._spec.connect_timeout)
                sock.connect(sockaddr)  # pyright: ignore[reportArgumentType]
            except OSError as exc:
                sock.close()
                last = exc
                continue
            return sock
        raise last if last is not None else OSError(errno.EHOSTUNREACH, "no address")

    def connect(self) -> None:
        self._conn.connect()  # TCP, then TLS, both under the connect timeout
        if self._conn.sock is not None:
            self._conn.sock.settimeout(self._spec.io_timeout)

    def request(
        self, method: str, path: str, body: bytes | None, headers: Mapping[str, str]
    ) -> None:
        self._conn.request(method, path, body=body, headers=dict(headers))

    def getresponse(self) -> _RealResponse:
        return _RealResponse(self._conn.getresponse())

    def close(self) -> None:
        self._conn.close()


class RealGateway:
    """The production gateway."""

    # --- clocks
    def monotonic(self) -> float:
        return time.monotonic()

    def wall_time(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    # --- names
    def resolve(self, host: str, port: int) -> list[AddrInfo]:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)  # pyright: ignore[reportReturnType]

    # --- identity
    def home_dir(self) -> str:
        try:
            home = pwd.getpwuid(os.getuid()).pw_dir
        except (KeyError, OSError, OverflowError):
            raise HomeLookupError("home directory lookup failed") from None
        if not home or not os.path.isabs(home) or not os.path.isdir(home):
            raise HomeLookupError("home directory is empty, relative or not a directory")
        return home

    def uid(self) -> int:
        return os.getuid()

    def login_name(self) -> str | None:
        try:
            return pwd.getpwuid(os.getuid()).pw_name
        except (KeyError, OSError, OverflowError):
            return None

    # --- input
    def isatty(self, fd: int) -> bool:
        try:
            return os.isatty(fd)
        except OSError:
            return False

    def read_source(
        self, source: int | str, max_bytes: int, remaining: Callable[[], float]
    ) -> SourceResult:
        """Read at most ``max_bytes`` from a descriptor (not closed) or a regular file path.

        Reads in slices of at most ``SLICE_SECONDS`` and asks ``remaining()`` (seconds left,
        0 or less means expired) before each, so a stalled producer cannot hold the caller past
        its deadline. A signal the caller wants noticed makes ``remaining`` return 0. A closed
        or unreadable descriptor is empty input. A path is opened ``O_NONBLOCK`` and the opened
        descriptor must be a regular file, else ``SourceError``.
        """
        if isinstance(source, str):
            fd = self._open_regular(source)
            try:
                return self._read_fd(fd, max_bytes, remaining)
            finally:
                os.close(fd)
        return self._read_fd(source, max_bytes, remaining)

    @staticmethod
    def _open_regular(path: str) -> int:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        except (OSError, ValueError):
            raise SourceError("input file cannot be opened") from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise SourceError("input file is not a regular file")
        except BaseException:
            os.close(fd)
            raise
        return fd

    @staticmethod
    def _read_fd(fd: int, max_bytes: int, remaining: Callable[[], float]) -> SourceResult:
        data = bytearray()
        while True:
            left = remaining()
            if left <= 0:
                return SourceResult(bytes(data), "timeout")
            try:
                ready, _, _ = select.select([fd], [], [], min(SLICE_SECONDS, left))
            except (OSError, ValueError):
                break  # closed or unusable descriptor: empty (or what arrived so far)
            if not ready:
                continue
            want = min(FILE_CHUNK, max_bytes + 1 - len(data))
            try:
                chunk = os.read(fd, want)
            except BlockingIOError:
                continue
            except OSError:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                return SourceResult(bytes(data[:max_bytes]), "too_large")
        return SourceResult(bytes(data), "ok")

    # --- state directory
    def open_state_dir(self, home: str) -> int:
        """Create (mode 0700) and open ``<home>/.local/state/ha-notice``; return its descriptor.

        The directory is opened ``O_DIRECTORY | O_NOFOLLOW`` and must be owned by the user with
        no group or other permissions, else ``StateDirError``.
        """
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        parent_fd = -1
        fd = -1
        try:
            parent = os.path.join(home, *STATE_DIR_PARTS[:-1])
            os.makedirs(parent, mode=0o700, exist_ok=True)
            parent_fd = os.open(parent, flags)
            try:
                os.mkdir(STATE_DIR_PARTS[-1], 0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
            fd = os.open(STATE_DIR_PARTS[-1], flags | os.O_NOFOLLOW, dir_fd=parent_fd)
            st = os.fstat(fd)
            if st.st_uid != os.getuid() or st.st_mode & 0o077:
                raise StateDirError("state directory is not private to the user")
            result, fd = fd, -1
            return result
        except StateDirError:
            raise
        except (OSError, ValueError):
            raise StateDirError("state directory cannot be opened") from None
        finally:
            if fd >= 0:
                os.close(fd)
            if parent_fd >= 0:
                os.close(parent_fd)

    def open_state_file(self, dir_fd: int, name: str, *, append: bool = False) -> int:
        """Open (creating, mode 0600) a regular file relative to the state directory."""
        _plain_name(name)
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        if append:
            flags |= os.O_APPEND
        try:
            fd = os.open(name, flags, 0o600, dir_fd=dir_fd)
        except OSError:
            raise StateDirError("state file cannot be opened") from None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise StateDirError("state file is not a regular file")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def try_lock(self, fd: int) -> bool:
        """One non-blocking exclusive ``flock`` attempt; the caller polls."""
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        except OSError:
            raise StateDirError("state lock cannot be taken") from None
        return True

    def rename_state_file(self, dir_fd: int, src: str, dst: str) -> None:
        _plain_name(src)
        _plain_name(dst)
        try:
            os.rename(src, dst, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except OSError:
            raise StateDirError("state file cannot be renamed") from None

    def write_fd(self, fd: int, data: bytes) -> int:
        try:
            return os.write(fd, data)
        except OSError:
            raise StateDirError("state file cannot be written") from None

    def close_fd(self, fd: int) -> None:
        try:
            os.close(fd)
        except OSError:
            pass

    # --- TLS and HTTP
    def ca_candidates(self) -> CaCandidates:
        paths = ssl.get_default_verify_paths()
        # openssl_* are the compiled-in locations; cafile/capath follow SSL_CERT_FILE/DIR.
        return CaCandidates(
            cafile=paths.openssl_cafile or "",
            capath=paths.openssl_capath or "",
            fallback_files=CA_FALLBACK_FILES,
        )

    def new_tls_context(self, ca_files: Sequence[str]) -> ssl.SSLContext:
        return build_tls_context(ca_files)

    def connect(self, spec: ConnectSpec) -> _RealConnection:
        """A connection that has not connected yet; call ``connect()`` before ``request()``."""
        return _RealConnection(self, spec)

    # --- process
    def exit_process(self, code: int) -> NoReturn:
        os._exit(code)
