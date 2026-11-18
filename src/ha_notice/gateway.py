"""Gateway: the single boundary for everything the outside world provides.

HTTP, the clocks, name resolution, the home directory and uid, input reading, config file reading,
state-directory access, CA path candidates and process exit all live here. No other module imports
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
import math
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
    "MAX_CONFIG_ENTRIES",
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
MAX_CONFIG_ENTRIES = 256

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

    # Config files
    def read_config(self, path: str, max_bytes: int) -> bytes | None: ...
    def list_config_dir(self, path: str) -> list[str]: ...

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
    that are usable, plus the config ``ca_file``) is decided by the HTTP client. A file that
    cannot be read or parsed raises ``GatewayError`` with a fixed message (never the path).
    TODO(#22): trust selection (usable bundle, non-empty directory, fallback files).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    failed = False
    for path in ca_files:
        try:
            ctx.load_verify_locations(cafile=path)
        except (OSError, ssl.SSLError, ValueError):
            failed = True
            break
    if failed:  # raised outside the handler so no context carries the path
        raise GatewayError("trust file cannot be loaded")
    return ctx


def _plain_name(name: str) -> None:
    if not name or "/" in name or "\0" in name or name in (".", ".."):
        raise ValueError("state file names must be plain names")


class _RealResponse:
    def __init__(self, response: http.client.HTTPResponse) -> None:
        self._response = response
        self.status: int = response.status
        # ``http.client`` returns a short ``read(amt)`` silently when the peer closes before
        # Content-Length bytes arrive, so the declared length is tracked here.
        self._expected: int | None = response.length

    def read(self, amt: int) -> bytes:
        if amt < 0:
            data = self._response.read()  # raises IncompleteRead itself on a short body
            self._expected = 0 if self._expected is not None else None
            return data
        data = self._response.read(amt)
        if self._expected is not None:
            self._expected -= len(data)
            if not data and amt > 0 and self._expected > 0:
                raise IncompleteRead(b"", self._expected)
        return data


class _RealConnection:
    """``http.client`` connection that resolves through the gateway and sets its own timeouts.

    ``connect_timeout`` is one monotonic deadline that starts in ``connect()`` and covers name
    resolution, every address and the TLS handshake. After ``connect()`` only the per-operation
    ``io_timeout`` applies: neither this class nor ``http.client`` bounds a whole exchange (a
    server can send ``100 Continue`` responses forever), so the overall send deadline is enforced
    by the caller's worker thread and ``os._exit``, never here.
    """

    def __init__(self, gateway: RealGateway, spec: ConnectSpec) -> None:
        self._gateway = gateway
        self._spec = spec
        self._deadline = 0.0
        if spec.scheme == "https":
            if spec.tls is None:
                raise ValueError("https needs a TLS context")
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                spec.host, spec.port, timeout=spec.connect_timeout, context=spec.tls
            )
        else:
            conn = http.client.HTTPConnection(spec.host, spec.port, timeout=spec.connect_timeout)
        # http.client's connect() calls this to open the TCP socket (and wraps it in TLS
        # afterwards); ours resolves through the gateway instead of the socket module. If a
        # Python release renames the attribute, fail loudly instead of silently using the
        # stdlib resolver.
        if not hasattr(conn, "_create_connection"):
            raise GatewayError("http.client connection seam is missing")
        conn._create_connection = self._open_socket  # pyright: ignore[reportAttributeAccessIssue]
        if conn._create_connection != self._open_socket:  # pyright: ignore[reportAttributeAccessIssue]
            raise GatewayError("http.client connection seam is not in use")
        self._conn = conn

    def _time_left(self) -> float:
        return self._deadline - self._gateway.monotonic()

    def _open_socket(
        self,
        address: tuple[str, int],
        timeout: float | None = None,
        source_address: tuple[str, int] | None = None,
    ) -> socket.socket:
        host, port = address
        last: OSError | None = None
        addresses = self._gateway.resolve(host, port)
        for family, kind, proto, _canon, sockaddr in addresses:
            left = self._time_left()
            if left <= 0:
                raise TimeoutError("connect timed out")
            sock = socket.socket(family, kind, proto)
            try:
                sock.settimeout(left)
                sock.connect(sockaddr)  # pyright: ignore[reportArgumentType]
            except OSError as exc:
                sock.close()
                last = exc
                continue
            # http.client wraps this socket in TLS next. CPython bounds a whole handshake by the
            # socket timeout (one deadline across its reads, not one per read), so re-arming it
            # with what remains makes a stalled or drip-feeding handshake end with the deadline.
            remaining = self._time_left()
            if remaining <= 0:
                sock.close()
                raise TimeoutError("connect timed out")
            sock.settimeout(remaining)
            return sock
        if self._time_left() <= 0:
            raise TimeoutError("connect timed out")
        raise last if last is not None else OSError(errno.EHOSTUNREACH, "no address")

    def connect(self) -> None:
        self._deadline = self._gateway.monotonic() + self._spec.connect_timeout
        self._conn.connect()  # name resolution, TCP, then TLS, all under the one deadline
        if self._time_left() <= 0:
            raise TimeoutError("connect timed out")
        if self._conn.sock is not None:
            self._conn.sock.settimeout(self._spec.io_timeout)

    def request(
        self, method: str, path: str, body: bytes | None, headers: Mapping[str, str]
    ) -> None:
        # http.client's validation errors echo the offending text (a header value may be the
        # token), so they are replaced by fixed ones, raised outside the handler (no context).
        failure: type[BaseException] | None = None
        try:
            self._conn.request(method, path, body=body, headers=dict(headers))
        except UnicodeEncodeError:
            failure = UnicodeEncodeError
        except InvalidURL:
            failure = InvalidURL
        except ValueError:
            failure = ValueError
        if failure is UnicodeEncodeError:
            raise UnicodeEncodeError("latin-1", "", 0, 1, "request text is not encodable")
        if failure is InvalidURL:
            raise InvalidURL("invalid request path")
        if failure is ValueError:
            raise ValueError("invalid header")

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
        descriptor is empty input; any other read error, or any error after data arrived, is
        ``SourceError``. A path is opened ``O_NONBLOCK`` and the opened
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
        # ``poll`` rather than ``select``: select cannot watch a descriptor >= 1024. A negative
        # descriptor raises ValueError (a caller bug, never swallowed).
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        data = bytearray()
        while True:
            left = remaining()
            if left <= 0:
                return SourceResult(bytes(data), "timeout")
            events = poller.poll(max(1, math.ceil(min(SLICE_SECONDS, left) * 1000)))
            if not events:
                continue
            if events[0][1] & select.POLLNVAL:
                if data:
                    raise SourceError("input descriptor was closed while reading")
                break  # a closed descriptor is empty input
            want = min(FILE_CHUNK, max_bytes + 1 - len(data))
            failed_errno = 0
            chunk = b""
            try:
                chunk = os.read(fd, want)
            except BlockingIOError:
                continue
            except OSError as exc:
                failed_errno = exc.errno or -1
            if failed_errno:  # raised outside the handler: no context carries the OS text
                if failed_errno == errno.EBADF and not data:
                    break
                raise SourceError("input cannot be read")
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                return SourceResult(bytes(data[:max_bytes]), "too_large")
        return SourceResult(bytes(data), "ok")

    # --- config files
    def read_config(self, path: str, max_bytes: int) -> bytes | None:
        """Read a config file of at most ``max_bytes``; ``None`` when it does not exist.

        The path is opened ``O_NONBLOCK`` (a FIFO never blocks) and ``O_NOCTTY``, and the opened
        descriptor must be a regular file; symlinks are followed. A file that is not regular,
        cannot be read or is larger than ``max_bytes`` is ``SourceError``. Only a missing file
        (also a dangling symlink) is ``None``.
        """
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            raise SourceError("config file cannot be opened") from None
        failed = ""
        data = bytearray()
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                failed = "config file is not a regular file"
            while not failed:
                try:
                    chunk = os.read(fd, min(FILE_CHUNK, max_bytes + 1 - len(data)))
                except OSError:
                    failed = "config file cannot be read"
                    break
                if not chunk:
                    break
                data += chunk
                if len(data) > max_bytes:
                    failed = "config file is too large"
        finally:
            os.close(fd)
        if failed:
            raise SourceError(failed)
        return bytes(data)

    def list_config_dir(self, path: str) -> list[str]:
        """Names of the ``*.yaml`` entries (not starting with a dot) of a directory, sorted.

        A missing directory is an empty list; anything else that is not a readable directory, or
        more than ``MAX_CONFIG_ENTRIES`` matching names, is ``SourceError``.
        """
        try:
            names = os.listdir(path)
        except FileNotFoundError:
            return []
        except (OSError, ValueError):
            raise SourceError("config directory cannot be read") from None
        found = sorted(n for n in names if n.endswith(".yaml") and not n.startswith("."))
        if len(found) > MAX_CONFIG_ENTRIES:
            raise SourceError("config directory has too many files")
        return found

    # --- state directory
    def open_state_dir(self, home: str) -> int:
        """Create (mode 0700) and open ``<home>/.local/state/ha-notice``; return its descriptor.

        The directory is opened ``O_DIRECTORY | O_NOFOLLOW`` and must be owned by the user with
        no group or other permissions, else ``StateDirError``; ``home`` must be absolute. Ownership
        is checked against ``self.uid()`` so a test can inject the user.
        """
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        parent_fd = -1
        fd = -1
        if not os.path.isabs(home):
            raise StateDirError("state directory home is not absolute")
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
            if st.st_uid != self.uid() or st.st_mode & 0o077:
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
