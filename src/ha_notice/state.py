"""The state directory: a safe handle, or one fixed warning (docs/interface.md, Log).

The directory is found from the password-database home through the gateway (``HOME`` and
``XDG_STATE_HOME`` are never read), created with mode 0700 and opened without following a
symlink; every entry below it is opened relative to that descriptor. Any problem becomes
``StateUnusable``, which carries no text and no path, and the caller prints ``STATE_WARNING`` once.
A state problem never changes an exit code.

This module only opens things; the log record, the lock policy and rotation are in ``log``.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from types import TracebackType
from typing import TYPE_CHECKING, TextIO, TypeVar

from ha_notice.gateway import Gateway, GatewayError
from ha_notice.output import write_text

if TYPE_CHECKING:
    from typing import Self

__all__ = ["STATE_WARNING", "StateDir", "StateUnusable", "StateWarner", "open_state"]

_T = TypeVar("_T")

STATE_WARNING = "warning: log record skipped (state directory unusable)"


class StateUnusable(Exception):
    """The state directory or an entry in it cannot be used. Carries no detail by design."""


class StateDir:
    """An opened, validated state directory; entries are opened relative to its descriptor."""

    def __init__(self, gateway: Gateway, fd: int) -> None:
        self._gateway = gateway
        self._fd = fd

    def open_file(self, name: str, *, append: bool = False) -> int:
        """Open (creating with mode 0600) a regular file; a FIFO, symlink or device is refused."""
        return self._call(lambda: self._gateway.open_state_file(self._fd, name, append=append))

    def try_lock(self, fd: int) -> bool:
        return self._call(lambda: self._gateway.try_lock(fd))

    def rename(self, src: str, dst: str, *, missing_ok: bool = False) -> None:
        self._call(
            lambda: self._gateway.rename_state_file(self._fd, src, dst, missing_ok=missing_ok)
        )

    def size(self, fd: int) -> int:
        return self._call(lambda: self._gateway.state_file_size(fd))

    def truncate(self, fd: int, size: int) -> None:
        self._call(lambda: self._gateway.state_file_truncate(fd, size))

    def close_file(self, fd: int) -> None:
        """Close a descriptor returned by ``open_file`` (releases a lock held on it)."""
        self._gateway.close_fd(fd)

    def write(self, fd: int, data: bytes) -> int:
        return self._call(lambda: self._gateway.write_fd(fd, data))

    def close(self) -> None:
        if self._fd >= 0:
            fd, self._fd = self._fd, -1
            self._gateway.close_fd(fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _call(self, fn: Callable[[], _T]) -> _T:
        if self._fd < 0:
            raise StateUnusable
        try:
            return fn()
        except (GatewayError, OSError, ValueError):
            raise StateUnusable from None


def open_state(gateway: Gateway) -> StateDir:
    """Resolve, create and validate the state directory, or raise ``StateUnusable``."""
    try:
        home = gateway.home_dir()
        fd = gateway.open_state_dir(home)
    except (GatewayError, OSError, ValueError):
        raise StateUnusable from None
    return StateDir(gateway, fd)


class StateWarner:
    """Prints ``STATE_WARNING`` at most once per run; a broken stream is ignored."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = sys.stderr if stream is None else stream
        self._done = False

    def warn(self) -> None:
        if not self._done:
            self._done = True
            write_text(self._stream, STATE_WARNING + "\n")
