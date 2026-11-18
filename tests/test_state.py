"""The state directory module (issue #20): safe open, one fixed warning, never an exception.

Everything runs on a private tmp home passed through the gateway; ``HOME`` and ``XDG_STATE_HOME``
are pointed at a trap directory that must stay empty.
"""

from __future__ import annotations

import errno
import io
import os
import signal
import stat
import subprocess
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ha_notice import gateway as gw
from ha_notice.gateway import HomeLookupError, RealGateway
from ha_notice.state import STATE_WARNING, StateDir, StateUnusable, StateWarner, open_state
from tests.fake_gateway import FakeGateway

STATE_REL = Path(".local") / "state" / "ha-notice"


@pytest.fixture
def trap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """HOME and XDG_STATE_HOME point here; nothing may ever be created in it."""
    t = tmp_path / "trap"
    t.mkdir()
    monkeypatch.setenv("HOME", str(t))
    monkeypatch.setenv("XDG_STATE_HOME", str(t))
    return t


@pytest.fixture
def home(tmp_path: Path, trap: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir(mode=0o700)
    return h


def make_gateway(home: Path, **kw: Any) -> FakeGateway:
    return FakeGateway(home=str(home), **kw)


@pytest.fixture(autouse=True)
def _alarm(request: pytest.FixtureRequest) -> Iterator[None]:
    # a FIFO opened for blocking would hang: fail instead
    def boom(*_: Any) -> None:
        raise AssertionError("blocked")

    old = signal.signal(signal.SIGALRM, boom)
    # the alarm must exceed any subprocess timeout a test uses, so slow CI shows a real result
    signal.alarm(60 if request.node.get_closest_marker("long_alarm") else 20)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def fd_count() -> int:
    return len(os.listdir("/proc/self/fd"))


# --- creation and validation ---------------------------------------------------------------


def test_creates_the_directory_private_under_the_gateway_home(home: Path, trap: Path) -> None:
    with open_state(make_gateway(home)) as state:
        assert isinstance(state, StateDir)
    d = home / STATE_REL
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    assert list(trap.iterdir()) == []  # HOME and XDG_STATE_HOME are not read


@pytest.mark.parametrize("umask", [0o000, 0o077, 0o022])
def test_creation_mode_is_0700_whatever_the_umask(home: Path, umask: int) -> None:
    old = os.umask(umask)
    try:
        open_state(make_gateway(home)).close()
    finally:
        os.umask(old)
    assert stat.S_IMODE((home / STATE_REL).stat().st_mode) == 0o700


def test_an_existing_private_directory_is_reused(home: Path) -> None:
    open_state(make_gateway(home)).close()
    (home / STATE_REL / "keep").write_text("x")
    open_state(make_gateway(home)).close()
    assert (home / STATE_REL / "keep").read_text() == "x"


def test_a_failed_home_lookup_is_unusable_not_an_exception() -> None:
    g = FakeGateway(home=HomeLookupError("nope"))
    with pytest.raises(StateUnusable):
        open_state(g)


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o770, 0o701, 0o777])
def test_group_or_other_bits_are_refused_and_not_changed(home: Path, mode: int) -> None:
    d = home / STATE_REL
    d.mkdir(parents=True)
    d.chmod(mode)
    with pytest.raises(StateUnusable):
        open_state(make_gateway(home))
    assert stat.S_IMODE(d.stat().st_mode) == mode  # a foreign dir is never chmodded


def test_a_symlinked_final_component_is_refused(home: Path, tmp_path: Path) -> None:
    real = tmp_path / "elsewhere"
    real.mkdir(mode=0o700)
    d = home / STATE_REL
    d.parent.mkdir(parents=True)
    d.symlink_to(real)
    with pytest.raises(StateUnusable):
        open_state(make_gateway(home))
    assert list(real.iterdir()) == []


def test_a_dangling_symlink_is_refused_and_its_target_not_created(
    home: Path, tmp_path: Path
) -> None:
    d = home / STATE_REL
    d.parent.mkdir(parents=True)
    d.symlink_to(tmp_path / "nowhere")
    with pytest.raises(StateUnusable):
        open_state(make_gateway(home))
    assert not (tmp_path / "nowhere").exists()


def test_a_regular_file_in_its_place_is_refused(home: Path) -> None:
    d = home / STATE_REL
    d.parent.mkdir(parents=True)
    d.write_text("x")
    with pytest.raises(StateUnusable):
        open_state(make_gateway(home))


def test_a_file_in_place_of_an_intermediate_directory_is_refused(home: Path) -> None:
    (home / ".local").write_text("x")
    with pytest.raises(StateUnusable):
        open_state(make_gateway(home))


def test_a_wrong_owner_is_refused_by_the_injected_uid(home: Path) -> None:
    open_state(make_gateway(home)).close()
    with pytest.raises(StateUnusable):
        open_state(make_gateway(home, user_id=os.getuid() + 1))


@pytest.mark.skipif(os.getuid() == 0, reason="root ignores directory permissions")
def test_a_read_only_home_is_unusable(home: Path) -> None:
    home.chmod(0o500)
    try:
        with pytest.raises(StateUnusable):
            open_state(make_gateway(home))
    finally:
        home.chmod(0o700)
    assert not (home / ".local").exists()


@pytest.mark.skipif(os.getuid() == 0, reason="root ignores directory permissions")
def test_a_read_only_parent_with_no_state_directory_is_unusable(home: Path) -> None:
    parent = home / ".local" / "state"
    parent.mkdir(parents=True)
    parent.chmod(0o500)
    try:
        with pytest.raises(StateUnusable):
            open_state(make_gateway(home))
    finally:
        parent.chmod(0o700)


def test_created_directories_are_private_even_with_umask_zero(home: Path) -> None:
    old = os.umask(0)
    try:
        open_state(make_gateway(home)).close()
    finally:
        os.umask(old)
    for rel in (".local", ".local/state", ".local/state/ha-notice"):
        assert stat.S_IMODE((home / rel).stat().st_mode) & 0o077 == 0, rel


def test_existing_intermediate_directories_are_not_chmodded(home: Path) -> None:
    (home / ".local").mkdir(mode=0o755)
    (home / ".local").chmod(0o755)
    open_state(make_gateway(home)).close()
    assert stat.S_IMODE((home / ".local").stat().st_mode) == 0o755


@pytest.mark.skipif(os.getuid() == 0, reason="root ignores directory permissions")
def test_a_read_only_state_directory_opens_but_the_log_cannot_be_created(home: Path) -> None:
    d = home / STATE_REL
    d.mkdir(parents=True, mode=0o700)
    d.chmod(0o500)
    try:
        s = open_state(make_gateway(home))
        try:
            with pytest.raises(StateUnusable):
                s.open_file("log.jsonl")
        finally:
            s.close()
    finally:
        d.chmod(0o700)


def test_a_too_long_path_is_unusable(home: Path) -> None:
    long_home = str(home) + "/" + "a" * 300
    with pytest.raises(StateUnusable):
        open_state(FakeGateway(home=long_home))
    assert os.listdir(home) == []


def test_a_nul_in_the_home_is_unusable() -> None:
    with pytest.raises(StateUnusable):
        open_state(FakeGateway(home="/tmp/a\0b"))


def test_a_relative_home_is_unusable() -> None:
    with pytest.raises(StateUnusable):
        open_state(FakeGateway(home="relative/home"))


@pytest.mark.parametrize("err", [errno.ENOSPC, errno.EROFS, errno.EACCES, errno.ENAMETOOLONG])
def test_any_os_error_from_os_open_is_unusable(
    home: Path, monkeypatch: pytest.MonkeyPatch, err: int
) -> None:
    def failing(*_a: Any, **_k: Any) -> int:
        raise OSError(err, os.strerror(err))

    monkeypatch.setattr(gw.os, "open", failing)
    with pytest.raises(StateUnusable):
        open_state(make_gateway(home))


@pytest.mark.parametrize("err", [errno.ENOSPC, errno.EROFS, errno.EACCES])
def test_any_os_error_from_mkdir_is_unusable(
    home: Path, monkeypatch: pytest.MonkeyPatch, err: int
) -> None:
    (home / ".local" / "state").mkdir(parents=True)

    def failing(*_a: Any, **_k: Any) -> None:
        raise OSError(err, os.strerror(err))

    monkeypatch.setattr(gw.os, "mkdir", failing)
    with pytest.raises(StateUnusable):
        open_state(make_gateway(home))


def test_failures_leak_no_descriptors(home: Path) -> None:
    d = home / STATE_REL
    d.mkdir(parents=True)
    d.chmod(0o755)
    before = fd_count()
    for _ in range(5):
        with pytest.raises(StateUnusable):
            open_state(make_gateway(home))
    assert fd_count() == before


def test_success_close_releases_the_descriptor_and_is_idempotent(home: Path) -> None:
    before = fd_count()
    state = open_state(make_gateway(home))
    assert fd_count() == before + 1
    state.close()
    state.close()
    assert fd_count() == before


def test_the_exception_carries_no_path_or_detail(home: Path) -> None:
    d = home / STATE_REL
    d.mkdir(parents=True)
    d.chmod(0o755)
    with pytest.raises(StateUnusable) as exc:
        open_state(make_gateway(home))
    assert str(home) not in repr(exc.value) and str(exc.value) == ""
    assert exc.value.__cause__ is None and exc.value.__suppress_context__ is True


# --- files ---------------------------------------------------------------------------------


@pytest.fixture
def state(home: Path) -> Iterator[StateDir]:
    s = open_state(make_gateway(home))
    try:
        yield s
    finally:
        s.close()


def test_files_are_created_0600_whatever_the_umask(state: StateDir, home: Path) -> None:
    old = os.umask(0)
    try:
        fd = state.open_file("log.jsonl", append=True)
    finally:
        os.umask(old)
    try:
        os.write(fd, b"a\n")
        os.write(fd, b"b\n")
        assert (home / STATE_REL / "log.jsonl").read_bytes() == b"a\nb\n"
    finally:
        os.close(fd)
    assert stat.S_IMODE((home / STATE_REL / "log.jsonl").stat().st_mode) == 0o600


@pytest.mark.parametrize("name", ["log.jsonl", "log.lock", "log.jsonl.1", "log.jsonl.3"])
def test_a_fifo_is_unusable_and_returns_at_once(state: StateDir, home: Path, name: str) -> None:
    os.mkfifo(home / STATE_REL / name)
    before = fd_count()
    with pytest.raises(StateUnusable):
        state.open_file(name, append=True)
    assert fd_count() == before


@pytest.mark.parametrize("name", ["log.jsonl", "log.lock"])
def test_a_symlink_is_unusable_and_its_target_untouched(
    state: StateDir, home: Path, tmp_path: Path, name: str
) -> None:
    target = tmp_path / "target"
    target.write_text("x")
    (home / STATE_REL / name).symlink_to(target)
    with pytest.raises(StateUnusable):
        state.open_file(name)
    assert target.read_text() == "x"


def test_a_dangling_symlink_does_not_create_its_target(
    state: StateDir, home: Path, tmp_path: Path
) -> None:
    (home / STATE_REL / "log.jsonl").symlink_to(tmp_path / "created")
    with pytest.raises(StateUnusable):
        state.open_file("log.jsonl", append=True)
    assert not (tmp_path / "created").exists()


def test_a_directory_named_like_a_log_file_is_unusable(state: StateDir, home: Path) -> None:
    (home / STATE_REL / "log.jsonl").mkdir()
    with pytest.raises(StateUnusable):
        state.open_file("log.jsonl", append=True)


def test_a_device_node_symlink_is_unusable(state: StateDir, home: Path) -> None:
    (home / STATE_REL / "log.lock").symlink_to("/dev/null")
    with pytest.raises(StateUnusable):
        state.open_file("log.lock")


@pytest.mark.parametrize("name", ["", "a/b", "../x", ".", "..", "a\0b"])
def test_names_must_be_plain_and_a_bad_name_is_unusable_not_a_value_error(
    state: StateDir, name: str
) -> None:
    with pytest.raises(StateUnusable):
        state.open_file(name)


def test_a_swap_to_a_symlink_after_the_directory_check_is_not_followed(
    state: StateDir, home: Path, tmp_path: Path
) -> None:
    # The directory is held by descriptor: replacing the path afterwards changes nothing.
    d = home / STATE_REL
    moved = tmp_path / "moved"
    d.rename(moved)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    d.symlink_to(attacker)
    fd = state.open_file("log.jsonl", append=True)
    os.close(fd)
    assert (moved / "log.jsonl").exists() and list(attacker.iterdir()) == []


def test_lock_and_rename_helpers_map_to_unusable(state: StateDir, home: Path) -> None:
    a = state.open_file("log.lock")
    b = state.open_file("log.lock")
    try:
        assert state.try_lock(a) is True
        assert state.try_lock(b) is False
    finally:
        os.close(a)
        os.close(b)
    log = state.open_file("log.jsonl", append=True)
    os.close(log)
    state.rename("log.jsonl", "log.jsonl.1")
    assert (home / STATE_REL / "log.jsonl.1").exists()
    with pytest.raises(StateUnusable):
        state.rename("absent", "other")


def test_write_failure_is_unusable(state: StateDir, home: Path) -> None:
    fd = os.open(home / STATE_REL / "log.jsonl", os.O_RDONLY | os.O_CREAT, 0o600)
    try:
        with pytest.raises(StateUnusable):
            state.write(fd, b"x")  # not open for writing
    finally:
        os.close(fd)


# --- the warning ---------------------------------------------------------------------------


def test_the_warning_is_one_fixed_line_without_a_path(home: Path) -> None:
    assert STATE_WARNING == "warning: log record skipped (state directory unusable)"
    buf = io.StringIO()
    w = StateWarner(buf)
    w.warn()
    w.warn()
    w.warn()
    assert buf.getvalue() == STATE_WARNING + "\n"
    assert "/" not in STATE_WARNING


def test_the_warner_survives_a_broken_stream() -> None:
    class Broken(io.StringIO):
        def write(self, s: str) -> int:
            raise BrokenPipeError

    StateWarner(Broken()).warn()


# --- concurrent creation ---------------------------------------------------------------------

_RACER = textwrap.dedent(
    """
    import os, sys, time
    from ha_notice.gateway import RealGateway
    from ha_notice.state import open_state
    from ha_notice.gateway import HomeLookupError

    class G(RealGateway):
        def home_dir(self):
            return sys.argv[1]

    go = sys.argv[2]
    while not os.path.exists(go):
        time.sleep(0.001)
    s = open_state(G())
    s.close()
    """
)


@pytest.mark.long_alarm
def test_concurrent_creation_by_several_processes_all_succeed(home: Path, tmp_path: Path) -> None:
    go = tmp_path / "go"
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path / "trap")}
    procs = [
        subprocess.Popen(
            [sys.executable, "-I", "-c", _RACER, str(home), str(go)],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(8)
    ]
    try:
        go.write_text("")
        results = [p.communicate(timeout=30) + (p.returncode,) for p in procs]
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()  # only the PIDs this test started
                p.wait()
    assert [r[2] for r in results] == [0] * 8, results
    assert stat.S_IMODE((home / STATE_REL).stat().st_mode) == 0o700


# --- gateway fidelity ----------------------------------------------------------------------


def test_the_fake_honours_the_injected_uid_like_the_real_one(home: Path) -> None:
    class Other(RealGateway):
        def uid(self) -> int:
            return os.getuid() + 1

    open_state_dir_ok = make_gateway(home).open_state_dir(str(home))
    os.close(open_state_dir_ok)
    with pytest.raises(gw.StateDirError):
        Other().open_state_dir(str(home))
    with pytest.raises(gw.StateDirError):
        make_gateway(home, user_id=os.getuid() + 1).open_state_dir(str(home))
