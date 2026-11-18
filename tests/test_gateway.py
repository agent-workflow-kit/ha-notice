"""The real gateway: identity, clock, input sources, state directory, CA and TLS (issue #3)."""

from __future__ import annotations

import os
import pwd
import ssl
import stat
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from ha_notice import gateway as gw
from ha_notice.gateway import (
    HomeLookupError,
    RealGateway,
    SourceError,
    StateDirError,
)


@pytest.fixture
def real() -> RealGateway:
    return RealGateway()


def never_expires() -> float:
    return 60.0


# --- identity -------------------------------------------------------------------------------


def _pwd_entry(name: str = "someone", home: str = "") -> pwd.struct_passwd:
    return pwd.struct_passwd((name, "x", 4242, 4242, "", home, "/bin/sh"))


def test_home_dir_comes_from_the_password_database_not_the_environment(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pw_home = tmp_path / "pwhome"
    pw_home.mkdir()
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    monkeypatch.setattr(gw.pwd, "getpwuid", lambda uid: _pwd_entry(home=str(pw_home)))
    monkeypatch.setenv("HOME", str(hostile))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(hostile))
    monkeypatch.setenv("XDG_STATE_HOME", str(hostile))
    assert real.home_dir() == str(pw_home)


def test_home_dir_works_with_home_unset(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(gw.pwd, "getpwuid", lambda uid: _pwd_entry(home=str(tmp_path)))
    monkeypatch.delenv("HOME", raising=False)
    assert real.home_dir() == str(tmp_path)


def test_home_dir_asks_for_the_real_uid(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asked: list[int] = []

    def fake(uid: int) -> pwd.struct_passwd:
        asked.append(uid)
        return _pwd_entry(home=str(tmp_path))

    monkeypatch.setattr(gw.pwd, "getpwuid", fake)
    real.home_dir()
    assert asked == [os.getuid()]


def test_home_dir_fails_when_the_lookup_fails(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def missing(uid: int) -> pwd.struct_passwd:
        raise KeyError(uid)

    monkeypatch.setattr(gw.pwd, "getpwuid", missing)
    monkeypatch.setenv("HOME", str(tmp_path))  # no fallback to HOME
    with pytest.raises(HomeLookupError):
        real.home_dir()


@pytest.mark.parametrize("home", ["", "relative/dir", "~", "/definitely/not/a/dir-xyz"])
def test_home_dir_refuses_empty_relative_or_missing(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch, home: str
) -> None:
    monkeypatch.setattr(gw.pwd, "getpwuid", lambda uid: _pwd_entry(home=home))
    with pytest.raises(HomeLookupError):
        real.home_dir()


def test_home_dir_refuses_a_file(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    f = tmp_path / "file"
    f.write_text("x")
    monkeypatch.setattr(gw.pwd, "getpwuid", lambda uid: _pwd_entry(home=str(f)))
    with pytest.raises(HomeLookupError):
        real.home_dir()


def test_home_lookup_error_message_has_no_path(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gw.pwd, "getpwuid", lambda uid: _pwd_entry(home="/secret/where"))
    with pytest.raises(HomeLookupError) as exc:
        real.home_dir()
    assert "/secret" not in str(exc.value)


def test_uid_is_the_real_uid(real: RealGateway) -> None:
    assert real.uid() == os.getuid()


def test_login_name_from_the_password_database(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gw.pwd, "getpwuid", lambda uid: _pwd_entry(name="alice"))
    monkeypatch.setenv("USER", "mallory")
    monkeypatch.setenv("LOGNAME", "mallory")
    assert real.login_name() == "alice"


def test_login_name_is_none_when_the_lookup_fails(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing(uid: int) -> pwd.struct_passwd:
        raise KeyError(uid)

    monkeypatch.setattr(gw.pwd, "getpwuid", missing)
    assert real.login_name() is None


# --- clock ----------------------------------------------------------------------------------


def test_monotonic_never_goes_backwards(real: RealGateway) -> None:
    samples = [real.monotonic() for _ in range(100)]
    assert samples == sorted(samples)


def test_monotonic_is_the_time_module_monotonic(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gw.time, "monotonic", lambda: 123.5)
    assert real.monotonic() == 123.5


def test_wall_time_is_the_time_module_time(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gw.time, "time", lambda: 1.5)
    assert real.wall_time() == 1.5


def test_sleep_sleeps_and_ignores_non_positive(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    slept: list[float] = []
    monkeypatch.setattr(gw.time, "sleep", slept.append)
    real.sleep(2.0)
    real.sleep(0.0)
    real.sleep(-1.0)
    assert slept == [2.0]


# --- input sources --------------------------------------------------------------------------


def test_read_source_reads_a_regular_file(real: RealGateway, tmp_path: Path) -> None:
    f = tmp_path / "in.json"
    f.write_bytes(b'{"message":"hi"}')
    r = real.read_source(str(f), 1000, never_expires)
    assert (r.data, r.status) == (b'{"message":"hi"}', "ok")


def test_read_source_empty_file_is_ok_and_empty(real: RealGateway, tmp_path: Path) -> None:
    f = tmp_path / "empty"
    f.write_bytes(b"")
    r = real.read_source(str(f), 1000, never_expires)
    assert (r.data, r.status) == (b"", "ok")


def test_read_source_exactly_max_bytes_is_ok(real: RealGateway, tmp_path: Path) -> None:
    f = tmp_path / "exact"
    f.write_bytes(b"a" * 100)
    r = real.read_source(str(f), 100, never_expires)
    assert (len(r.data), r.status) == (100, "ok")


def test_read_source_one_byte_over_max_is_too_large(real: RealGateway, tmp_path: Path) -> None:
    f = tmp_path / "over"
    f.write_bytes(b"a" * 101)
    r = real.read_source(str(f), 100, never_expires)
    assert (len(r.data), r.status) == (100, "too_large")


def test_read_source_reads_a_file_larger_than_one_chunk(real: RealGateway, tmp_path: Path) -> None:
    f = tmp_path / "big"
    payload = os.urandom(3 * gw.FILE_CHUNK + 17)
    f.write_bytes(payload)
    r = real.read_source(str(f), 10_000_000, never_expires)
    assert (r.data, r.status) == (payload, "ok")


def test_read_source_follows_a_symlink_to_a_regular_file(real: RealGateway, tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"ok")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert real.read_source(str(link), 10, never_expires).data == b"ok"


def test_read_source_missing_file_raises_source_error(real: RealGateway, tmp_path: Path) -> None:
    with pytest.raises(SourceError):
        real.read_source(str(tmp_path / "nope"), 10, never_expires)


def test_read_source_directory_raises_source_error(real: RealGateway, tmp_path: Path) -> None:
    with pytest.raises(SourceError):
        real.read_source(str(tmp_path), 10, never_expires)


def test_read_source_fifo_path_raises_at_once(real: RealGateway, tmp_path: Path) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    started = time.monotonic()
    with pytest.raises(SourceError):
        real.read_source(str(fifo), 10, never_expires)
    assert time.monotonic() - started < 2


def test_read_source_dev_zero_raises(real: RealGateway) -> None:
    with pytest.raises(SourceError):
        real.read_source("/dev/zero", 10, never_expires)


def test_source_error_message_has_no_path(real: RealGateway, tmp_path: Path) -> None:
    secret = tmp_path / "secret-name"
    with pytest.raises(SourceError) as exc:
        real.read_source(str(secret), 10, never_expires)
    assert "secret-name" not in str(exc.value)


@pytest.fixture
def pipe() -> Iterator[tuple[int, int]]:
    r, w = os.pipe()
    try:
        yield r, w
    finally:
        for fd in (r, w):
            try:
                os.close(fd)
            except OSError:
                pass


def test_read_source_fd_reads_until_eof(real: RealGateway) -> None:
    r, w = os.pipe()
    os.write(w, b"hello")
    os.close(w)
    try:
        res = real.read_source(r, 100, never_expires)
    finally:
        os.close(r)
    assert (res.data, res.status) == (b"hello", "ok")


def test_read_source_fd_stall_times_out_with_what_arrived(
    real: RealGateway, pipe: tuple[int, int]
) -> None:
    r, w = pipe
    os.write(w, b"0123456789")  # ten bytes, then the producer stalls
    start = time.monotonic()
    res = real.read_source(r, 100, lambda: 0.3 - (time.monotonic() - start))
    elapsed = time.monotonic() - start
    assert (res.data, res.status) == (b"0123456789", "timeout")
    assert 0.25 <= elapsed < 1.5


def test_read_source_notices_the_deadline_within_a_slice(
    real: RealGateway, pipe: tuple[int, int]
) -> None:
    r, _w = pipe
    calls = 0

    def remaining() -> float:
        nonlocal calls
        calls += 1
        return 1.0 if calls < 3 else 0.0

    start = time.monotonic()
    res = real.read_source(r, 100, remaining)
    assert res.status == "timeout"
    assert time.monotonic() - start < 0.1 * 2 + 0.5


def test_read_source_already_expired_is_a_timeout(real: RealGateway, pipe: tuple[int, int]) -> None:
    r, _w = pipe
    assert real.read_source(r, 100, lambda: 0.0).status == "timeout"


def test_read_source_fd_over_the_cap_is_too_large(real: RealGateway) -> None:
    r, w = os.pipe()
    os.write(w, b"x" * 50)
    os.close(w)
    try:
        res = real.read_source(r, 10, never_expires)
    finally:
        os.close(r)
    assert (len(res.data), res.status) == (10, "too_large")


def test_read_source_closed_fd_is_empty_input(real: RealGateway) -> None:
    r, w = os.pipe()
    os.close(r)
    os.close(w)
    res = real.read_source(r, 10, never_expires)
    assert (res.data, res.status) == (b"", "ok")


def test_read_source_does_not_close_a_borrowed_fd(real: RealGateway) -> None:
    r, w = os.pipe()
    os.close(w)
    try:
        real.read_source(r, 10, never_expires)
        os.fstat(r)  # still open
    finally:
        os.close(r)


def test_read_source_leaves_no_descriptor_behind_for_a_path(
    real: RealGateway, tmp_path: Path
) -> None:
    f = tmp_path / "f"
    f.write_bytes(b"x")
    before = set(os.listdir("/proc/self/fd"))
    for _ in range(20):
        real.read_source(str(f), 10, never_expires)
    with pytest.raises(SourceError):
        real.read_source(str(tmp_path), 10, never_expires)
    assert set(os.listdir("/proc/self/fd")) == before


def test_isatty(real: RealGateway, pipe: tuple[int, int]) -> None:
    assert real.isatty(pipe[0]) is False
    assert real.isatty(987654) is False  # not open: not a terminal, no exception
    master, slave = os.openpty()
    try:
        assert real.isatty(slave) is True
    finally:
        os.close(master)
        os.close(slave)


# --- state directory ------------------------------------------------------------------------


def mode(path: Path | str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_state_dir_is_created_private_under_the_given_home(
    real: RealGateway, tmp_path: Path
) -> None:
    fd = real.open_state_dir(str(tmp_path))
    try:
        d = tmp_path / ".local" / "state" / "ha-notice"
        assert d.is_dir()
        assert mode(d) == 0o700
        assert os.fstat(fd).st_ino == d.stat().st_ino
    finally:
        real.close_fd(fd)


def test_state_dir_is_reopened_when_it_exists(real: RealGateway, tmp_path: Path) -> None:
    real.close_fd(real.open_state_dir(str(tmp_path)))
    real.close_fd(real.open_state_dir(str(tmp_path)))


def test_state_dir_ignores_xdg_state_home(
    real: RealGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setenv("XDG_STATE_HOME", str(other))
    home = tmp_path / "home"
    home.mkdir()
    real.close_fd(real.open_state_dir(str(home)))
    assert not (other / "ha-notice").exists()
    assert (home / ".local" / "state" / "ha-notice").is_dir()


def test_state_dir_rejects_a_symlinked_directory(real: RealGateway, tmp_path: Path) -> None:
    parent = tmp_path / ".local" / "state"
    parent.mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (parent / "ha-notice").symlink_to(elsewhere)
    with pytest.raises(StateDirError):
        real.open_state_dir(str(tmp_path))


@pytest.mark.parametrize("bad_mode", [0o755, 0o750, 0o770, 0o701, 0o707])
def test_state_dir_rejects_group_or_other_permissions(
    real: RealGateway, tmp_path: Path, bad_mode: int
) -> None:
    d = tmp_path / ".local" / "state" / "ha-notice"
    d.mkdir(parents=True)
    d.chmod(bad_mode)
    with pytest.raises(StateDirError):
        real.open_state_dir(str(tmp_path))


def test_state_dir_rejects_a_regular_file_in_its_place(real: RealGateway, tmp_path: Path) -> None:
    parent = tmp_path / ".local" / "state"
    parent.mkdir(parents=True)
    (parent / "ha-notice").write_text("x")
    with pytest.raises(StateDirError):
        real.open_state_dir(str(tmp_path))


def test_state_dir_fails_cleanly_when_home_is_unwritable(real: RealGateway, tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores directory modes")
    home = tmp_path / "ro"
    home.mkdir()
    home.chmod(0o500)
    try:
        with pytest.raises(StateDirError):
            real.open_state_dir(str(home))
    finally:
        home.chmod(0o700)


def test_state_dir_does_not_leak_descriptors_on_failure(real: RealGateway, tmp_path: Path) -> None:
    d = tmp_path / ".local" / "state" / "ha-notice"
    d.mkdir(parents=True)
    d.chmod(0o755)
    before = set(os.listdir("/proc/self/fd"))
    for _ in range(10):
        with pytest.raises(StateDirError):
            real.open_state_dir(str(tmp_path))
    assert set(os.listdir("/proc/self/fd")) == before


@pytest.fixture
def state(real: RealGateway, tmp_path: Path) -> Iterator[tuple[int, Path]]:
    fd = real.open_state_dir(str(tmp_path))
    try:
        yield fd, tmp_path / ".local" / "state" / "ha-notice"
    finally:
        real.close_fd(fd)


def test_state_file_is_created_0600_and_appends(real: RealGateway, state: tuple[int, Path]) -> None:
    dir_fd, d = state
    for chunk in (b"one\n", b"two\n"):
        fd = real.open_state_file(dir_fd, "log.jsonl", append=True)
        try:
            assert real.write_fd(fd, chunk) == len(chunk)
        finally:
            real.close_fd(fd)
    assert (d / "log.jsonl").read_bytes() == b"one\ntwo\n"
    assert mode(d / "log.jsonl") == 0o600


def test_state_file_rejects_a_fifo_without_blocking(
    real: RealGateway, state: tuple[int, Path]
) -> None:
    dir_fd, d = state
    os.mkfifo(d / "log.jsonl")
    started = time.monotonic()
    with pytest.raises(StateDirError):
        real.open_state_file(dir_fd, "log.jsonl", append=True)
    assert time.monotonic() - started < 2


def test_state_file_rejects_a_symlink(real: RealGateway, state: tuple[int, Path]) -> None:
    dir_fd, d = state
    target = d.parent / "target"
    target.write_text("x")
    (d / "log.lock").symlink_to(target)
    with pytest.raises(StateDirError):
        real.open_state_file(dir_fd, "log.lock")
    assert target.read_text() == "x"


def test_state_file_rejects_a_device(real: RealGateway, state: tuple[int, Path]) -> None:
    dir_fd, d = state
    (d / "log.lock").symlink_to("/dev/null")  # a symlink to a device is also refused
    with pytest.raises(StateDirError):
        real.open_state_file(dir_fd, "log.lock")


@pytest.mark.parametrize("name", ["", "a/b", "../x", ".", ".."])
def test_state_file_names_must_be_plain(
    real: RealGateway, state: tuple[int, Path], name: str
) -> None:
    with pytest.raises(ValueError):
        real.open_state_file(state[0], name)


def test_try_lock_is_exclusive_between_descriptors(
    real: RealGateway, state: tuple[int, Path]
) -> None:
    dir_fd, _ = state
    a = real.open_state_file(dir_fd, "log.lock")
    b = real.open_state_file(dir_fd, "log.lock")
    try:
        assert real.try_lock(a) is True
        assert real.try_lock(b) is False
        real.close_fd(a)
        assert real.try_lock(b) is True
    finally:
        real.close_fd(b)


def test_rename_state_file_rotates(real: RealGateway, state: tuple[int, Path]) -> None:
    dir_fd, d = state
    fd = real.open_state_file(dir_fd, "log.jsonl", append=True)
    real.write_fd(fd, b"x")
    real.close_fd(fd)
    real.rename_state_file(dir_fd, "log.jsonl", "log.jsonl.1")
    assert (d / "log.jsonl.1").read_bytes() == b"x"
    assert not (d / "log.jsonl").exists()


def test_rename_missing_source_is_a_state_error(real: RealGateway, state: tuple[int, Path]) -> None:
    with pytest.raises(StateDirError):
        real.rename_state_file(state[0], "absent", "other")


def test_rename_missing_source_is_skipped_with_missing_ok(
    real: RealGateway, state: tuple[int, Path]
) -> None:
    dir_fd, d = state
    real.rename_state_file(dir_fd, "absent", "other", missing_ok=True)
    assert not (d / "other").exists()


def test_rename_missing_ok_still_fails_on_other_errors(
    real: RealGateway, state: tuple[int, Path]
) -> None:
    dir_fd, d = state
    (d / "src").write_text("x")
    (d / "dst").mkdir()
    (d / "dst" / "child").write_text("y")  # a non-empty directory cannot be replaced
    with pytest.raises(StateDirError):
        real.rename_state_file(dir_fd, "src", "dst", missing_ok=True)


def test_state_file_size_follows_appends(real: RealGateway, state: tuple[int, Path]) -> None:
    dir_fd, _ = state
    fd = real.open_state_file(dir_fd, "log.jsonl", append=True)
    try:
        assert real.state_file_size(fd) == 0
        real.write_fd(fd, b"abc\n")
        assert real.state_file_size(fd) == 4
    finally:
        real.close_fd(fd)


def test_state_file_size_of_a_closed_descriptor_is_a_state_error(
    real: RealGateway, state: tuple[int, Path]
) -> None:
    fd = real.open_state_file(state[0], "log.jsonl", append=True)
    real.close_fd(fd)
    with pytest.raises(StateDirError):
        real.state_file_size(fd)


@pytest.mark.parametrize("src,dst", [("a/b", "c"), ("a", "../c"), ("", "c")])
def test_rename_names_must_be_plain(
    real: RealGateway, state: tuple[int, Path], src: str, dst: str
) -> None:
    with pytest.raises(ValueError):
        real.rename_state_file(state[0], src, dst)


# --- CA candidates and TLS context ----------------------------------------------------------


def test_ca_candidates_are_the_compiled_paths_not_the_environment(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_ca = tmp_path / "evil.pem"
    fake_ca.write_text("not a cert")
    compiled = ssl.get_default_verify_paths()
    expected = (compiled.openssl_cafile, compiled.openssl_capath)
    monkeypatch.setenv("SSL_CERT_FILE", str(fake_ca))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    got = real.ca_candidates()
    assert (got.cafile, got.capath) == expected
    assert str(fake_ca) != got.cafile
    assert got.fallback_files == (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    )


def test_tls_context_is_strict(real: RealGateway) -> None:
    ctx = real.new_tls_context([])
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert ctx.protocol == ssl.PROTOCOL_TLS_CLIENT


def test_tls_context_loads_nothing_from_the_environment(
    real: RealGateway, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bogus = tmp_path / "bogus.pem"
    bogus.write_text("garbage")
    monkeypatch.setenv("SSL_CERT_FILE", str(bogus))  # would raise if it were read
    ctx = real.new_tls_context([])
    assert ctx.cert_store_stats() == {"x509": 0, "crl": 0, "x509_ca": 0}


def test_tls_context_with_a_missing_file_raises_a_fixed_gateway_error(
    real: RealGateway, tmp_path: Path
) -> None:
    path = str(tmp_path / "missing-secret-name.pem")
    with pytest.raises(gw.GatewayError) as exc:
        real.new_tls_context([path])
    assert_no_text(exc.value, path, "missing-secret-name")


def test_tls_context_with_an_unparsable_file_raises_a_fixed_gateway_error(
    real: RealGateway, tmp_path: Path
) -> None:
    f = tmp_path / "junk-secret-name.pem"
    f.write_text("junk")
    with pytest.raises(gw.GatewayError) as exc:
        real.new_tls_context([str(f)])
    assert_no_text(exc.value, str(f), "junk-secret-name")


def assert_no_text(exc: BaseException, *texts: str) -> None:
    shown = f"{exc!s} {exc!r} {exc.args!r}"
    for text in texts:
        assert text not in shown
    assert exc.__context__ is None


# --- process --------------------------------------------------------------------------------


def test_exit_process_calls_os_exit(real: RealGateway, monkeypatch: pytest.MonkeyPatch) -> None:
    class Stop(Exception):
        pass

    codes: list[int] = []

    def fake_exit(code: int) -> None:
        codes.append(code)
        raise Stop

    monkeypatch.setattr(gw.os, "_exit", fake_exit)
    with pytest.raises(Stop):
        real.exit_process(7)
    assert codes == [7]


# --- review round 1 ---------------------------------------------------------------------------


def test_read_source_works_for_a_descriptor_above_1024(real: RealGateway) -> None:
    import fcntl
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < 1300:
        pytest.skip("descriptor limit too low")
    if soft != resource.RLIM_INFINITY and soft < 1300:
        resource.setrlimit(resource.RLIMIT_NOFILE, (1300, hard))
    r, w = os.pipe()
    high = fcntl.fcntl(r, fcntl.F_DUPFD, 1100)
    try:
        os.write(w, b"abc")
        os.close(w)
        res = real.read_source(high, 10, never_expires)
        assert (res.data, res.status) == (b"abc", "ok")
    finally:
        os.close(r)
        os.close(high)


def test_read_source_closed_descriptor_above_1024_is_empty_input(real: RealGateway) -> None:
    import fcntl
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < 1300:
        pytest.skip("descriptor limit too low")
    if soft != resource.RLIM_INFINITY and soft < 1300:
        resource.setrlimit(resource.RLIMIT_NOFILE, (1300, hard))
    r, w = os.pipe()
    high = fcntl.fcntl(r, fcntl.F_DUPFD, 1100)
    os.close(high)
    os.close(r)
    os.close(w)
    res = real.read_source(high, 10, never_expires)
    assert (res.data, res.status) == (b"", "ok")


def test_read_source_negative_descriptor_is_not_swallowed(real: RealGateway) -> None:
    with pytest.raises(ValueError):
        real.read_source(-1, 10, never_expires)


def test_read_source_error_after_data_is_a_source_error(
    real: RealGateway, pipe: tuple[int, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    r, w = pipe
    os.write(w, b"abc")
    os.close(w)  # the next poll reports hang-up, so the second read happens
    calls: list[int] = []
    real_read = os.read

    def flaky(fd: int, n: int) -> bytes:
        if fd != r:
            return real_read(fd, n)
        calls.append(n)
        if len(calls) == 1:
            return real_read(fd, n)
        raise OSError(5, "io error")

    monkeypatch.setattr(gw.os, "read", flaky)
    with pytest.raises(SourceError) as exc:
        real.read_source(r, 10, never_expires)
    assert_no_text(exc.value, "io error")


def test_read_source_error_before_any_data_is_a_source_error_unless_ebadf(
    real: RealGateway, pipe: tuple[int, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    r, w = pipe
    os.write(w, b"x")

    def failing(fd: int, n: int) -> bytes:
        raise OSError(5, "io error")

    monkeypatch.setattr(gw.os, "read", failing)
    with pytest.raises(SourceError):
        real.read_source(r, 10, never_expires)


def test_state_dir_uses_the_gateways_uid(tmp_path: Path) -> None:
    class Other(RealGateway):
        def uid(self) -> int:
            return os.getuid() + 1

    with pytest.raises(StateDirError):
        Other().open_state_dir(str(tmp_path))


def test_state_dir_uses_the_gateways_uid_and_accepts_a_match(tmp_path: Path) -> None:
    seen: list[int] = []

    class Same(RealGateway):
        def uid(self) -> int:
            seen.append(1)
            return os.getuid()

    g = Same()
    fd = g.open_state_dir(str(tmp_path))
    g.close_fd(fd)
    assert seen


@pytest.mark.parametrize("home", ["", "relh", "./relh"])
def test_state_dir_refuses_a_home_that_is_not_absolute(
    real: RealGateway, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, home: str
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(StateDirError):
        real.open_state_dir(home)
    assert list(tmp_path.iterdir()) == []
