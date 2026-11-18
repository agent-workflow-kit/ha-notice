"""Input reading limits and the hardened JSON parse (issue #12)."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from ha_notice import gateway as gw
from ha_notice import payload
from ha_notice.payload import (
    INPUT_MAX,
    InputTimeout,
    Notification,
    PayloadError,
    hardened_loads,
    input_timeout_error,
    parse_notification,
    read_notification,
)
from tests.fake_gateway import FakeGateway, StallingSource
from tests.harness import schema_errors

DEADLINE = 10.0


def fake_remaining(fake: FakeGateway, seconds: float = DEADLINE):
    end = fake.monotonic() + seconds
    return lambda: end - fake.monotonic()


def refused_pointer(data: bytes) -> str | None:
    with pytest.raises(PayloadError) as info:
        parse_notification(data)
    err = info.value
    assert err.reason == "invalid_payload"
    assert err.to_error().exit_code == 20
    assert schema_errors("cli/error", err.to_error().envelope) == []
    return err.pointer


# --- the parse: accepted ---------------------------------------------------------------------


def test_valid_object_is_validated() -> None:
    got = parse_notification(b'{"message": "hi", "level": "warn", "title": "t"}')
    assert got == Notification(message="hi", level="warn", title="t")


def test_json_whitespace_and_escapes_accepted() -> None:
    assert parse_notification(b' \t\r\n{"message":"a\\u00e9\\n"}\n').message == "a\u00e9\n"


def test_non_ascii_utf8_accepted() -> None:
    assert parse_notification('{"message":"\u00e9\U0001f600"}'.encode()).message == "\u00e9\U0001f600"


# --- the parse: every refusal is invalid_payload with pointer "" ------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"   ",
        b"[]",
        b"null",
        b'"x"',
        b"1",
        b"true",
        b"{",
        b'{"message":"a"} x',
        b'{"message":"a"}{"message":"b"}',
        b"\xef\xbb\xbf" + b'{"message":"a"}',
        b"\xef\xbb\xbf",
        b'{"message":"a\xff"}',
        b'{"message":"\xed\xa0\x80"}',  # an encoded surrogate is not UTF-8
        b'{"message":"\xc0\x80"}',  # overlong NUL
        b'{"message":"a"\x00}',
        b'{"message":"a\x00"}',  # raw control character in a string
        b'{"message":"a","message":"b"}',
        b'{"a":1,"a":2}',
        b'{"message":NaN}',
        b'{"message":Infinity}',
        b'{"message":-Infinity}',
        b'{"message":1e999}',
        b'{"message":-1e999}',
        b"{'message':'a'}",
        b'{"message":"a",}',
        b'{"message":"\\x"}',
    ],
)
def test_parse_refusals_have_empty_pointer(data: bytes) -> None:
    assert refused_pointer(data) == ""


def test_duplicate_key_is_refused_even_when_values_are_equal() -> None:
    assert refused_pointer(b'{"message":"a","message":"a"}') == ""


def test_duplicate_key_in_a_nested_object_is_refused() -> None:
    assert refused_pointer(b'{"message":"a","x":{"k":1,"k":1}}') == ""


def test_duplicate_key_with_escaped_spelling_is_refused() -> None:
    assert refused_pointer(b'{"message":"a","\\u006dessage":"b"}') == ""


def test_big_integer_is_refused_with_empty_pointer() -> None:
    assert refused_pointer(b'{"message":' + b"9" * 5000 + b"}") == ""


def test_big_integer_is_refused_even_when_the_interpreter_limit_is_off() -> None:
    # PYTHONINTMAXSTRDIGITS=0 would remove the interpreter's limit: the parse has its own.
    import sys

    old = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        started = time.monotonic()
        assert refused_pointer(b'{"message":' + b"9" * 200000 + b"}") == ""
        assert time.monotonic() - started < 2
    finally:
        sys.set_int_max_str_digits(old)


def test_moderate_integer_is_a_type_error_not_a_parse_error() -> None:
    err = pytest.raises(PayloadError, parse_notification, b'{"message":' + b"9" * 4000 + b"}")
    assert err.value.pointer == "/message"


def test_deep_nesting_is_refused_without_recursion_error() -> None:
    assert refused_pointer(b"[" * 100000 + b"]" * 100000) == ""
    assert refused_pointer(b'{"message":' + b"[" * 100000) == ""
    assert refused_pointer(b'{"a":' * 100000 + b"1" + b"}" * 100000) == ""


def test_one_mebibyte_of_open_brackets_is_refused() -> None:
    assert refused_pointer(b"[" * INPUT_MAX) == ""


def test_recursion_error_and_overflow_error_map_to_empty_pointer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for exc in (RecursionError, OverflowError, ValueError):

        def boom(*_a: object, **_k: object) -> object:
            raise exc("secret-input-text")

        monkeypatch.setattr(payload.json.JSONDecoder, "decode", boom)
        with pytest.raises(PayloadError) as info:
            parse_notification(b'{"message":"a"}')
        assert info.value.pointer == ""
        assert "secret" not in repr(info.value.to_error())
        assert info.value.__cause__ is None
        assert info.value.__suppress_context__ or info.value.__context__ is None


def test_non_object_with_valid_json_has_empty_pointer() -> None:
    for data in (b"[]", b"null", b'"x"', b"0", b"[1]"):
        assert refused_pointer(data) == ""


def test_empty_object_is_empty_message_not_a_parse_error() -> None:
    with pytest.raises(PayloadError) as info:
        parse_notification(b"{}")
    assert info.value.reason == "empty_message"
    with pytest.raises(PayloadError) as info:
        parse_notification(b'{"title":"x"}')
    assert info.value.reason == "empty_message"


def test_long_key_has_question_mark_pointer() -> None:
    data = b'{"message":"a","' + b"k" * 5000 + b'":1}'
    with pytest.raises(PayloadError) as info:
        parse_notification(data)
    assert info.value.pointer == "/?"


def test_refusals_never_echo_input() -> None:
    marker = "SECRET.MARKER"  # not a valid field name, so never a pointer
    for data in (
        f'{{"message":"a","{marker}":1}}'.encode(),
        f'{{"{marker}":1,"{marker}":2}}'.encode(),
        f'{{"message":"{marker}\\x"}}'.encode(),
        f"[{marker}]".encode(),
        f'{{"message":"a","level":"{marker}"}}'.encode(),
    ):
        with pytest.raises(PayloadError) as info:
            parse_notification(data)
        text = json.dumps(info.value.to_error().envelope) + repr(info.value) + str(info.value)
        assert marker not in text


def test_hardened_loads_accepts_plain_json_and_raises_value_error() -> None:
    assert hardened_loads('{"a": [1, 2.5, "x", null, true]}') == {"a": [1, 2.5, "x", None, True]}
    for bad in ("", "NaN", '{"a":1,"a":2}', "[" * 100000, "9" * 5000, "1e999", "\ufeff{}"):
        with pytest.raises(ValueError):
            hardened_loads(bad)


# --- the size cap ------------------------------------------------------------------------------


def padded(size: int) -> bytes:
    head = b'{"message":"a","title":"'
    tail = b'"}'
    return head + b"x" * (size - len(head) - len(tail)) + tail


def test_input_max_is_one_mebibyte() -> None:
    assert INPUT_MAX == 1048576


def test_cap_boundary_through_the_gateway() -> None:
    fake = FakeGateway()
    fake.sources[0] = padded(INPUT_MAX)
    # Within the cap the bytes are read; the text limit of the title (#11) then refuses them.
    with pytest.raises(PayloadError) as info:
        read_notification(fake, 0, fake_remaining(fake))
    assert info.value.pointer == "/title"
    fake.sources[0] = padded(INPUT_MAX + 1)
    with pytest.raises(PayloadError) as info:
        read_notification(fake, 0, fake_remaining(fake))
    assert info.value.pointer == ""


def test_over_cap_is_refused_even_if_the_prefix_is_a_valid_notification() -> None:
    fake = FakeGateway()
    fake.sources[0] = b'{"message":"a"}' + b" " * INPUT_MAX
    with pytest.raises(PayloadError) as info:
        read_notification(fake, 0, fake_remaining(fake))
    assert (info.value.reason, info.value.pointer) == ("invalid_payload", "")


# --- reading through the gateway ----------------------------------------------------------------


def test_read_notification_from_descriptor_and_path() -> None:
    fake = FakeGateway()
    fake.sources[0] = b'{"message":"from stdin"}'
    fake.sources["/some/file"] = b'{"message":"from file"}'
    assert read_notification(fake, 0, fake_remaining(fake)).message == "from stdin"
    assert read_notification(fake, "/some/file", fake_remaining(fake)).message == "from file"


def test_closed_stdin_is_empty_input_a_parse_failure() -> None:
    fake = FakeGateway()  # nothing scripted: empty input
    with pytest.raises(PayloadError) as info:
        read_notification(fake, 0, fake_remaining(fake))
    assert (info.value.reason, info.value.pointer) == ("invalid_payload", "")


def test_stalled_producer_times_out_at_the_deadline() -> None:
    fake = FakeGateway()
    fake.sources[0] = StallingSource(b'{"message":')  # sends 10 bytes and stalls
    start = fake.monotonic()
    with pytest.raises(InputTimeout):
        read_notification(fake, 0, fake_remaining(fake, 5.0))
    assert fake.monotonic() - start == pytest.approx(5.0, abs=gw.SLICE_SECONDS + 1e-6)


def test_timeout_wins_over_a_parse_failure_of_the_partial_data() -> None:
    fake = FakeGateway()
    fake.sources[0] = StallingSource(b"\xff\xff")
    with pytest.raises(InputTimeout):
        read_notification(fake, 0, fake_remaining(fake, 1.0))


def test_expired_deadline_before_reading_is_a_timeout() -> None:
    fake = FakeGateway()
    fake.sources[0] = b'{"message":"a"}'
    with pytest.raises(InputTimeout):
        read_notification(fake, 0, lambda: 0.0)


def test_input_timeout_error_is_the_exit_12_envelope() -> None:
    err = input_timeout_error()
    assert err.exit_code == 12
    assert schema_errors("cli/error", err.envelope) == []
    body = err.envelope["error"]
    assert body["code"] == "unavailable"
    assert body["details"] == {"phase": "input"}
    assert body["retryable"] is True
    assert body["unknown_outcome"] is False


def test_source_error_propagates_for_the_caller_to_map_to_usage() -> None:
    fake = FakeGateway()
    fake.sources["/bad"] = gw.SourceError("input file cannot be opened")
    with pytest.raises(gw.SourceError):
        read_notification(fake, "/bad", fake_remaining(fake))


# --- the real gateway: files, pipes, devices ------------------------------------------------------


@pytest.fixture
def real() -> gw.RealGateway:
    return gw.RealGateway()


def real_remaining(seconds: float = 20.0):
    end = time.monotonic() + seconds
    return lambda: end - time.monotonic()


def test_regular_file_is_read(tmp_path: Path, real: gw.RealGateway) -> None:
    path = tmp_path / "n.json"
    path.write_bytes(b'{"message":"file"}')
    assert read_notification(real, str(path), real_remaining()).message == "file"


def test_symlink_to_regular_file_is_accepted(tmp_path: Path, real: gw.RealGateway) -> None:
    target = tmp_path / "n.json"
    target.write_bytes(b'{"message":"linked"}')
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert read_notification(real, str(link), real_remaining()).message == "linked"


def test_regular_file_over_the_cap_is_refused(tmp_path: Path, real: gw.RealGateway) -> None:
    path = tmp_path / "big.json"
    path.write_bytes(padded(INPUT_MAX + 1))
    with pytest.raises(PayloadError) as info:
        read_notification(real, str(path), real_remaining())
    assert info.value.pointer == ""


def test_file_of_exactly_the_cap_is_read(tmp_path: Path, real: gw.RealGateway) -> None:
    path = tmp_path / "cap.json"
    path.write_bytes(padded(INPUT_MAX))
    with pytest.raises(PayloadError) as info:
        read_notification(real, str(path), real_remaining())
    assert info.value.pointer == "/title"  # read in full, then the 100000 character rule


def test_directory_fifo_and_dev_zero_are_source_errors(
    tmp_path: Path, real: gw.RealGateway
) -> None:
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    for path in (tmp_path, fifo, "/dev/zero", tmp_path / "missing"):
        with pytest.raises(gw.SourceError):
            read_notification(real, str(path), real_remaining())
    assert stat.S_ISFIFO(os.stat(fifo).st_mode)


def test_closed_descriptor_is_empty_input(real: gw.RealGateway) -> None:
    r, w = os.pipe()
    os.close(r)
    os.close(w)
    with pytest.raises(PayloadError) as info:
        read_notification(real, r, real_remaining(5.0))
    assert info.value.pointer == ""


def test_pipe_with_a_complete_notification(real: gw.RealGateway) -> None:
    r, w = os.pipe()
    try:
        os.write(w, b'{"message":"piped"}')
        os.close(w)
        w = -1
        assert read_notification(real, r, real_remaining(5.0)).message == "piped"
    finally:
        os.close(r)
        if w >= 0:
            os.close(w)


def test_pipe_that_sends_ten_bytes_and_stalls_times_out_without_hanging(
    real: gw.RealGateway,
) -> None:
    r, w = os.pipe()
    try:
        os.write(w, b'{"message"')
        started = time.monotonic()
        with pytest.raises(InputTimeout):
            read_notification(real, r, real_remaining(0.5))
        elapsed = time.monotonic() - started
        assert 0.4 <= elapsed < 3.0
    finally:
        os.close(r)
        os.close(w)


def test_slow_trickle_cannot_extend_the_deadline(real: gw.RealGateway) -> None:
    r, w = os.pipe()
    stop = threading.Event()

    def trickle() -> None:
        while not stop.is_set():
            try:
                os.write(w, b" ")
            except OSError:
                return
            stop.wait(0.05)

    thread = threading.Thread(target=trickle, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        with pytest.raises(InputTimeout):
            read_notification(real, r, real_remaining(0.6))
        assert time.monotonic() - started < 3.0
    finally:
        stop.set()
        thread.join(5)
        os.close(r)
        os.close(w)


def test_socket_stdin_is_read(real: gw.RealGateway) -> None:
    a, b = socket.socketpair()
    try:
        b.sendall(b'{"message":"sock"}')
        b.close()
        assert read_notification(real, a.fileno(), real_remaining(5.0)).message == "sock"
    finally:
        a.close()


def test_closed_stdin_in_a_child_process(tmp_path: Path) -> None:
    """``<&-``: a process whose descriptor 0 is closed reads empty input (a parse failure)."""
    code = (
        "import sys,time\n"
        "from ha_notice.gateway import RealGateway\n"
        "from ha_notice.payload import read_notification, PayloadError\n"
        "end=time.monotonic()+5\n"
        "try:\n"
        "    read_notification(RealGateway(), 0, lambda: end-time.monotonic())\n"
        "except PayloadError as e:\n"
        "    print(e.reason, repr(e.pointer))\n"
    )
    home = tmp_path / "home"
    home.mkdir()
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home), "PATH": os.environ.get("PATH", "")}
    # ``0<&-`` closes descriptor 0 in the child; a shell is the portable way to ask for it.
    proc = subprocess.Popen(  # noqa: S602
        f'"{sys.executable}" -c "$CODE" 0<&-',
        shell=True,
        env={**env, "CODE": code},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
    )
    try:
        out, err = proc.communicate(timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()  # the exact child this test started
    assert proc.returncode == 0, err
    assert out.decode().split() == ["invalid_payload", "''"]
