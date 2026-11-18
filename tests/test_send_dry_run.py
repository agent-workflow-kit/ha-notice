"""The send pipeline up to and including --dry-run (issue #19)."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from ha_notice import cli
from ha_notice.cli import main
from ha_notice.gateway import SourceError, SourceResult, StateDirError
from ha_notice.render import serialize
from tests.fake_gateway import FakeGateway, StallingSource
from tests.harness import Golden, schema_errors

Result = tuple[int, str, str]

FLAGS = [
    "--title=Backup done",
    "--message=Nightly backup finished",
    "--level=warn",
    "--link=https://ha.example/x",
    "--dedupe-key=k1",
]
FLAGS_AS_JSON = {
    "title": "Backup done",
    "message": "Nightly backup finished",
    "level": "warn",
    "link": "https://ha.example/x",
}


@dataclass
class SpyGateway(FakeGateway):
    """Records which sources were read."""

    reads: list[int | str] = field(default_factory=list)
    state_calls: list[str] = field(default_factory=list)
    input_seconds: float = 0.0  # fake clock time one input read takes

    def open_state_dir(self, home: str) -> int:
        self.state_calls.append("open_state_dir")
        return super().open_state_dir(home)

    def open_state_file(self, dir_fd: int, name: str, *, append: bool = False) -> int:
        self.state_calls.append("open_state_file")
        return super().open_state_file(dir_fd, name, append=append)

    def read_source(
        self, source: int | str, max_bytes: int, remaining: Callable[[], float]
    ) -> SourceResult:
        self.reads.append(source)
        self.advance(self.input_seconds)
        return super().read_source(source, max_bytes, remaining)


class NoEnv(Mapping[str, str]):
    """An environment that fails the test on any access."""

    def __getitem__(self, key: str) -> str:
        raise AssertionError("the environment was read")

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("the environment was read")

    def __len__(self) -> int:
        raise AssertionError("the environment was read")


@pytest.fixture
def conf(tmp_path: Path) -> Callable[[str], str]:
    def write(text: str) -> str:
        path = tmp_path / "c.yaml"
        path.write_text(text, encoding="utf-8")
        return str(path)

    return write


@pytest.fixture
def run(capsys: pytest.CaptureFixture[str]) -> Callable[..., Result]:
    def _run(argv: list[str], gateway: FakeGateway | None = None, env: Any = None) -> Result:
        gw = SpyGateway() if gateway is None else gateway
        code = main(argv, {} if env is None else env, gw)  # type: ignore[arg-type]
        out = capsys.readouterr()
        return code, out.out, out.err

    return _run


def _error(out: str) -> dict[str, Any]:
    doc = json.loads(out)
    assert schema_errors("cli/error", doc) == []
    return doc["error"]  # type: ignore[no-any-return]


# --- the output ---------------------------------------------------------------------------


def test_dry_run_json_golden(run: Any, conf: Any, golden: Golden) -> None:
    cfg = conf("default_group: ops\n")
    code, out, err = run(["--json", "--config", cfg, "send", "--dry-run", *FLAGS])
    assert (code, err) == (0, "")
    assert schema_errors("cli/send", json.loads(out)) == []
    golden.check("output", "send-dry-run.json", out)
    golden.check("request", "dry-run.json", serialize(json.loads(out)["rendered"]).decode())


def test_dry_run_human_prints_the_request_on_stderr(run: Any, conf: Any) -> None:
    cfg = conf("default_group: ops\n")
    code, out, err = run(["--config", cfg, "--dry-run", "send", *FLAGS])
    assert code == 0 and out == ""
    assert err == Golden().path("request", "dry-run.json").read_text(encoding="utf-8") + "\n"


def test_dry_run_quiet_prints_nothing(run: Any, conf: Any) -> None:
    code, out, err = run(
        ["--quiet", "--config", conf("enabled: true\n"), "send", "--dry-run", "--message=a"]
    )
    assert (code, out, err) == (0, "", "")


def test_dry_run_verbose_phases(run: Any, conf: Any) -> None:
    code, _, err = run(
        ["--verbose", "--config", conf("enabled: true\n"), "send", "--dry-run", "--message=a"]
    )
    assert code == 0
    assert err.splitlines()[:2] == ["input: 0 ms", "render: 0 ms"]


def test_no_key_means_no_tag(run: Any, conf: Any) -> None:
    code, out, _ = run(
        ["--json", "--config", conf("enabled: true\n"), "send", "--dry-run", "--message=hi"]
    )
    doc = json.loads(out)
    assert code == 0 and schema_errors("cli/send", doc) == []
    assert doc["tag_set"] is False and doc["dedupe_key"] is None
    assert doc["rendered"] == {"message": "hi"} and doc["bytes"] == len(b'{"message":"hi"}')
    assert doc["http_status"] is None and doc["warnings"] == [] and doc["truncated"] is False


def test_truncated_flag_and_bytes(run: Any, conf: Any) -> None:
    msg = "x" * 5000
    code, out, _ = run(
        ["--json", "--config", conf("enabled: true\n"), "send", "--dry-run", f"--message={msg}"]
    )
    doc = json.loads(out)
    assert code == 0 and doc["truncated"] is True
    assert doc["bytes"] == len(serialize(doc["rendered"]))
    assert schema_errors("cli/send", doc) == []


def test_unicode_is_not_escaped(run: Any, conf: Any) -> None:
    code, out, _ = run(
        [
            "--json",
            "--config",
            conf("enabled: true\n"),
            "send",
            "--dry-run",
            "--message=Grüße 😀",
            "--title=é",
        ]
    )
    assert code == 0 and "Grüße 😀" in out and "\\u" not in out


def test_dedupe_key_is_echoed_and_never_hashed_elsewhere(run: Any, conf: Any) -> None:
    key = 'weird "key" é ; rm -rf'
    code, out, _ = run(
        [
            "--json",
            "--config",
            conf("enabled: true\n"),
            "send",
            "--dry-run",
            "--message=a",
            f"--dedupe-key={key}",
        ]
    )
    doc = json.loads(out)
    assert code == 0 and doc["dedupe_key"] == key and doc["tag_set"] is True
    assert doc["rendered"]["data"]["tag"].startswith("awkit-")


# --- step order ---------------------------------------------------------------------------


def test_dry_run_needs_no_destination_and_no_token(run: Any, conf: Any) -> None:
    gw = SpyGateway(state_error=StateDirError())
    code, _, err = run(
        ["--json", "--config", conf("enabled: true\n"), "send", "--dry-run", "--message=a"],
        gw,
        NoEnv(),
    )
    assert code == 0 and err == ""
    assert gw.resolve_calls == [] and gw.connections == [] and gw.reads == []
    assert gw.state_calls == []  # no state directory, so no log


def test_dry_run_with_service_missing_exits_0(run: Any, conf: Any) -> None:
    cfg = conf("base_url: https://ha.example\n")
    assert run(["--config", cfg, "send", "--dry-run", "--message=a"])[0] == 0


def test_dry_run_malformed_base_url_still_exits_2(run: Any, conf: Any) -> None:
    cfg = conf("base_url: ftp://x\n")
    code, out, _ = run(["--json", "--config", cfg, "send", "--dry-run", "--message=a"])
    err = _error(out)
    assert code == 2 and err["code"] == "config_invalid" and err["details"] == {"key": "base_url"}


def test_dry_run_does_not_check_ca_file(run: Any, conf: Any) -> None:
    cfg = conf("ca_file: /nonexistent/ca.pem\n")
    assert run(["--config", cfg, "send", "--dry-run", "--message=a"])[0] == 0


def test_real_send_missing_base_url_exits_2_before_stdin(run: Any, conf: Any) -> None:
    gw = SpyGateway(sources={0: b'{"message":"a"}'})
    code, out, _ = run(["--json", "--config", conf("enabled: true\n"), "send", "--stdin-json"], gw)
    err = _error(out)
    assert code == 2 and err["details"] == {"key": "base_url"} and gw.reads == []


def test_real_send_missing_service_then_ca_file(run: Any, conf: Any) -> None:
    gw = SpyGateway(sources={0: b'{"message":"a"}'})
    cfg = conf("base_url: https://ha.example\nca_file: /nonexistent/ca.pem\n")
    _, out, _ = run(["--json", "--config", cfg, "send", "--stdin-json"], gw)
    assert _error(out)["details"] == {"key": "service"}
    cfg = conf(
        "base_url: https://ha.example\nservice: mobile_app_x\nca_file: /nonexistent/ca.pem\n"
    )
    _, out, _ = run(["--json", "--config", cfg, "send", "--stdin-json"], gw)
    assert _error(out)["details"] == {"key": "ca_file"} and gw.reads == []


def test_real_send_without_a_token_is_credential_invalid(run: Any, conf: Any) -> None:
    cfg = conf("base_url: https://ha.example\nservice: mobile_app_x\n")
    code, out, _ = run(["--json", "--config", cfg, "send", "--message=a"])
    err = _error(out)
    assert (
        code == 12 and err["code"] == "credential_invalid" and err["details"] == {"env": "HA_TOKEN"}
    )


@pytest.mark.parametrize("dry", [[], ["--dry-run"]])
def test_disabled_exits_22_before_input_and_destination(
    run: Any, conf: Any, dry: list[str]
) -> None:
    gw = SpyGateway(sources={0: b"not json"})
    cfg = conf("enabled: false\nca_file: /nonexistent/ca.pem\n")
    code, out, err = run(["--json", "--config", cfg, "send", "--stdin-json", *dry], gw)
    assert (code, out, err) == (22, '{"outcome":"disabled"}\n', "") and gw.reads == []
    code, out, err = run(["--config", cfg, "send", "--stdin-json", *dry], gw)
    assert (code, out, err) == (22, "", "disabled in config\n")


def test_config_error_wins_over_disabled(run: Any, conf: Any) -> None:
    cfg = conf("enabled: false\ntimeout: bogus\n")
    code, out, _ = run(["--json", "--config", cfg, "send", "--dry-run", "--message=a"])
    assert code == 2 and _error(out)["details"] == {"key": "timeout"}


def test_missing_config_file_flag(run: Any) -> None:
    code, out, _ = run(["--json", "--config", "/nonexistent/c.yaml", "send", "--message=a"])
    assert code == 2 and _error(out)["details"] == {"key": "--config"}


def test_usage_wins_over_config_and_disabled(run: Any, conf: Any) -> None:
    cfg = conf("enabled: false\ntimeout: bogus\n")
    code, out, _ = run(["--json", "--config", cfg, "send", "--stdin-json", "--message=a"])
    assert code == 2 and _error(out)["code"] == "usage"


def test_json_source_with_file_and_dedupe_key_disabled_is_usage(run: Any, conf: Any) -> None:
    # Deferred from #11: usage (2) is judged before the config, so enabled: false cannot give 22.
    cfg = conf("enabled: false\n")
    argv = ["--json", "--config", cfg, "send", "--stdin-json", "--file=x", "--dedupe-key=k"]
    code, out, _ = run(argv)
    assert code == 2 and _error(out)["code"] == "usage"


def test_home_failure_is_config_invalid_home(run: Any) -> None:
    from ha_notice.gateway import HomeLookupError

    gw = SpyGateway(home=HomeLookupError())
    code, out, _ = run(["--json", "send", "--dry-run", "--message=a"], gw)
    assert code == 2 and _error(out)["details"] == {"key": "home"}


# --- input and validation -----------------------------------------------------------------


def test_flags_and_stdin_and_file_give_the_same_request(
    run: Any, conf: Any, tmp_path: Path
) -> None:
    cfg = conf("default_group: ops\nlink_hosts: [ha.example]\n")
    doc = json.dumps(FLAGS_AS_JSON).encode()
    (tmp_path / "n.json").write_bytes(doc)
    gw = lambda: SpyGateway(sources={0: doc, str(tmp_path / "n.json"): doc})  # noqa: E731
    base = ["--json", "--config", cfg, "send", "--dry-run", "--dedupe-key=k1"]
    outs = [
        run([*base, *FLAGS[:4]], gw())[1],
        run([*base, "--stdin-json"], gw())[1],
        run([*base, "--file=-"], gw())[1],
        run([*base, f"--file={tmp_path / 'n.json'}"], gw())[1],
    ]
    assert len(set(outs)) == 1
    assert json.loads(outs[0])["rendered"]["data"]["tag"] == "awkit-6ab9f1eb8f7d3388f4f9d586"


def test_stdin_json_reads_descriptor_0_only(run: Any, conf: Any) -> None:
    gw = SpyGateway(sources={0: b'{"message":"a"}'})
    assert (
        run(["--config", conf("enabled: true\n"), "send", "--dry-run", "--stdin-json"], gw)[0] == 0
    )
    assert gw.reads == [0]


def test_flags_do_not_read_stdin(run: Any, conf: Any) -> None:
    gw = SpyGateway(sources={0: b"junk"})
    assert (
        run(["--config", conf("enabled: true\n"), "send", "--dry-run", "--message=a"], gw)[0] == 0
    )
    assert gw.reads == []


@pytest.mark.parametrize(
    ("data", "reason", "pointer"),
    [
        (b"", "invalid_payload", ""),
        (b"[]", "invalid_payload", ""),
        (b'{"message":"a","x":1}', "invalid_payload", "/x"),
        (b'{"message":"a","level":"loud"}', "invalid_payload", "/level"),
        (b'{"message":"  "}', "empty_message", None),
        (b'{"message":"command_dismiss"}', "command_keyword", None),
        (b'{"message":"a","link":"ftp://x"}', "link_scheme", None),
        (b'{"message":"a","link":"https://evil.example/"}', "link_invalid", "/link"),
        (b'{"message":"a"}' + b" " * 2000000, "invalid_payload", ""),
        (b'{"message":"a","message":"b"}', "invalid_payload", ""),
    ],
)
def test_refusals_exit_20(
    run: Any, conf: Any, data: bytes, reason: str, pointer: str | None
) -> None:
    cfg = conf("link_hosts: [ha.example]\n")
    gw = SpyGateway(sources={0: data})
    code, out, err = run(["--json", "--config", cfg, "send", "--dry-run", "--stdin-json"], gw)
    body = _error(out)
    assert code == 20 and body["code"] == "refused" and body["reason"] == reason
    assert (body["details"] or {}).get("pointer") == pointer
    assert err.startswith(f"refused ({reason}): ")


def test_stalled_input_is_unavailable(run: Any, conf: Any) -> None:
    gw = SpyGateway(sources={0: StallingSource(b'{"mess')})
    code, out, _ = run(
        ["--json", "--config", conf("timeout: 2s\n"), "send", "--dry-run", "--stdin-json"], gw
    )
    body = _error(out)
    assert code == 12 and body["code"] == "unavailable" and body["details"] == {"phase": "input"}
    assert body["retryable"] is True and body["unknown_outcome"] is False


@pytest.mark.parametrize("source", ["--file=/nonexistent/n.json", "--file="])
def test_unscripted_file_is_usage_like_the_real_gateway(run: Any, conf: Any, source: str) -> None:
    code, out, err = run(
        ["--json", "--config", conf("enabled: true\n"), "send", "--dry-run", source]
    )
    assert code == 2 and _error(out)["code"] == "usage"
    assert "nonexistent" not in out + err


@pytest.mark.parametrize("source", ["--file=/nonexistent/n.json", "--file="])
def test_bad_file_is_usage(run: Any, conf: Any, source: str) -> None:
    gw = SpyGateway(sources={"/nonexistent/n.json": SourceError(), "": SourceError()})
    code, out, err = run(
        ["--json", "--config", conf("enabled: true\n"), "send", "--dry-run", source], gw
    )
    assert code == 2 and _error(out)["code"] == "usage"
    assert "nonexistent" not in out + err


# --- the default source, the clock, warnings and links ------------------------------------


def _dry(cfg: str, *extra: str) -> list[str]:
    return ["--json", "--config", cfg, "send", "--dry-run", *extra]


def test_default_stdin_is_read_when_no_source_flag(run: Any, conf: Any) -> None:
    gw = SpyGateway(sources={0: b'{"message":"piped","title":"T"}'})
    code, out, _ = run(_dry(conf("enabled: true\n")), gw)
    doc = json.loads(out)
    assert code == 0 and gw.reads == [0]
    assert doc["rendered"]["message"] == "piped" and doc["rendered"]["title"] == "T"


def test_default_stdin_garbage_is_invalid_payload_not_empty_message(run: Any, conf: Any) -> None:
    gw = SpyGateway(sources={0: b"garbage"})
    code, out, _ = run(_dry(conf("enabled: true\n")), gw)
    body = _error(out)
    assert code == 20 and body["reason"] == "invalid_payload"
    assert body["details"] == {"pointer": ""}


@pytest.mark.parametrize("scripted", [b"", SourceError()], ids=["devnull", "closed"])
def test_default_stdin_empty_or_unreadable_is_invalid_payload(
    run: Any, conf: Any, scripted: Any
) -> None:
    gw = SpyGateway(sources={0: scripted})
    code, out, _ = run(_dry(conf("enabled: true\n")), gw)
    body = _error(out)
    assert code == 20 and body["reason"] == "invalid_payload" and gw.reads == [0]


def test_default_stdin_stalled_is_unavailable(run: Any, conf: Any) -> None:
    gw = SpyGateway(sources={0: StallingSource(b'{"mess')})
    code, out, _ = run(_dry(conf("timeout: 2s\n")), gw)
    body = _error(out)
    assert code == 12 and body["code"] == "unavailable" and body["details"] == {"phase": "input"}


def test_message_flag_wins_over_piped_stdin(run: Any, conf: Any) -> None:
    gw = SpyGateway(sources={0: b'{"message":"from stdin"}'})
    code, out, _ = run(_dry(conf("enabled: true\n"), "--message=from flag"), gw)
    assert code == 0 and gw.reads == []
    assert json.loads(out)["rendered"]["message"] == "from flag"


def test_input_time_is_in_duration_and_verbose(run: Any, conf: Any) -> None:
    gw = SpyGateway(sources={0: b'{"message":"a"}'}, input_seconds=1.5)
    code, out, err = run(["--verbose", *_dry(conf("enabled: true\n"))], gw)
    assert code == 0 and json.loads(out)["duration_ms"] == 1500
    assert err.splitlines() == ["input: 1500 ms", "render: 0 ms"]


def test_dry_run_has_no_insecure_http_warning(run: Any, conf: Any) -> None:
    cfg = conf("base_url: http://ha.example\nallow_insecure_http: true\n")
    code, out, err = run(_dry(cfg, "--message=a"))
    assert code == 0 and json.loads(out)["warnings"] == [] and err == ""


def test_flags_link_outside_link_hosts_is_link_invalid(run: Any, conf: Any) -> None:
    cfg = conf("link_hosts: [ha.example]\n")
    code, out, _ = run(_dry(cfg, "--message=a", "--link=https://evil.example/"))
    body = _error(out)
    assert code == 20 and body["reason"] == "link_invalid"
    assert body["details"] == {"pointer": "/link"}


# --- progress and safety ------------------------------------------------------------------


def test_progress_writing_stays_false(run: Any, conf: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[cli.Invocation] = []
    real = cli.HANDLERS["send"]

    def spy(inv: cli.Invocation) -> int:
        seen.append(inv)
        return real(inv)

    monkeypatch.setitem(cli.HANDLERS, "send", spy)
    assert run(["--config", conf("enabled: true\n"), "send", "--dry-run", "--message=a"])[0] == 0
    assert seen[0].progress.writing is False


def test_unexpected_exception_is_internal_not_after_writing(
    run: Any, conf: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("secret text")

    monkeypatch.setattr("ha_notice.send.render", boom)
    code, out, err = run(
        ["--json", "--config", conf("enabled: true\n"), "send", "--dry-run", "--message=a"]
    )
    body = _error(out)
    assert code == 1 and body["unknown_outcome"] is False and "secret" not in out + err


def test_real_process_dry_run_reads_no_home_and_no_token(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys

    home = tmp_path / "home"
    home.mkdir()
    cfg = tmp_path / "c.yaml"
    cfg.write_text("default_group: ops\n", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "cfg"),
        "XDG_STATE_HOME": str(home / "state"),
        "LC_ALL": "C",
        "HA_TOKEN": "sentinel-token-value",
    }
    proc = subprocess.run(
        [sys.executable, "-m", "ha_notice", "--json", "--config", str(cfg), "send", "--dry-run"]
        + FLAGS,
        capture_output=True,
        timeout=60,
        check=False,
        env=env,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 0 and proc.stderr == b""
    assert b"sentinel-token-value" not in proc.stdout + proc.stderr
    assert schema_errors("cli/send", json.loads(proc.stdout)) == []
    assert list(home.iterdir()) == []
