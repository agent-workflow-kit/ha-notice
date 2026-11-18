"""Every mode of `send` and `validate` through the CLI, against hand-made goldens (issue #30).

Each scenario runs `cli.main` with the fake gateway, validates the captured stdout against the
schema of its command (`cli/send`, `cli/validate`, `cli/error`) and compares the exact bytes with
a golden file. The goldens named here were written by hand from docs/interface.md (key order,
details by code, retryable and unknown_outcome flags, the hashes of the message, the byte size and
the durations from the fake clock), not copied from the program's output; the only text taken
from the program is the fixed message of each code, which the interface leaves to the tool.
The coverage of all goldens is checked in tests/test_golden_coverage.py.
"""

from __future__ import annotations

import http.client
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from ha_notice import __version__
from ha_notice.cli import main
from ha_notice.gateway import CaCandidates
from tests.fake_gateway import (
    ConnectionScript,
    FakeExit,
    FakeGateway,
    StallingSource,
    private_home,
)
from tests.harness import Golden, schema_errors

TOKEN = "HA_SECRET_tok_30303030303030"
ENV = {"HA_TOKEN": TOKEN}
BASE = "base_url: https://ha.example\nservice: mobile_app_x\n"
LONG_KEY = "k" * 65  # a field name outside [A-Za-z0-9_-]{1,64}: the pointer is /?
Prep = Callable[[FakeGateway], None]


def _noop(gw: FakeGateway) -> None:
    return None


@dataclass(frozen=True)
class Scenario:
    id: str
    exit: int
    schema: str
    output: str | None
    argv: tuple[str, ...] = ("--message=hi",)
    source: bytes | StallingSource | None = None
    config: str = BASE
    timeout: int = 5
    env: dict[str, str] = field(default_factory=lambda: dict(ENV))
    scripts: tuple[ConnectionScript, ...] = ()  # one per connection, then the default
    prep: Prep = _noop
    log: str | None = None
    # True when the run legitimately writes a log record that has no golden of its own here.
    logs_unchecked: bool = False
    request: str | None = None


def _no_trust(gw: FakeGateway) -> None:
    gw.ca = CaCandidates("", "", ())


SEND: tuple[Scenario, ...] = (
    Scenario(
        "sent",
        0,
        "cli/send",
        "send-sent.json",
        log="send-sent.jsonl",
        argv=(
            "--title=Backup done",
            "--message=Nightly backup finished",
            "--level=warn",
            "--link=https://ha.example/x",
            "--dedupe-key=k1",
        ),
        config=BASE + "default_group: ops\n",
        request="dry-run.json",
    ),
    Scenario(
        "sent-truncated",
        0,
        "cli/send",
        "send-sent-truncated.json",
        log="send-sent-truncated.jsonl",
        argv=("--message=" + "a" * 1100,),
        request="message_cut.json",
    ),
    Scenario(
        "sent-insecure",
        0,
        "cli/send",
        "send-sent-insecure.json",
        config="base_url: http://ha.example\nservice: s\nallow_insecure_http: true\n",
        logs_unchecked=True,
    ),
    Scenario(
        "dry-run",
        0,
        "cli/send",
        "send-dry-run.json",
        argv=(
            "--dry-run",
            "--title=Backup done",
            "--message=Nightly backup finished",
            "--level=warn",
            "--link=https://ha.example/x",
            "--dedupe-key=k1",
        ),
        config=BASE + "default_group: ops\n",
        env={},
    ),
    Scenario("disabled", 22, "cli/send", "disabled.json", config=BASE + "enabled: false\n"),
    Scenario(
        "config-invalid",
        2,
        "cli/error",
        "error-config-invalid-key.json",
        config=BASE + '"bad key": 1\n',
    ),
    Scenario("usage", 2, "cli/error", "usage-no-command.json", argv=()),
    Scenario(
        "refused-empty-message",
        20,
        "cli/error",
        "error-refused-empty-message.json",
        argv=("--stdin-json",),
        source=b'{"title":"x"}',
        log="send-refused.jsonl",
    ),
    Scenario(
        "refused-command-keyword",
        20,
        "cli/error",
        "error-refused-command-keyword.json",
        argv=("--message=tts",),
        log="send-refused-command-keyword.jsonl",
    ),
    Scenario(
        "refused-link-invalid",
        20,
        "cli/error",
        "error-refused-link-invalid.json",
        argv=("--message=hi", "--link=https://other.example/x"),
        config=BASE + "link_hosts: [ha.example]\n",
        log="send-refused-link-invalid.jsonl",
    ),
    Scenario(
        "refused-link-scheme",
        20,
        "cli/error",
        "error-refused-link-scheme.json",
        argv=("--message=hi", "--link=javascript:x"),
        log="send-refused-link-scheme.jsonl",
    ),
    Scenario(
        "refused-invalid-payload",
        20,
        "cli/error",
        "error-refused-invalid-payload.json",
        argv=("--stdin-json",),
        source=json.dumps({"message": "a", LONG_KEY: 1}).encode(),
        log="send-refused-invalid-payload.jsonl",
    ),
    Scenario(
        "host-rejected",
        12,
        "cli/error",
        "error-host-rejected.json",
        scripts=(ConnectionScript(status=400),),
        log="send-host-rejected.jsonl",
    ),
    Scenario(
        "auth-required",
        12,
        "cli/error",
        "error-auth-required.json",
        scripts=(ConnectionScript(status=401),),
        log="send-auth-required.jsonl",
    ),
    Scenario(
        "credential-invalid",
        12,
        "cli/error",
        "error-credential-invalid.json",
        env={},
        log="send-credential-invalid.jsonl",
    ),
    Scenario(
        "rate-limited",
        12,
        "cli/error",
        "error-rate-limited.json",
        timeout=10,
        scripts=(ConnectionScript(status=429),) * 3,
        log="send-rate-limited.jsonl",
    ),
    Scenario(
        "upstream-error",
        12,
        "cli/error",
        "error-upstream-error.json",
        scripts=(ConnectionScript(status=500),),
        log="send-upstream-error.jsonl",
    ),
    Scenario(
        "network-error",
        12,
        "cli/error",
        "error-network-error.json",
        scripts=(ConnectionScript(connect_error=ConnectionRefusedError(111, "x")),) * 2,
        log="send-network-error.jsonl",
    ),
    Scenario(
        "network-error-tls",
        12,
        "cli/error",
        "error-network-error-tls.json",
        prep=_no_trust,
        logs_unchecked=True,
    ),
    Scenario(
        "network-error-timeout",
        12,
        "cli/error",
        "error-network-error-timeout.json",
        scripts=(ConnectionScript(connect_error=TimeoutError("x")),) * 2,
        logs_unchecked=True,
    ),
    Scenario(
        "outcome-unknown-tagged",
        12,
        "cli/error",
        "error-outcome-unknown-tagged.json",
        argv=("--message=hi", "--dedupe-key=k1"),
        scripts=(ConnectionScript(response_error=ConnectionResetError(104, "x")),),
        logs_unchecked=True,
    ),
    Scenario(
        "outcome-unknown",
        12,
        "cli/error",
        "error-outcome-unknown.json",
        scripts=(ConnectionScript(response_error=ConnectionResetError(104, "x")),),
        logs_unchecked=True,
    ),
    Scenario(
        "wrong-host-response",
        12,
        "cli/error",
        "error-wrong-host-response.json",
        scripts=(ConnectionScript(status=404),),
        log="send-wrong-host-response.jsonl",
    ),
    Scenario(
        "wrong-host-response-not-http",
        12,
        "cli/error",
        "error-wrong-host-response-not-http.json",
        scripts=(ConnectionScript(response_error=http.client.BadStatusLine("x")),),
        log="send-wrong-host-response-not-http.jsonl",
    ),
    Scenario(
        "unavailable",
        12,
        "cli/error",
        "error-unavailable.json",
        argv=("--stdin-json",),
        source=StallingSource(b'{"mess'),
        log="send-unavailable.jsonl",
    ),
    Scenario(
        "internal",
        1,
        "cli/error",
        "error-internal.json",
        scripts=(ConnectionScript(connect_error=ValueError("x")),),
    ),
    Scenario(
        "internal-after-writing",
        1,
        "cli/error",
        "error-internal-after-writing.json",
        scripts=(ConnectionScript(request_error=SystemExit(3)),),
        log="send-internal-after-writing.jsonl",
    ),
)

LIST = ConnectionScript(body=b"[]")
OBJECT = ConnectionScript(body=b"{}")
VALIDATE: tuple[Scenario, ...] = (
    Scenario("validate-ok", 0, "cli/validate", "validate-ok.json", argv=()),
    Scenario(
        "validate-enabled-false",
        0,
        "cli/validate",
        "validate-disabled.json",
        argv=(),
        config=BASE + "enabled: false\n",
    ),
    Scenario(
        "validate-missing-base-url",
        2,
        "cli/validate",
        "validate-missing-base-url.json",
        argv=(),
        config="service: s\n",
    ),
    Scenario(
        "validate-bad-credential",
        12,
        "cli/validate",
        "validate-bad-credential.json",
        argv=(),
        env={},
    ),
    Scenario(
        "validate-probe-ok",
        0,
        "cli/validate",
        "validate-probe-ok.json",
        argv=("--probe",),
        scripts=(OBJECT,),
    ),
    Scenario(
        "validate-probe-auth",
        12,
        "cli/validate",
        "validate-probe-auth.json",
        argv=("--probe",),
        scripts=(ConnectionScript(status=401),),
    ),
    Scenario(
        "validate-test-message-ok",
        0,
        "cli/validate",
        "validate-test-message-ok.json",
        argv=("--test-message", "--actor=human:tester"),
        scripts=(LIST,),
        request="validate-test-message.json",
        log="validate-test-message-sent.jsonl",
    ),
    Scenario(
        "validate-test-message-failed",
        12,
        "cli/validate",
        "validate-test-message-failed.json",
        argv=("--test-message",),
        scripts=(ConnectionScript(status=401),),
        logs_unchecked=True,
    ),
    Scenario(
        "validate-probe-test-message-ok",
        0,
        "cli/validate",
        "validate-probe-test-message-ok.json",
        argv=("--probe", "--test-message"),
        scripts=(OBJECT, LIST),
        logs_unchecked=True,
    ),
    Scenario(
        "validate-disabled-probe",
        22,
        "cli/validate",
        "disabled.json",
        argv=("--probe",),
        config=BASE + "enabled: false\n",
    ),
    Scenario(
        "validate-config-invalid",
        2,
        "cli/error",
        "error-config-invalid-key.json",
        argv=(),
        config=BASE + '"bad key": 1\n',
    ),
)


def _run(
    sc: Scenario, tmp: Path, cert: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
) -> tuple[int, str, str, FakeGateway, Path]:
    home = private_home(tmp)
    gw = FakeGateway(
        home=home,
        ca=CaCandidates(str(cert[0]), "", ()),
        sources={0: sc.source if sc.source is not None else b'{"message":"hi"}'},
        default_script=ConnectionScript(body=b"[]"),
    )
    gw.scripts.extend(sc.scripts)
    sc.prep(gw)
    config = tmp / "c.yaml"
    config.write_text(f"timeout: {sc.timeout}s\n{sc.config}", encoding="utf-8")
    command = "validate" if sc.id.startswith("validate-") else "send"
    full = ["--config", str(config), "--json", *([command] if sc.id != "usage" else []), *sc.argv]
    try:
        code = main(full, sc.env, gw)
    except FakeExit as done:
        code = done.code
    out = capsys.readouterr()
    return code, out.out, out.err, gw, Path(home)


@pytest.mark.parametrize("sc", SEND + VALIDATE, ids=lambda s: s.id)
def test_the_mode_prints_its_golden_and_a_schema_valid_document(
    sc: Scenario,
    tmp_path: Path,
    self_signed_cert: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
    golden: Golden,
) -> None:
    code, out, err, gw, home = _run(sc, tmp_path, self_signed_cert, capsys)
    assert code == sc.exit, err
    assert schema_errors(sc.schema, json.loads(out)) == []
    assert sc.output is not None
    golden.check("output", sc.output, out, schema=sc.schema)
    if sc.request is not None:
        posts = [r for c in gw.connections for r in c.requests if r.method == "POST"]
        assert len(posts) == 1 and posts[0].body is not None
        golden.check("request", sc.request, posts[0].body.decode())
    log = home / ".local" / "state" / "ha-notice" / "log.jsonl"
    if sc.log is not None:
        raw = log.read_text(encoding="utf-8")
        # The real version is normalised for the golden, so pin it separately.
        assert all(json.loads(line)["version"] == __version__ for line in raw.splitlines())
        text = raw.replace(f'"version":"{__version__}"', '"version":"0.1.0"')
        golden.check("log", sc.log, text, schema="log")
    elif not sc.logs_unchecked:
        assert not log.exists(), "this scenario has no log golden but wrote a log record"


def test_every_scenario_id_is_unique() -> None:
    ids = [s.id for s in SEND + VALIDATE]
    assert len(ids) == len(set(ids))
