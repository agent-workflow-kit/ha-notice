"""``clear`` against a real socket (issue #38): the fake Home Assistant of tests/fake_ha.py."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from ha_notice.render import serialize, tag_from_dedupe_key
from tests.fake_ha import FakeHA
from tests.harness import schema_errors
from tests.test_send_socket import SERVICE, TOKEN, RealIO, config, records, run, state_dir


@pytest.fixture
def io(tmp_path: Path) -> Iterator[RealIO]:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    gateway = RealIO(home)
    try:
        yield gateway
    finally:
        gateway.release.set()


def test_one_post_with_the_exact_body_and_the_token_only_in_the_header(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    with FakeHA(token=TOKEN, services={SERVICE}) as ha:
        code, out, err, exited = run(
            capsys, io, config(tmp_path, ha), ["--json", "clear", "--dedupe-key=k"]
        )
        assert code == 0 and not exited
        [request] = ha.requests
        assert request.method == "POST" and request.path == f"/api/services/notify/{SERVICE}"
        assert request.header("Authorization") == f"Bearer {TOKEN}"
        expected = serialize(
            {"message": "clear_notification", "data": {"tag": tag_from_dedupe_key("k")}}
        )
        assert request.body == expected
        doc = json.loads(out)
        assert schema_errors("cli/clear", doc) == []
        assert doc["bytes"] == len(expected) and doc["http_status"] == 200
        assert doc["warnings"] == ["insecure_http"] and "insecure_http" in err
        [record] = records(io)
        assert record["message_sha256"] is None and record["tag_set"] is True
        assert schema_errors("log", record) == []
        for text in (out, err, (state_dir(io) / "log.jsonl").read_text(encoding="utf-8")):
            assert TOKEN not in text


def test_a_401_is_auth_required_and_nothing_else_is_sent(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    with FakeHA(token="HA_OTHER_token_0000", services={SERVICE}) as ha:
        code, out, _, _ = run(
            capsys, io, config(tmp_path, ha), ["--json", "clear", "--dedupe-key=k"]
        )
        assert code == 12 and json.loads(out)["error"]["code"] == "auth_required"
        assert len(ha.requests) == 1
        assert ha.requests[0].header("Authorization") == f"Bearer {TOKEN}"


def test_the_dry_run_makes_no_request(
    tmp_path: Path, io: RealIO, capsys: pytest.CaptureFixture[str]
) -> None:
    with FakeHA(token=TOKEN, services={SERVICE}) as ha:
        code, out, _, _ = run(
            capsys,
            io,
            config(tmp_path, ha),
            ["--json", "--dry-run", "clear", "--dedupe-key=k"],
            env={},
        )
        assert code == 0 and json.loads(out)["outcome"] == "dry_run"
        assert ha.requests == [] and not state_dir(io).exists()
