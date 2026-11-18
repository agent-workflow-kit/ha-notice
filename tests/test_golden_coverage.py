"""Golden coverage (issue #30): every exit code, error code, refusal reason, details key, validate
check, log outcome and code combination and request feature has a golden file.

The coverage function is tried against fake listings first, so the repository check below is
known to be able to fail: removing a golden from a listing names exactly what is lost.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from tests import golden_coverage as gc
from tests.harness import GOLDEN_DIR, load_schema

LISTING = gc.read_listing()


def _without(kind: str, name: str) -> dict[str, dict[str, str]]:
    listing = copy.deepcopy(LISTING)
    del listing[kind][name]
    return listing


def test_the_repository_goldens_cover_every_required_item() -> None:
    gaps = gc.missing(LISTING)
    assert gaps == [], "no golden shows:\n  " + "\n  ".join(gaps)


def test_every_golden_validates_against_its_schema() -> None:
    assert gc.problems(LISTING) == []


def test_the_listing_is_read_from_the_golden_directory_in_sorted_order() -> None:
    assert set(LISTING) == {"output", "request", "log"}
    for names in LISTING.values():
        assert names and list(names) == sorted(names)
    assert (GOLDEN_DIR / "output" / "disabled.json").is_file()


# --- the coverage function itself can fail ---------------------------------------------------


def test_an_empty_listing_misses_everything_except_the_allowlist() -> None:
    gaps = gc.missing({"output": {}, "request": {}, "log": {}})
    assert set(gaps) == gc.required() - set(gc.NON_GOLDENABLE)
    assert "exit:12" in gaps and "error:host_rejected" in gaps and "exit:128+N" not in gaps


@pytest.mark.parametrize(
    ("kind", "name", "lost"),
    [
        ("output", "error-host-rejected.json", "error:host_rejected"),
        ("output", "error-host-rejected.json", "details:hint"),
        ("output", "error-refused-link-scheme.json", "refusal:link_scheme"),
        ("output", "error-credential-invalid.json", "details:env"),
        ("output", "error-unavailable.json", "details:phase"),
        ("output", "error-network-error-tls.json", "variant:network_error:tls"),
        (
            "output",
            "error-wrong-host-response-not-http.json",
            "variant:wrong_host_response:not-http",
        ),
        ("output", "disabled.json", "exit:22"),
        ("output", "validate-probe-auth.json", "check:probe:failed"),
        ("output", "validate-test-message-failed.json", "check:test_message:failed"),
        ("output", "send-dry-run.json", "send:dry_run"),
        ("output", "send-sent-insecure.json", "send:warning:insecure_http"),
        ("output", "send-sent-truncated.json", "send:truncated:true"),
        ("output", "error-internal.json", "variant:internal:before-writing"),
        ("log", "send-rate-limited.jsonl", "log:failed/12/rate_limited/-"),
        ("log", "send-refused-link-scheme.jsonl", "log:refused/20/refused/link_scheme"),
        (
            "log",
            "send-wrong-host-response-not-http.jsonl",
            "log:outcome_unknown/12/wrong_host_response/-",
        ),
        ("request", "level_action.json", "request:level:action"),
        ("request", "title_cut.json", "request:title-cut"),
    ],
)
def test_removing_a_golden_names_what_is_lost(kind: str, name: str, lost: str) -> None:
    assert lost in gc.missing(_without(kind, name))


def _all_files() -> list[Any]:
    return [pytest.param(k, n, id=f"{k}/{n}") for k, names in LISTING.items() for n in names]


@pytest.mark.parametrize(("kind", "name"), _all_files())
def test_removing_any_golden_loses_exactly_the_items_only_it_shows(kind: str, name: str) -> None:
    rest = _without(kind, name)
    only_here = gc.covered({kind: {name: LISTING[kind][name]}}) - gc.covered(rest)
    assert set(gc.missing(rest)) == only_here - set(gc.NON_GOLDENABLE)


def test_a_golden_that_breaks_its_schema_is_reported() -> None:
    bad = copy.deepcopy(LISTING)
    doc = json.loads(bad["output"]["error-auth-required.json"])
    doc["error"]["retryable"] = True  # auth_required is never retryable
    bad["output"]["error-auth-required.json"] = json.dumps(doc) + "\n"
    assert any("error-auth-required.json" in p for p in gc.problems(bad))
    bad["log"]["send-sent.jsonl"] = bad["log"]["send-sent.jsonl"].replace('"exit":0', '"exit":12')
    assert any("send-sent.jsonl" in p for p in gc.problems(bad))
    bad["output"]["usage-no-command.json"] = "{not json}\n"
    assert any("not JSON" in p for p in gc.problems(bad))


def test_a_request_golden_that_breaks_the_rendered_schema_is_reported() -> None:
    bad = copy.deepcopy(LISTING)
    name = next(iter(bad["request"]))
    doc = json.loads(bad["request"][name])
    doc["unexpected"] = 1
    bad["request"][name] = json.dumps(doc)
    assert any(p.startswith(f"request/{name}") for p in gc.problems(bad))
    del doc["unexpected"]
    del doc["message"]
    bad["request"][name] = json.dumps(doc)
    assert any(p.startswith(f"request/{name}") for p in gc.problems(bad))


@pytest.mark.parametrize(("prefix", "level"), [("WARN:", "warn"), ("ACTION:", "action")])
def test_a_title_that_is_only_a_level_prefix_is_that_level(prefix: str, level: str) -> None:
    text = json.dumps({"title": prefix, "message": "m"})
    assert gc.covered({"request": {"x.json": text}}) >= {f"request:level:{level}"}
    assert "request:level:info" not in gc.covered({"request": {"x.json": text}})


def test_an_allowlisted_item_is_required_and_never_covered() -> None:
    assert set(gc.NON_GOLDENABLE) <= gc.required()
    assert not set(gc.NON_GOLDENABLE) & gc.covered(LISTING)
    assert all(reason for reason in gc.NON_GOLDENABLE.values())


# --- the requirement list is derived from the interface --------------------------------------


def test_the_exit_table_of_the_interface_matches_the_schema() -> None:
    defs: dict[str, Any] = load_schema("defs")["$defs"]
    table = gc.exit_table()
    assert set(table) == {str(e) for e in defs["exit_code"]["enum"]} | {"128+N"}
    codes = [c for row in ("1", "2", "12") for c in table[row]]
    assert sorted(codes + ["refused"]) == sorted(defs["error_code"]["enum"])
    assert table["20"] == defs["refusal_reason"]["enum"]
    assert table["22"] == ["disabled"] and table["0"] == []


def test_every_log_code_is_a_logged_one_or_an_exit_2_code() -> None:
    logged = {i.split("/")[2] for i in gc.required() if i.startswith("log:")} - {"-"}
    assert logged | {"usage", "config_invalid"} == set(
        load_schema("defs")["$defs"]["error_code"]["enum"]
    )


def test_the_required_items_include_every_exit_code_and_check() -> None:
    required = gc.required()
    for exit_code in (0, 1, 2, 12, 20, 22):
        assert f"exit:{exit_code}" in required
    for check in ("config", "credential", "probe", "test_message"):
        assert {f"check:{check}:ok", f"check:{check}:failed"} <= required
