"""Every schema loads, is draft 2020-12, accepts its positive samples and rejects its negatives.

Samples live in tests/samples/<schema name>.json:
  {"valid": {name: instance}, "invalid": {name: {"instance": ..., "path": [...], "keyword": k}}}
`path` is the instance location (list of keys/indexes) and `keyword` the schema keyword
(`required`, `pattern`, `const`, ...) of one reported error (errors inside oneOf/anyOf branches
included), so a negative sample must fail for the reason it names, not for some other one.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from tests.harness import ROOT, load_schema, schema_error_pairs, schema_errors, schema_names

SAMPLES = Path(__file__).parent / "samples"
DRAFT = "https://json-schema.org/draft/2020-12/schema"
LF_SAFE_END = r"(?![\s\S])"
# The one pattern that is a prefix check, not a full match, so a trailing LF is irrelevant: the
# scheme rule of config.json that applies when allow_insecure_http is not true (the base_url
# pattern itself is LF-safe). Keyed by schema name, location and exact pattern.
PREFIX_ONLY_PATTERN = ("config", "/allOf/0/then/base_url", "^[Hh][Tt][Tt][Pp][Ss]://")
# defs.json holds shared definitions only; its definitions are exercised through the others.
SAMPLED = [n for n in schema_names() if n != "defs"]


def _samples(name: str) -> dict[str, Any]:
    with (SAMPLES / f"{name}.json").open(encoding="utf-8") as fh:
        return json.load(fh)


def _cases(kind: str) -> list[Any]:
    return [pytest.param(n, k, id=f"{n}:{k}") for n in SAMPLED for k in _samples(n)[kind]]


def _patterns(node: Any, where: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                found.append((where, value))
            elif key == "properties" and isinstance(value, dict):
                for prop, sub in value.items():
                    found += _patterns(sub, f"{where}/{prop}")
            else:
                found += _patterns(value, f"{where}/{key}")
    elif isinstance(node, list):
        for i, item in enumerate(node):
            found += _patterns(item, f"{where}/{i}")
    return found


@pytest.mark.parametrize("name", schema_names())
def test_schema_is_a_valid_draft_2020_12_schema(name: str) -> None:
    schema = load_schema(name)
    assert schema["$schema"] == DRAFT
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("name", schema_names())
def test_schema_id_matches_its_path(name: str) -> None:
    assert load_schema(name)["$id"] == f"ha-notice/{name}.json"


@pytest.mark.parametrize("name", schema_names())
def test_every_pattern_refuses_a_trailing_lf(name: str) -> None:
    # JSON Schema `$` accepts a trailing LF; every pattern must end with (?![\s\S]) instead.
    bad = [
        (w, p)
        for w, p in _patterns(load_schema(name))
        if not p.endswith(LF_SAFE_END) and (name, w, p) != PREFIX_ONLY_PATTERN
    ]
    assert bad == []


@pytest.mark.parametrize("name", schema_names())
def test_every_pattern_is_anchored_at_the_start_and_has_no_dollar(name: str) -> None:
    # A pattern is a search, so it must start with ^; an unescaped $ would accept a trailing LF.
    unanchored = [(w, p) for w, p in _patterns(load_schema(name)) if not p.startswith("^")]
    dollars = [(w, p) for w, p in _patterns(load_schema(name)) if "$" in re.sub(r"\\.", "", p)]
    assert unanchored == []
    assert dollars == []


def test_only_the_scheme_prefix_pattern_is_exempt_from_the_lf_guard() -> None:
    name, where, pattern = PREFIX_ONLY_PATTERN
    assert (where, pattern) in _patterns(load_schema(name))
    # and it is not the schema's own base_url pattern: that one is LF-safe
    assert load_schema(name)["properties"]["base_url"]["pattern"].endswith(LF_SAFE_END)


@pytest.mark.parametrize("name", SAMPLED)
def test_a_schema_has_positive_and_negative_samples(name: str) -> None:
    samples = _samples(name)
    assert samples["valid"] and samples["invalid"]


def test_every_sample_file_belongs_to_a_schema() -> None:
    files = {p.relative_to(SAMPLES).with_suffix("").as_posix() for p in SAMPLES.rglob("*.json")}
    assert files == set(SAMPLED)


@pytest.mark.parametrize(("name", "key"), _cases("valid"))
def test_positive_sample_validates(name: str, key: str) -> None:
    instance = _samples(name)["valid"][key]
    assert [e.message for e in schema_errors(name, instance)] == []


@pytest.mark.parametrize(("name", "key"), _cases("invalid"))
def test_negative_sample_is_rejected_at_its_named_location_for_its_named_keyword(
    name: str, key: str
) -> None:
    sample = _samples(name)["invalid"][key]
    assert set(sample) == {"instance", "path", "keyword"}
    pairs = schema_error_pairs(name, sample["instance"])
    assert pairs, "negative sample was accepted"
    assert (tuple(sample["path"]), sample["keyword"]) in pairs, (
        f"expected {sample['keyword']} at {sample['path']}, got {sorted(map(str, pairs))}"
    )


def _without(instance: dict[str, Any], field: str) -> dict[str, Any]:
    return {k: v for k, v in instance.items() if k != field}


def _required_cases(name: str, samples: list[str]) -> list[Any]:
    return [
        pytest.param(name, s, field, id=f"{name}:{s}:{field}")
        for s in samples
        for field in _samples(name)["valid"][s]
    ]


@pytest.mark.parametrize(
    ("name", "sample", "field"),
    _required_cases("log", list(_samples("log")["valid"]))
    + _required_cases("cli/send", ["sent", "sent_with_key_and_warning", "dry_run"]),
)
def test_removing_any_field_of_a_log_record_or_send_output_fails_as_required(
    name: str, sample: str, field: str
) -> None:
    instance = _without(copy.deepcopy(_samples(name)["valid"][sample]), field)
    assert ((), "required") in schema_error_pairs(name, instance)


def test_the_log_schema_requires_exactly_the_fields_of_a_record() -> None:
    record = _samples("log")["valid"]["sent"]
    assert set(load_schema("log")["required"]) == set(record)


_LEVELS = ["info", "warn", "action", "error"]


@pytest.mark.parametrize("level", _LEVELS)
def test_level_prefix_refuses_a_trailing_lf(level: str) -> None:
    assert schema_errors("config", {"level_prefix": {level: "WARN:"}}) == []
    assert schema_errors("config", {"level_prefix": {level: "WARN:\n"}}) != []
    assert schema_errors("config", {"level_prefix": {level: "\n"}}) != []


def test_link_hosts_refuses_a_trailing_lf() -> None:
    assert schema_errors("config", {"link_hosts": ["example.com"]}) == []
    assert schema_errors("config", {"link_hosts": ["example.com\n"]}) != []
    assert schema_errors("config", {"link_hosts": ["example.com", "b.example.org\n"]}) != []


# token_env and default_group: the schema refuses a trailing LF, and so does a full match (which
# is how the tool applies every pattern). The actor pattern has its own test below.
# The tool's token_env check (config.token_env_ok) is compared in tests/test_config_url.py.
# The tool's default_group check (a full match) is compared in tests/test_config_keys.py.
@pytest.mark.parametrize(
    ("schema", "path", "good"),
    [
        ("config", ["token_env"], "HA_TOKEN"),
        ("config", ["default_group"], "my-group_1"),
    ],
)
def test_config_patterns_agree_with_a_full_match(schema: str, path: list[str], good: str) -> None:
    pattern = load_schema(schema)["properties"][path[0]]["pattern"]
    for value, ok in [(good, True), (good + "\n", False), ("\n" + good, False), ("", False)]:
        assert bool(re.fullmatch(pattern, value)) is ok
        assert (schema_errors(schema, {path[0]: value}) == []) is ok


def test_actor_pattern_agrees_with_a_full_match() -> None:
    # The tool's own check (cli.ACTOR_RE, a full match) is compared in tests/test_cli.py.
    pattern = load_schema("defs")["$defs"]["actor"]["pattern"]
    for value, ok in [("human:me", True), ("auto:a.b", True), ("human:me\n", False)]:
        assert bool(re.fullmatch(pattern, value)) is ok
        assert bool(re.search(pattern, value)) is ok


def test_config_example_validates_against_the_config_schema() -> None:
    with (ROOT / "config.example.yaml").open(encoding="utf-8") as fh:
        example = yaml.safe_load(fh)
    assert [e.message for e in schema_errors("config", example)] == []
    # Loading config.example.yaml with the stated defaults is tested in
    # tests/test_config_keys.py::test_the_example_loads_with_the_stated_defaults.


@pytest.mark.parametrize("key", ["timeout", "connect_timeout"])
@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("1s", True),
        ("0.5s", True),
        ("1000ms", True),
        ("10", True),
        ("0", True),
        ("010", False),
        ("01.5s", False),
        ("00s", False),
        ("10\n", False),
    ],
)
def test_duration_string_samples(key: str, value: str, ok: bool) -> None:
    assert (schema_errors("config", {key: value}) == []) is ok
