"""Every schema loads, is draft 2020-12, accepts its positive samples and rejects its negatives.

Samples live in tests/samples/<schema name>.json:
  {"valid": {name: instance}, "invalid": {name: {"instance": ..., "path": [...]}}}
`path` is the instance location (list of keys/indexes) of at least one reported error, so a
negative sample must fail for the reason it names, not for some other one.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from tests.harness import ROOT, load_schema, schema_errors, schema_names

SAMPLES = Path(__file__).parent / "samples"
DRAFT = "https://json-schema.org/draft/2020-12/schema"
LF_SAFE_END = r"(?![\s\S])"
# Prefix checks that are not full matches, so a trailing LF is irrelevant: the scheme rule that
# applies when allow_insecure_http is not true (the base_url pattern itself is LF-safe).
PREFIX_ONLY_PATTERNS = {"^[Hh][Tt][Tt][Pp][Ss]://"}
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
    patterns = _patterns(load_schema(name))
    bad = [
        (w, p) for w, p in patterns if not p.endswith(LF_SAFE_END) and p not in PREFIX_ONLY_PATTERNS
    ]
    assert bad == []


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
def test_negative_sample_is_rejected_at_its_named_location(name: str, key: str) -> None:
    sample = _samples(name)["invalid"][key]
    errors = schema_errors(name, sample["instance"])
    assert errors, "negative sample was accepted"
    paths = [list(e.absolute_path) for e in errors]
    assert sample["path"] in paths, f"rejected at {paths}, expected {sample['path']}"


# The three patterns the issue names: the schema refuses a trailing LF, and so does a
# full match (which is how the tool applies every pattern).
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
    pattern = load_schema("defs")["$defs"]["actor"]["pattern"]
    for value, ok in [("human:me", True), ("auto:a.b", True), ("human:me\n", False)]:
        assert bool(re.fullmatch(pattern, value)) is ok
        assert bool(re.search(pattern, value)) is ok


def test_config_example_validates_against_the_config_schema() -> None:
    with (ROOT / "config.example.yaml").open(encoding="utf-8") as fh:
        example = yaml.safe_load(fh)
    assert [e.message for e in schema_errors("config", example)] == []
    # TODO(#8): loading config.example.yaml with the stated defaults is tested in the config issue.
