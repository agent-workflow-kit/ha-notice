"""Schema and golden-file harness shared by the tests.

Schemas: `schema_errors(name, instance)` validates against `schemas/<name>.json` (JSON Schema
draft 2020-12, cross-file `$ref`s resolved from the local files, never the network).

Golden files: `Golden.check(kind, name, actual)` compares exact text with
`tests/golden/<kind>/<name>`. `kind` is `output` (a --json output), `request` (a Home Assistant
request body) or `log` (log.jsonl records). A mismatch or a missing file fails. Update mode
rewrites the file; it is on only with `pytest --update-golden` and is refused when the `CI`
environment variable is set, so CI can never rewrite what it is meant to check.

TODO(#30): golden files for every --json output, request body and log record.
TODO(#6): golden files for the CLI (version, usage errors).
TODO(#7): golden files for send and validate output.
"""

from __future__ import annotations

import difflib
import json
import os
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = ROOT / "schemas"
GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
KINDS = ("output", "request", "log")


class GoldenError(AssertionError):
    """A golden-file check failed (or update mode was refused)."""


def schema_names() -> list[str]:
    """Every schema as a name relative to schemas/ without `.json` (`cli/send`, `defs`)."""
    return sorted(
        p.relative_to(SCHEMAS_DIR).with_suffix("").as_posix() for p in SCHEMAS_DIR.rglob("*.json")
    )


def schema_path(name: str) -> Path:
    path = (SCHEMAS_DIR / f"{name}.json").resolve()
    if not path.is_relative_to(SCHEMAS_DIR.resolve()):
        raise ValueError(f"schema name escapes schemas/: {name!r}")
    return path


def load_schema(name: str) -> dict[str, Any]:
    with schema_path(name).open(encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def _registry() -> Registry[Any]:
    resources = []
    for name in schema_names():
        doc = load_schema(name)
        resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources)


def validator(name: str) -> Draft202012Validator:
    """A validator for one schema. No format assertions: the schemas use patterns only."""
    return Draft202012Validator(load_schema(name), registry=_registry())


def schema_errors(name: str, instance: Any) -> list[ValidationError]:
    return list(validator(name).iter_errors(instance))


def _check_name(name: str) -> None:
    parts = name.split("/")
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or "\x00" in name
        or any(p in ("", ".", "..") for p in parts)
    ):
        raise ValueError(f"unsafe golden name: {name!r}")


class Golden:
    def __init__(
        self,
        root: Path = GOLDEN_DIR,
        update: bool = False,
        env: Mapping[str, str] | None = None,
    ) -> None:
        if update and (os.environ if env is None else env).get("CI"):
            raise GoldenError("golden update mode is refused when CI is set")
        self.root = root
        self.update = update

    def path(self, kind: str, name: str) -> Path:
        if kind not in KINDS:
            raise ValueError(f"unknown golden kind {kind!r}; expected one of {KINDS}")
        _check_name(name)
        return self.root / kind / name

    def check(self, kind: str, name: str, actual: str, schema: str | None = None) -> None:
        path = self.path(kind, name)
        if schema is not None:
            _validate_text(schema, actual, kind)
        if path.is_symlink():
            raise ValueError(f"golden file is a symlink: {path}")
        if self.update:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8", newline="") as fh:
                fh.write(actual)
            return
        if not path.is_file():
            raise GoldenError(
                f"golden file missing: {path}; create it with pytest --update-golden "
                "(never in CI) and review it"
            )
        with path.open(encoding="utf-8", newline="") as fh:
            expected = fh.read()
        if expected != actual:
            diff = "".join(
                difflib.unified_diff(
                    expected.splitlines(keepends=True),
                    actual.splitlines(keepends=True),
                    "golden",
                    "actual",
                )
            )
            raise GoldenError(
                f"golden mismatch for {path} (exact text, including newlines):\n{diff}\n"
                "If the change is intended, rerun with --update-golden and review the diff."
            )


def _validate_text(schema: str, text: str, kind: str) -> None:
    docs = [ln for ln in text.split("\n") if ln] if kind == "log" else [text]
    for doc in docs:
        try:
            instance = json.loads(doc)
        except ValueError as exc:
            raise GoldenError(f"text is not JSON ({exc.__class__.__name__})") from exc
        errors = schema_errors(schema, instance)
        if errors:
            raise GoldenError(
                f"text violates schema {schema}: {errors[0].message} at /"
                + "/".join(str(p) for p in errors[0].absolute_path)
            )
