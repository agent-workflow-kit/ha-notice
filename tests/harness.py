"""Schema and golden-file harness shared by the tests.

Schemas: `schema_errors(name, instance)` validates against `schemas/<name>.json` (JSON Schema
draft 2020-12, cross-file `$ref`s resolved from the local files, never the network).

Golden files: `Golden.check(kind, name, actual)` compares exact text with
`tests/golden/<kind>/<name>`. `kind` is `output` (a --json output), `request` (a Home Assistant
request body) or `log` (log.jsonl records). A mismatch or a missing file fails. Update mode
atomically rewrites an existing file (it never creates a file or a directory: goldens are
created by hand in the issue that owns them); it is on only with `pytest --update-golden` and
is refused when the `CI` environment variable is set, so CI can never rewrite what it is meant
to check. A symlink at any component below the golden root is refused in both modes.

TODO(#30): golden files for every --json output, request body and log record.
Usage-error goldens (#6) live in tests/golden/output/usage-*.json; the version line is not a
golden because the release job bumps the version (tests/test_cli.py compares with pyproject).
Goldens of the error envelope and of the disabled outcome (#7) are
tests/golden/output/error-*.json and disabled.json.
TODO(#27): golden files for send output. TODO(#28): golden files for validate output.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import tempfile
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


_NAME_SEGMENT = re.compile(r"[a-z0-9._-]+")


def schema_error_pairs(name: str, instance: Any) -> set[tuple[tuple[str | int, ...], str]]:
    """Every (instance path, keyword) the schema reports, including inside oneOf/anyOf branches."""
    pairs: set[tuple[tuple[str | int, ...], str]] = set()

    def walk(errors: list[ValidationError]) -> None:
        for err in errors:
            pairs.add((tuple(err.absolute_path), str(err.validator)))
            walk(list(err.context or []))

    walk(schema_errors(name, instance))
    return pairs


def _check_name(name: str) -> None:
    """Golden names are `/`-joined segments of [a-z0-9._-], none starting or ending with `.`.

    Lowercase only, so two names can never collide on a case-insensitive filesystem; no
    whitespace or control characters, so a name is the same everywhere.
    """
    parts = name.split("/")
    if not name or any(
        _NAME_SEGMENT.fullmatch(p) is None or p.startswith(".") or p.endswith(".") for p in parts
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

    def _refuse_symlinks(self, path: Path) -> None:
        """Refuse a symlink at any component below the root, and a path that leaves the root."""
        current = self.root
        for part in path.relative_to(self.root).parts:
            current = current / part
            if current.is_symlink():
                raise ValueError(f"golden path contains a symlink: {current}")
        if not path.resolve().is_relative_to(self.root.resolve()):
            raise ValueError(f"golden path leaves the golden root: {path}")

    def check(self, kind: str, name: str, actual: str, schema: str | None = None) -> None:
        path = self.path(kind, name)
        if schema is not None:
            _validate_text(schema, actual, kind)
        self._refuse_symlinks(path)
        if self.update:
            self._rewrite(path, actual)
            return
        if not path.is_file():
            raise GoldenError(
                f"golden file missing: {path}; goldens are created by hand in the issue "
                "that owns them, then reviewed"
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

    @staticmethod
    def _rewrite(path: Path, actual: str) -> None:
        """Update mode: replace an existing golden atomically; never create a file or directory."""
        if not path.is_file():
            raise GoldenError(
                f"golden file missing: {path}; update mode only rewrites existing goldens, "
                "create new ones by hand in the issue that owns them"
            )
        data = actual.encode("utf-8")  # first: a failed encode leaves the golden untouched
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".golden-", suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            shutil.copymode(path, tmp)
            os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise


class _StrictJSONError(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _StrictJSONError("duplicate object key")
    return dict(pairs)


def _no_constant(value: str) -> Any:
    raise _StrictJSONError(f"non-standard constant {value}")


def _validate_text(schema: str, text: str, kind: str) -> None:
    if kind == "log":
        if not text:
            raise GoldenError("log text is empty")
        if "\r" in text:
            raise GoldenError("log text contains a CR; records end with a single LF")
        if not text.endswith("\n"):
            raise GoldenError("log text must end with a LF after the last record")
        docs = text[:-1].split("\n")
        if any(not d for d in docs):
            raise GoldenError("log text has a blank line (or more than one final LF)")
    elif not text:
        raise GoldenError("text is empty (not JSON)")
    else:
        docs = [text]
    for doc in docs:
        try:
            instance = json.loads(
                doc, object_pairs_hook=_no_duplicates, parse_constant=_no_constant
            )
        except _StrictJSONError as exc:
            raise GoldenError(f"text is not strict JSON: {exc}") from exc
        except (ValueError, RecursionError) as exc:
            raise GoldenError(f"text is not JSON ({exc.__class__.__name__})") from exc
        errors = schema_errors(schema, instance)
        if errors:
            raise GoldenError(
                f"text violates schema {schema}: {errors[0].message} at /"
                + "/".join(str(p) for p in errors[0].absolute_path)
            )
