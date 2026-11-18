"""Tests of the schema and golden-file harness itself (tests/harness.py)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.harness import Golden, GoldenError, load_schema, schema_errors, schema_names


def test_schema_names_lists_every_schema_file_but_no_other_file() -> None:
    names = schema_names()
    assert "config" in names
    assert "cli/send" in names
    assert "defs" in names
    assert all(not n.endswith(".json") for n in names)


def test_load_schema_returns_the_parsed_document() -> None:
    assert load_schema("log")["$id"] == "ha-notice/log.json"


def test_load_schema_rejects_a_path_outside_the_schemas_directory() -> None:
    with pytest.raises(ValueError):
        load_schema("../pyproject")


def test_cross_file_refs_resolve() -> None:
    # cli/error.json references ../defs.json; an unresolvable ref would raise, not report.
    err = schema_errors("cli/error", {"error": {"code": "nope", "message": "x"}})
    assert err != []
    assert schema_errors("cli/error", {"error": {"code": "usage", "message": "x"}}) == []


def test_schema_errors_is_empty_for_a_valid_instance() -> None:
    assert schema_errors("cli/send", {"outcome": "disabled"}) == []


def test_schema_errors_reports_an_invalid_instance() -> None:
    assert schema_errors("cli/send", {"outcome": "bogus"}) != []


def test_golden_matches_an_identical_file(tmp_path: Path) -> None:
    g = Golden(root=tmp_path, update=False)
    (tmp_path / "request").mkdir()
    (tmp_path / "request" / "a.json").write_text('{"message":"x"}\n', encoding="utf-8")
    g.check("request", "a.json", '{"message":"x"}\n')


def test_golden_mismatch_fails_with_a_diff(tmp_path: Path) -> None:
    g = Golden(root=tmp_path, update=False)
    (tmp_path / "request").mkdir()
    (tmp_path / "request" / "a.json").write_text('{"message":"x"}\n', encoding="utf-8")
    with pytest.raises(GoldenError) as exc:
        g.check("request", "a.json", '{"message":"y"}\n')
    assert "--update-golden" in str(exc.value)
    assert '"x"' in str(exc.value) and '"y"' in str(exc.value)


def test_golden_trailing_newline_difference_is_a_mismatch(tmp_path: Path) -> None:
    g = Golden(root=tmp_path, update=False)
    (tmp_path / "output").mkdir()
    (tmp_path / "output" / "a.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(GoldenError):
        g.check("output", "a.json", "{}")


def test_golden_missing_file_fails_and_does_not_create_it(tmp_path: Path) -> None:
    g = Golden(root=tmp_path, update=False)
    with pytest.raises(GoldenError, match="missing"):
        g.check("log", "new.jsonl", "{}\n")
    assert not (tmp_path / "log" / "new.jsonl").exists()


def test_golden_update_writes_the_file_exactly(tmp_path: Path) -> None:
    g = Golden(root=tmp_path, update=True, env={})
    g.check("log", "d/new.jsonl", "ünï\r\n{}\n")
    assert (tmp_path / "log" / "d" / "new.jsonl").read_bytes() == "ünï\r\n{}\n".encode()
    # and a second, non-update run now matches
    Golden(root=tmp_path, update=False).check("log", "d/new.jsonl", "ünï\r\n{}\n")


def test_golden_update_is_refused_in_ci(tmp_path: Path) -> None:
    with pytest.raises(GoldenError, match="CI"):
        Golden(root=tmp_path, update=True, env={"CI": "true"})


def test_golden_update_is_refused_in_ci_even_when_ci_is_falsy_looking(tmp_path: Path) -> None:
    # Any non-empty CI value counts, including "false" and "0".
    with pytest.raises(GoldenError, match="CI"):
        Golden(root=tmp_path, update=True, env={"CI": "0"})


def test_golden_default_is_not_update_mode(tmp_path: Path) -> None:
    g = Golden(root=tmp_path)
    assert g.update is False


@pytest.mark.parametrize("name", ["../x.json", "/etc/passwd", "a/../../x", "", "a\\b", "a\x00b"])
def test_golden_rejects_names_that_escape_the_root(tmp_path: Path, name: str) -> None:
    g = Golden(root=tmp_path, update=False)
    with pytest.raises(ValueError):
        g.check("output", name, "{}")


def test_golden_rejects_unknown_kinds(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        Golden(root=tmp_path).check("other", "a.json", "{}")


def test_golden_rejects_a_symlinked_golden_file(tmp_path: Path) -> None:
    (tmp_path / "output").mkdir()
    target = tmp_path / "elsewhere.json"
    target.write_text("{}\n", encoding="utf-8")
    (tmp_path / "output" / "a.json").symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        Golden(root=tmp_path).check("output", "a.json", "{}\n")


def test_golden_validates_actual_text_against_a_schema_before_comparing(
    tmp_path: Path,
) -> None:
    g = Golden(root=tmp_path, update=False)
    (tmp_path / "output").mkdir()
    bad = '{"outcome":"bogus"}\n'
    (tmp_path / "output" / "a.json").write_text(bad, encoding="utf-8")
    # Identical to the golden, still refused: a golden that violates its schema is a bug.
    with pytest.raises(GoldenError, match="schema"):
        g.check("output", "a.json", bad, schema="cli/send")


def test_golden_schema_check_accepts_a_valid_output(tmp_path: Path) -> None:
    g = Golden(root=tmp_path, update=False)
    (tmp_path / "output").mkdir()
    ok = '{"outcome":"disabled"}\n'
    (tmp_path / "output" / "a.json").write_text(ok, encoding="utf-8")
    g.check("output", "a.json", ok, schema="cli/send")


def test_golden_schema_check_validates_each_line_of_a_log(tmp_path: Path) -> None:
    g = Golden(root=tmp_path, update=False)
    (tmp_path / "log").mkdir()
    text = '{"a":1}\n{"b":2}\n'
    (tmp_path / "log" / "x.jsonl").write_text(text, encoding="utf-8")
    with pytest.raises(GoldenError, match="schema"):
        g.check("log", "x.jsonl", text, schema="log")


def test_golden_schema_check_refuses_text_that_is_not_json(tmp_path: Path) -> None:
    g = Golden(root=tmp_path, update=False)
    with pytest.raises(GoldenError, match="JSON"):
        g.check("output", "a.json", "not json", schema="cli/send")
