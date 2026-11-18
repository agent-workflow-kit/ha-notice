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


def test_golden_update_rewrites_an_existing_file_exactly(tmp_path: Path) -> None:
    (tmp_path / "log" / "d").mkdir(parents=True)
    (tmp_path / "log" / "d" / "new.jsonl").write_text("old\n", encoding="utf-8")
    g = Golden(root=tmp_path, update=True, env={})
    g.check("log", "d/new.jsonl", "ünï\r\n{}\n")
    assert (tmp_path / "log" / "d" / "new.jsonl").read_bytes() == "ünï\r\n{}\n".encode()
    # and a second, non-update run now matches
    Golden(root=tmp_path, update=False).check("log", "d/new.jsonl", "ünï\r\n{}\n")


def test_golden_update_does_not_create_a_missing_file(tmp_path: Path) -> None:
    (tmp_path / "log").mkdir()
    g = Golden(root=tmp_path, update=True, env={})
    with pytest.raises(GoldenError, match="by hand"):
        g.check("log", "new.jsonl", "{}\n")
    assert not (tmp_path / "log" / "new.jsonl").exists()


def test_golden_update_does_not_create_missing_directories(tmp_path: Path) -> None:
    g = Golden(root=tmp_path, update=True, env={})
    with pytest.raises(GoldenError, match="by hand"):
        g.check("log", "d/new.jsonl", "{}\n")
    assert list(tmp_path.iterdir()) == []


def test_golden_update_leaves_the_file_untouched_when_the_text_cannot_be_encoded(
    tmp_path: Path,
) -> None:
    (tmp_path / "output").mkdir()
    target = tmp_path / "output" / "a.json"
    target.write_text("keep\n", encoding="utf-8")
    g = Golden(root=tmp_path, update=True, env={})
    with pytest.raises(UnicodeEncodeError):
        g.check("output", "a.json", "\ud800")  # a lone surrogate has no UTF-8 encoding
    assert target.read_text(encoding="utf-8") == "keep\n"
    assert [p.name for p in (tmp_path / "output").iterdir()] == ["a.json"]


def test_golden_update_replaces_atomically_and_leaves_no_temp_file(tmp_path: Path) -> None:
    (tmp_path / "output").mkdir()
    target = tmp_path / "output" / "a.json"
    target.write_text("old\n", encoding="utf-8")
    inode_before = target.stat().st_ino
    Golden(root=tmp_path, update=True, env={}).check("output", "a.json", "new\n")
    assert target.read_text(encoding="utf-8") == "new\n"
    assert target.stat().st_ino != inode_before  # a new file renamed over it, not rewritten
    assert [p.name for p in (tmp_path / "output").iterdir()] == ["a.json"]


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


@pytest.mark.parametrize(
    "name",
    [
        "../x.json",
        "/etc/passwd",
        "a/../../x",
        "",
        "a\\b",
        "a\x00b",
        "A.json",  # uppercase: collides with a.json on a case-insensitive filesystem
        "a b.json",
        "a\tb.json",
        "a\nb.json",
        "a.json\n",
        "a\x7fb.json",
        ".hidden",
        "a/.hidden",
        "a.",
        "a./b.json",
        "a//b.json",
        "a/ b",
        "é.json",
    ],
)
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


def _symlink_setup(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "golden"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    return root, outside


@pytest.mark.parametrize("update", [False, True])
def test_golden_rejects_a_symlinked_directory_component(tmp_path: Path, update: bool) -> None:
    root, outside = _symlink_setup(tmp_path)
    (outside / "a.json").write_text("{}\n", encoding="utf-8")
    (root / "output").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        Golden(root=root, update=update, env={}).check("output", "a.json", "{}\n")
    assert (outside / "a.json").read_text(encoding="utf-8") == "{}\n"


@pytest.mark.parametrize("update", [False, True])
def test_golden_rejects_a_symlinked_subdirectory_component(tmp_path: Path, update: bool) -> None:
    root, outside = _symlink_setup(tmp_path)
    (root / "log").mkdir()
    (outside / "x.jsonl").write_text("{}\n", encoding="utf-8")
    (root / "log" / "d").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        Golden(root=root, update=update, env={}).check("log", "d/x.jsonl", "{}\n")


def test_golden_update_does_not_write_through_a_symlinked_file(tmp_path: Path) -> None:
    root, outside = _symlink_setup(tmp_path)
    (root / "output").mkdir()
    (outside / "t.json").write_text("keep\n", encoding="utf-8")
    (root / "output" / "a.json").symlink_to(outside / "t.json")
    with pytest.raises(ValueError, match="symlink"):
        Golden(root=root, update=True, env={}).check("output", "a.json", "new\n")
    assert (outside / "t.json").read_text(encoding="utf-8") == "keep\n"


def test_golden_rejects_a_symlinked_root_component_resolving_elsewhere(tmp_path: Path) -> None:
    # The root itself may be reached through a symlink (tmp dirs often are); what matters is
    # that nothing below it is one and that the resolved path stays under the resolved root.
    real = tmp_path / "real"
    (real / "output").mkdir(parents=True)
    (real / "output" / "a.json").write_text("{}\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    Golden(root=link).check("output", "a.json", "{}\n")


@pytest.mark.parametrize("update", [False, True])
def test_golden_a_directory_named_like_the_file_is_not_a_golden(
    tmp_path: Path, update: bool
) -> None:
    (tmp_path / "output" / "a.json").mkdir(parents=True)
    with pytest.raises(GoldenError):
        Golden(root=tmp_path, update=update, env={}).check("output", "a.json", "{}\n")


@pytest.mark.parametrize(
    "text",
    [
        '{"a":1,"a":2}',  # duplicate key
        '{"o":{"a":1,"a":2}}',  # duplicate key, nested
        '{"a":NaN}',
        '{"a":Infinity}',
        '{"a":-Infinity}',
        "",
    ],
)
def test_golden_schema_check_rejects_non_strict_json(tmp_path: Path, text: str) -> None:
    with pytest.raises(GoldenError, match="JSON"):
        Golden(root=tmp_path).check("output", "a.json", text, schema="cli/send")


@pytest.mark.parametrize(
    "text",
    [
        "",
        '{"tool":"ha-notice"}',  # no final LF
        '{"tool":"ha-notice"}\n\n',  # two final LFs
        '\n{"tool":"ha-notice"}\n',  # leading blank line
        '{"tool":"ha-notice"}\n\n{"tool":"ha-notice"}\n',  # blank line between records
        '{"tool":"ha-notice"}\r\n',  # CR
        '{"tool":"ha-notice"}\n{"tool":"ha-notice"}',  # last record without LF
    ],
)
def test_golden_log_text_must_be_lf_terminated_records_without_blank_lines(
    tmp_path: Path, text: str
) -> None:
    with pytest.raises(GoldenError, match="log"):
        Golden(root=tmp_path).check("log", "x.jsonl", text, schema="defs")
