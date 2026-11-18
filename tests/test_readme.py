"""README checks: the example config is the shipped file, and local links resolve."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
SKIPPED_DIRS = {"node_modules", "__pycache__"}


def _markdown_documents() -> list[Path]:
    """Every *.md file outside hidden directories (.venv, .git, .github, ...)."""
    found = []
    for path in ROOT.rglob("*.md"):
        parts = path.relative_to(ROOT).parts
        if any(part.startswith(".") or part in SKIPPED_DIRS for part in parts):
            continue
        found.append(path)
    return sorted(found)


DOCS = _markdown_documents()

EXAMPLE_MARKER = "<!-- config.example.yaml -->"
COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
ATX = re.compile(r"^ {0,3}#{1,6}(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$")
SETEXT = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
INLINE_LINK = re.compile(
    r"!?\[[^\]]*\]\(\s*(<[^>]*>|(?:[^()\s]|\([^()\s]*\))+)"
    r"(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?\s*\)"
)
REFERENCE_DEFINITION = re.compile(r"^ {0,3}\[[^\]]+\]:[ \t]*(<[^>]*>|\S+)", re.MULTILINE)
HREF = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _non_code_lines(text: str) -> list[str]:
    """Lines outside fenced code blocks and HTML comments, in order."""
    out: list[str] = []
    fence = ""
    for line in COMMENT.sub("", text).splitlines():
        match = FENCE.match(line)
        if fence:
            closing = re.match(rf"^ {{0,3}}{re.escape(fence[0])}{{{len(fence)},}}[ \t]*$", line)
            if closing:
                fence = ""
            continue
        if match:
            fence = match.group(1)
            continue
        out.append(line)
    return out


def _strip_code(text: str) -> str:
    """Remove fenced code blocks, HTML comments and inline code."""
    return "\n".join(re.sub(r"`[^`]*`", "", line) for line in _non_code_lines(text))


def _slug(heading: str) -> str:
    """GitHub's anchor rule: lowercase, drop punctuation except hyphens, spaces to hyphens."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # link text only
    text = re.sub(r"<[^>]+>", "", text)  # HTML tags
    text = text.replace("`", "")
    text = text.lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    """Heading anchors with GitHub's duplicate numbering (github-slugger)."""
    occurrences: dict[str, int] = {}
    anchors: set[str] = set()
    lines = _non_code_lines(path.read_text(encoding="utf-8"))
    for index, line in enumerate(lines):
        heading: str | None = None
        match = ATX.match(line)
        if match:
            heading = match.group(1) or ""
        elif (
            SETEXT.match(line)
            and index > 0
            and lines[index - 1].strip()
            and not ATX.match(lines[index - 1])
            and not SETEXT.match(lines[index - 1])
        ):
            heading = lines[index - 1].strip()
        if heading is None:
            continue
        slug = original = _slug(heading)
        while slug in occurrences:
            occurrences[original] += 1
            slug = f"{original}-{occurrences[original]}"
        occurrences[slug] = 0
        anchors.add(slug)
    return anchors


def _local_links(path: Path) -> list[tuple[str, str]]:
    """Decoded (target, fragment) of every relative link, image, reference definition and href."""
    text = COMMENT.sub("", path.read_text(encoding="utf-8"))
    code_free = _strip_code(text)
    raw = [m.group(1) for m in INLINE_LINK.finditer(code_free)]
    raw += [m.group(1) for m in REFERENCE_DEFINITION.finditer(code_free)]
    raw += [m.group(1) for m in HREF.finditer(code_free)]
    links: list[tuple[str, str]] = []
    for link in raw:
        if link.startswith("<") and link.endswith(">"):
            link = link[1:-1]
        if re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", link):
            continue
        target, _, fragment = link.partition("#")
        links.append((unquote(target), unquote(fragment)))
    return links


def test_readme_example_config_is_config_example_yaml() -> None:
    text = README.read_text(encoding="utf-8")
    assert text.count(EXAMPLE_MARKER) == 1
    after = text.split(EXAMPLE_MARKER, 1)[1]
    match = re.match(r"\n+```yaml\n(.*?)\n```\n", after, re.DOTALL)
    assert match is not None, "the marker must be followed by a fenced yaml block"
    expected = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
    assert match.group(1) + "\n" == expected


@pytest.mark.parametrize("path", DOCS, ids=lambda p: p.name)
def test_relative_links_resolve(path: Path) -> None:
    assert _problems(path, root=ROOT) == []


def _problems(path: Path, root: Path | None = None) -> list[str]:
    root = root or path.parent
    problems: list[str] = []
    for target, fragment in _local_links(path):
        dest = (path.parent / target).resolve() if target else path
        shown = target + (f"#{fragment}" if fragment else "")
        if not dest.is_relative_to(root) or not dest.exists():
            problems.append(f"{shown}: no such file inside the repository")
        elif fragment and dest.suffix == ".md" and fragment not in _anchors(dest):
            problems.append(f"{shown}: no such heading")
    return problems


def test_every_checked_document_has_links() -> None:
    assert sum(len(_local_links(p)) for p in DOCS) > 10


def test_slug_rules() -> None:
    assert _slug("Calling from automation") == "calling-from-automation"
    assert _slug("`send`") == "send"
    assert _slug("Set up Home Assistant") == "set-up-home-assistant"
    assert _slug("Config and environment (v1)") == "config-and-environment-v1"
    assert _slug("What it does: a-b") == "what-it-does-a-b"


def test_duplicate_headings_get_numbered_anchors(tmp_path: Path) -> None:
    doc = tmp_path / "d.md"
    doc.write_text("# A\n\n## Same\n\n## Same\n\n```\n# not a heading\n```\n", encoding="utf-8")
    assert _anchors(doc) == {"a", "same", "same-1"}


def test_a_broken_anchor_is_detected() -> None:
    assert "no-such-heading" not in _anchors(ROOT / "docs" / "interface.md")
    assert "exit-codes" in _anchors(ROOT / "docs" / "interface.md")


def _write(tmp_path: Path, text: str) -> Path:
    doc = tmp_path / "d.md"
    doc.write_text(text, encoding="utf-8")
    return doc


def test_link_extraction_covers_all_link_forms(tmp_path: Path) -> None:
    doc = _write(
        tmp_path,
        '[a](a.md "title")\n'
        "[b](<sp ace.md>)\n"
        "![i](img.png)\n"
        "[r]: ref.md\n"
        '<a href="h.md">x</a>\n'
        "[c](p%20q.md#frag%20x)\n"
        "[d](dir/a(1).md)\n"
        "[e](https://example.org/x)\n"
        "`[code](code.md)`\n",
    )
    assert sorted(_local_links(doc)) == sorted(
        [
            ("a.md", ""),
            ("sp ace.md", ""),
            ("img.png", ""),
            ("ref.md", ""),
            ("h.md", ""),
            ("p q.md", "frag x"),
            ("dir/a(1).md", ""),
        ]
    )


def test_a_broken_image_target_is_reported(tmp_path: Path) -> None:
    doc = _write(tmp_path, "![i](missing.png)\n")
    assert _problems(doc) == ["missing.png: no such file inside the repository"]


def test_a_broken_reference_definition_is_reported(tmp_path: Path) -> None:
    doc = _write(tmp_path, "[r]: missing.md\n")
    assert len(_problems(doc)) == 1


def test_a_broken_href_is_reported(tmp_path: Path) -> None:
    doc = _write(tmp_path, '<a href="missing.md">x</a>\n')
    assert len(_problems(doc)) == 1


def test_a_percent_encoded_fragment_is_decoded(tmp_path: Path) -> None:
    doc = _write(tmp_path, "# Café\n\n[x](#caf%C3%A9)\n")
    assert _problems(doc) == []


def test_closing_fence_must_be_at_least_as_long_as_the_opener(tmp_path: Path) -> None:
    doc = _write(tmp_path, "````\n```\n# inside\n````\n# After\n")
    assert _anchors(doc) == {"after"}


def test_indented_headings_count(tmp_path: Path) -> None:
    assert _anchors(_write(tmp_path, "   ## Indented\n")) == {"indented"}


def test_headings_in_html_comments_are_skipped(tmp_path: Path) -> None:
    doc = _write(tmp_path, "<!--\n# Hidden\n-->\n# Shown\n")
    assert _anchors(doc) == {"shown"}


def test_html_tags_are_stripped_from_slugs(tmp_path: Path) -> None:
    assert _anchors(_write(tmp_path, "# A <b>bold</b> word\n")) == {"a-bold-word"}


def test_duplicate_numbering_matches_github(tmp_path: Path) -> None:
    assert _anchors(_write(tmp_path, "# Foo\n\n# Foo\n\n# Foo-1\n")) == {"foo", "foo-1", "foo-1-1"}


def test_setext_headings_produce_anchors(tmp_path: Path) -> None:
    assert _anchors(_write(tmp_path, "Title one\n=========\n\nTitle two\n---\n")) == {
        "title-one",
        "title-two",
    }


def test_all_markdown_documents_are_checked() -> None:
    names = {p.relative_to(ROOT).as_posix() for p in DOCS}
    assert {"README.md", "CLAUDE.md", "CHANGELOG.md", "docs/design.md"} <= names
    assert not any(part.startswith(".") for p in DOCS for part in p.relative_to(ROOT).parts)


def test_readme_has_links() -> None:
    assert len(_local_links(README)) > 10


def test_readme_keeps_the_pending_automation_marker() -> None:
    # Remove this test and the marker in README.md together when #33 lands.
    assert "<!-- TODO(#33):" in README.read_text(encoding="utf-8"), "remove with #33"
