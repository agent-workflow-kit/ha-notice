"""README checks: the example config is the shipped file, and local links resolve."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
DOCS = sorted([README, *(ROOT / "docs").glob("*.md")])

EXAMPLE_MARKER = "<!-- config.example.yaml -->"
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")


def _strip_code(text: str) -> str:
    """Remove fenced code blocks and inline code so their content is not read as links."""
    out: list[str] = []
    fence = ""
    for line in text.splitlines():
        stripped = line.lstrip()
        marker = stripped[:3]
        if fence:
            if stripped.startswith(fence):
                fence = ""
            continue
        if marker in ("```", "~~~"):
            fence = marker
            continue
        out.append(re.sub(r"`[^`]*`", "", line))
    return "\n".join(out)


def _slug(heading: str) -> str:
    """GitHub's anchor rule: lowercase, drop punctuation except hyphens, spaces to hyphens."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # link text only
    text = text.replace("`", "")
    text = text.lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    anchors: set[str] = set()
    fence = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.lstrip()
        if fence:
            if stripped.startswith(fence):
                fence = ""
            continue
        if stripped[:3] in ("```", "~~~"):
            fence = stripped[:3]
            continue
        match = HEADING.match(line)
        if not match:
            continue
        slug = _slug(match.group(1))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        anchors.add(slug if count == 0 else f"{slug}-{count}")
    return anchors


def _local_links(path: Path) -> list[str]:
    links = LINK.findall(_strip_code(path.read_text(encoding="utf-8")))
    return [link for link in links if not re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", link)]


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
    problems: list[str] = []
    for link in _local_links(path):
        target, _, fragment = link.partition("#")
        dest = (path.parent / target).resolve() if target else path
        if not dest.is_relative_to(ROOT) or not dest.exists():
            problems.append(f"{link}: no such file inside the repository")
        elif fragment and dest.suffix == ".md" and fragment not in _anchors(dest):
            problems.append(f"{link}: no such heading")
    assert problems == []


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
