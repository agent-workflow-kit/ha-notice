"""docs/automation.md: its shell examples parse, and its wrapper scripts behave as documented."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "automation.md"
README = ROOT / "README.md"
BINARY = Path(sys.executable).parent / "ha-notice"
FENCE_OPEN = re.compile(r"^```(\w*)$")
MARKER = re.compile(r"^<!-- test:(\w+) -->$")

# (info string, marker or None, body) for every fenced block of the document.
Block = tuple[str, str | None, str]


def _blocks() -> list[Block]:
    blocks: list[Block] = []
    lines = DOC.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        opened = FENCE_OPEN.match(lines[index])
        if opened and opened.group(1):
            marker = None
            if index >= 2 and MARKER.match(lines[index - 2]) and not lines[index - 1]:
                marker = MARKER.match(lines[index - 2]).group(1)  # type: ignore[union-attr]
            body: list[str] = []
            index += 1
            while lines[index] != "```":
                body.append(lines[index])
                index += 1
            blocks.append((opened.group(1), marker, "\n".join(body) + "\n"))
        index += 1
    return blocks


def _named(marker: str) -> str:
    found = [body for _, mark, body in _blocks() if mark == marker]
    assert len(found) == 1, f"expected exactly one block marked test:{marker}"
    return found[0]


SHELL_BLOCKS = [(m, b) for lang, m, b in _blocks() if lang == "sh"]


def test_the_document_has_shell_blocks_and_both_scripts() -> None:
    assert len(SHELL_BLOCKS) >= 6
    _named("wrapper")
    _named("retry")


@pytest.mark.parametrize("block", [b for _, b in SHELL_BLOCKS], ids=lambda b: b.split("\n")[0][:40])
def test_every_shell_block_parses(block: str) -> None:
    result = subprocess.run(["bash", "-n"], input=block, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_crontab_lines_escape_percent_and_hold_no_token() -> None:
    crontabs = [b for lang, _, b in _blocks() if lang == "crontab"]
    assert crontabs
    for block in crontabs:
        for line in block.splitlines():
            assert not re.search(r"(?<!\\)%", line), line
            assert "HA_TOKEN=" not in line and "Bearer" not in line, line
            fields = line.split(None, 5)
            if line and not line.startswith("#") and len(fields) == 6:
                parsed = subprocess.run(["sh", "-n", "-c", fields[5]], capture_output=True)
                assert parsed.returncode == 0, line


def test_kill_timeout_in_the_scripts_is_at_least_timeout_plus_ten() -> None:
    # The default timeout is 10 s, so a caller's kill timeout is at least 20 s.
    for marker in ("wrapper", "retry"):
        match = re.search(r"\btimeout (\d+) ha-notice\b", _named(marker))
        assert match is not None and int(match.group(1)) >= 20


def _script(tmp_path: Path, marker: str) -> Path:
    path = tmp_path / f"{marker}.sh"
    path.write_text(_named(marker), encoding="utf-8")
    return path


def _stub_ha_notice(bin_dir: Path, *, sleeper: bool = False) -> None:
    """A fake ha-notice: replays STUB_RCS (one per call) and records its argv, stdin and token."""
    bin_dir.mkdir()
    stub = bin_dir / "ha-notice"
    stub.write_text(
        "#!/bin/bash\n"
        'dir=$(dirname "$0")\n'
        'n=$(( $(cat "$dir/calls" 2>/dev/null || echo 0) + 1 ))\n'
        'echo "$n" > "$dir/calls"\n'
        'printf \'%s\\n\' "$*" >> "$dir/argv"\n'
        'if [ -p /dev/stdin ] || [ -f /dev/stdin ]; then cat > "$dir/stdin"; fi\n'
        'printf \'%s\' "${HA_TOKEN-unset}" > "$dir/token"\n'
        'rc=$(echo "$STUB_RCS" | cut -d, -f"$n")\n'
        'printf \'%s\\n\' "$(echo "$STUB_OUT" | cut -d"|" -f"$n")"\n'
        'exit "${rc:-0}"\n',
        encoding="utf-8",
    )
    stub.chmod(0o755)
    if sleeper:
        nap = bin_dir / "sleep"
        nap.write_text('#!/bin/bash\necho "$1" >> "$(dirname "$0")/naps"\n', encoding="utf-8")
        nap.chmod(0o755)


def _run(
    script: Path,
    args: list[str],
    tmp_path: Path,
    rcs: str,
    out: str = "",
    stdin: str = '{"message":"hi"}',
    sleeper: bool = False,
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "bin"
    _stub_ha_notice(bin_dir, sleeper=sleeper)
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "STUB_RCS": rcs,
        "STUB_OUT": out,
    }
    return subprocess.run(
        ["bash", str(script), *args], input=stdin, text=True, capture_output=True, env=env
    )


@pytest.mark.parametrize(
    ("raw", "expected"), [(0, 0), (1, 1), (2, 2), (12, 12), (20, 20), (22, 0), (124, 124)]
)
def test_wrapper_maps_only_exit_22_to_success(tmp_path: Path, raw: int, expected: int) -> None:
    result = _run(_script(tmp_path, "wrapper"), ["backup"], tmp_path, str(raw), '{"x":1}')
    assert result.returncode == expected


def test_wrapper_is_silent_on_success_and_disabled(tmp_path: Path) -> None:
    for raw in ("0", "22"):
        sub = tmp_path / raw
        sub.mkdir()
        result = _run(_script(sub, "wrapper"), ["backup"], sub, raw, '{"outcome":"disabled"}')
        assert (result.stdout, result.stderr) == ("", "")


def test_wrapper_reports_the_envelope_once_on_stderr_for_a_failure(tmp_path: Path) -> None:
    envelope = '{"error":{"code":"refused"}}'
    result = _run(_script(tmp_path, "wrapper"), ["backup"], tmp_path, "20", envelope)
    assert result.stdout == ""
    assert result.stderr.count(envelope) == 1 and "exit 20" in result.stderr


def test_wrapper_passes_the_canonical_call_and_stdin(tmp_path: Path) -> None:
    script = _script(tmp_path, "wrapper")
    _run(script, ["backup", "--dedupe-key=abc"], tmp_path, "0", stdin='{"message":"hi"}')
    argv = (tmp_path / "bin" / "argv").read_text(encoding="utf-8").strip()
    assert argv == "send --stdin-json --json --actor auto:backup --dedupe-key=abc"
    assert (tmp_path / "bin" / "stdin").read_text(encoding="utf-8") == '{"message":"hi"}'


def test_wrapper_requires_a_name(tmp_path: Path) -> None:
    result = _run(_script(tmp_path, "wrapper"), [], tmp_path, "0")
    assert result.returncode != 0 and not (tmp_path / "bin" / "calls").exists()


def test_cron_line_sources_the_env_file_and_aliases_the_token(tmp_path: Path) -> None:
    line = next(
        b
        for lang, _, b in _blocks()
        if lang == "crontab"
        for b in b.splitlines()
        if "ha-notice/env" in b and not b.startswith("#")
    )
    command = line.split(None, 5)[5]
    env_file = tmp_path / ".config" / "ha-notice" / "env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text("OTHER_TOKEN='secret-value'\nHA_TOKEN=$OTHER_TOKEN\n", encoding="utf-8")
    command = re.sub(r"/\S*/(\S+)$", r"\1", command.strip())  # drop the script directory
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    probe = bin_dir / command.split()[-1]
    probe.write_text('#!/bin/sh\nprintf %s "$HA_TOKEN" > "$HOME/seen"\n', encoding="utf-8")
    probe.chmod(0o755)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path)}
    subprocess.run(["sh", "-c", command], env=env, check=True)
    assert (tmp_path / "seen").read_text(encoding="utf-8") == "secret-value"


@pytest.mark.skipif(shutil.which("jq") is None, reason="the retry script uses jq")
class TestRetryScript:
    RETRYABLE = '{"error":{"code":"network_error","retryable":true,"unknown_outcome":false}}'
    PERMANENT = '{"error":{"code":"auth_required","retryable":false,"unknown_outcome":false}}'
    UNKNOWN = '{"error":{"code":"outcome_unknown","retryable":false,"unknown_outcome":true}}'

    def _go(self, tmp_path: Path, rcs: str, out: str) -> tuple[int, int, list[str]]:
        payload = tmp_path / "payload.json"
        payload.write_text('{"message":"hi"}', encoding="utf-8")
        result = _run(
            _script(tmp_path, "retry"), ["job", str(payload)], tmp_path, rcs, out, sleeper=True
        )
        calls = int((tmp_path / "bin" / "calls").read_text(encoding="utf-8"))
        nap_file = tmp_path / "bin" / "naps"
        naps = nap_file.read_text(encoding="utf-8").split() if nap_file.exists() else []
        return result.returncode, calls, naps

    def test_a_retryable_failure_is_retried_until_it_succeeds(self, tmp_path: Path) -> None:
        rc, calls, naps = self._go(tmp_path, "12,12,0", f"{self.RETRYABLE}|{self.RETRYABLE}|")
        assert (rc, calls, len(naps)) == (0, 3, 2)

    def test_retries_are_capped(self, tmp_path: Path) -> None:
        out = "|".join([self.RETRYABLE] * 5)
        rc, calls, _ = self._go(tmp_path, "12,12,12,12,12", out)
        assert (rc, calls) == (12, 3)

    def test_a_permanent_failure_is_not_retried(self, tmp_path: Path) -> None:
        rc, calls, _ = self._go(tmp_path, "12,0", f"{self.PERMANENT}|")
        assert (rc, calls) == (12, 1)

    def test_an_unknown_outcome_without_a_dedupe_key_is_not_retried(self, tmp_path: Path) -> None:
        rc, calls, _ = self._go(tmp_path, "12,0", f"{self.UNKNOWN}|")
        assert (rc, calls) == (12, 1)

    @pytest.mark.parametrize("raw", [1, 2, 20, 124])
    def test_other_failures_are_not_retried(self, tmp_path: Path, raw: int) -> None:
        rc, calls, _ = self._go(tmp_path, f"{raw},0", f"{self.RETRYABLE}|")
        assert (rc, calls) == (raw, 1)

    def test_disabled_is_success(self, tmp_path: Path) -> None:
        rc, calls, _ = self._go(tmp_path, "22", '{"outcome":"disabled"}')
        assert (rc, calls) == (0, 1)


@pytest.mark.skipif(not BINARY.exists(), reason="ha-notice is not installed in this environment")
class TestWrapperAgainstTheRealTool:
    """The wrapper's exit-code logic against the real binary: no network, no token."""

    def _run(
        self, tmp_path: Path, config: str, args: list[str]
    ) -> subprocess.CompletedProcess[str]:
        cfg = tmp_path / "config.yaml"
        cfg.write_text(config, encoding="utf-8")
        script = _script(tmp_path, "wrapper")
        env = {"PATH": f"{BINARY.parent}:{os.environ['PATH']}", "HOME": str(tmp_path)}
        env.pop("HA_TOKEN", None)
        return subprocess.run(
            ["bash", str(script), "demo", "--config", str(cfg), *args],
            input='{"message":"hi"}',
            text=True,
            capture_output=True,
            env=env,
        )

    DEST = "base_url: https://homeassistant.example:8123\nservice: mobile_app_your_phone\n"

    def test_a_dry_run_exits_0(self, tmp_path: Path) -> None:
        assert self._run(tmp_path, self.DEST, ["--dry-run"]).returncode == 0

    def test_a_disabled_tool_exits_0_though_the_tool_exits_22(self, tmp_path: Path) -> None:
        cfg = tmp_path / "off.yaml"
        cfg.write_text("enabled: false\n", encoding="utf-8")
        raw = subprocess.run(
            [str(BINARY), "send", "--stdin-json", "--json", "--config", str(cfg)],
            input='{"message":"hi"}',
            text=True,
            capture_output=True,
        )
        assert raw.returncode == 22
        assert self._run(tmp_path, "enabled: false\n", []).returncode == 0

    def test_a_usage_fault_keeps_exit_2(self, tmp_path: Path) -> None:
        result = self._run(tmp_path, self.DEST, ["--no-such-flag"])
        assert result.returncode == 2
        report = next(x for x in result.stderr.splitlines() if x.startswith("ha-notice failed"))
        assert json.loads(report.split(": ", 1)[1])["error"]["code"] == "usage"

    def test_a_missing_token_keeps_exit_12(self, tmp_path: Path) -> None:
        assert self._run(tmp_path, self.DEST, []).returncode == 12


def _prose_lines(path: Path) -> list[str]:
    lines, fenced = [], False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced:
            lines.append(line)
    return lines


def test_paragraphs_and_list_items_are_one_line() -> None:
    previous = ""
    for line in _prose_lines(DOC):
        is_text = bool(line.strip()) and not line.startswith(("#", "|", "<!--"))
        wrapped = is_text and previous and not line.lstrip().startswith(("- ", "1. "))
        assert not wrapped, f"a paragraph continues on a second line: {line!r}"
        previous = line if is_text else ""


def test_the_readme_links_the_guide_and_has_no_pending_marker() -> None:
    text = README.read_text(encoding="utf-8")
    assert "(docs/automation.md" in text
    assert "TODO(#33)" not in text
    assert "later README revision" not in text and "is pending in" not in text
    assert "will be added to this README" not in text


def test_the_guide_covers_the_required_topics() -> None:
    text = DOC.read_text(encoding="utf-8")
    for needle in (
        "install -m 600",
        "umask 077",
        "set -a",
        "plus 10",
        '[ "$rc" = 22 ] && rc=0',
        "validate --probe",
        "--test-message",
        "unknown_outcome",
        "HA_TOKEN",
    ):
        assert needle in text, needle
