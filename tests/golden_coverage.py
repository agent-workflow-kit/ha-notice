"""Which golden files must exist, derived from the schemas and docs/interface.md (issue #30).

`required()` lists the coverage items the goldens must show, built from the shipped schemas
(exit codes, error codes, refusal reasons, details keys, validate check names, log outcome and
code combinations, send outcomes and warnings, request data keys and levels) and from the exit-code
table of docs/interface.md. `covered(listing)` reads what a listing of golden files shows, and
`missing(listing)` is the difference, minus the explicit list of items that no golden can show.
`problems(listing)` reports golden files that do not validate against the schema of their kind.

A listing is `{kind: {name: text}}` for the kinds `output`, `request` and `log`, so the checks can
be tried against a fake listing without touching the repository. Items are plain strings such as
`exit:12`, `error:host_rejected`, `check:probe:failed` or `log:failed/12/rate_limited/-`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tests.harness import GOLDEN_DIR, KINDS, ROOT, fragment_validator, load_schema, schema_errors

Listing = Mapping[str, Mapping[str, str]]

# Items that no golden file can show, each with the reason (docs/interface.md, Exit codes).
NON_GOLDENABLE: dict[str, str] = {
    "exit:128+N": "a signal before the send started: no envelope, no output and no log record",
}
# The default level prefixes (docs/interface.md, Rendering); info has none.
PREFIXES = {"warn": "WARN: ", "action": "ACTION: ", "error": "ERROR: "}
TITLE_CUT_MARK = "…"
MESSAGE_CUT_MARK = "…[truncated]"
# Variants that the interface sets apart in its flag and details rules and that a golden must show.
VARIANTS = (
    "variant:internal:before-writing",
    "variant:internal:after-writing",
    "variant:wrong_host_response:not-http",
    "variant:network_error:tls",
    "variant:network_error:timeout",
    "variant:outcome_unknown:retryable",
    "variant:outcome_unknown:not-retryable",
    "variant:validate:enabled-false",
)


def read_listing(root: Path = GOLDEN_DIR) -> dict[str, dict[str, str]]:
    """The golden files below `root` as `{kind: {name: text}}`, in sorted order."""
    result: dict[str, dict[str, str]] = {}
    for kind in KINDS:
        files = (
            sorted(p for p in (root / kind).rglob("*") if p.is_file())
            if (root / kind).is_dir()
            else []
        )
        result[kind] = {
            p.relative_to(root / kind).as_posix(): p.read_text(encoding="utf-8") for p in files
        }
    return result


def _defs() -> dict[str, Any]:
    return load_schema("defs")["$defs"]  # type: ignore[no-any-return]


def exit_table() -> dict[str, list[str]]:
    """`{exit: [code or reason, ...]}` from the Exit codes table of docs/interface.md."""
    text = (ROOT / "docs" / "interface.md").read_text(encoding="utf-8")
    text = text.split("\n## Exit codes\n", 1)[1].split("\n### Error envelope\n", 1)[0]
    table: dict[str, list[str]] = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 3 and re.fullmatch(r"\d+|128\+N", cells[0]):
            table[cells[0]] = re.findall(r"`([a-z_]+)`", cells[2])
    return table


def code_to_exit() -> dict[str, int]:
    """The exit of each error code: rows 1, 2 and 12 of the table, and `refused` is 20."""
    table = exit_table()
    result = {code: int(row) for row in ("1", "2", "12") for code in table[row]}
    result["refused"] = 20
    return result


def _log_combinations() -> set[str]:
    """Every (outcome, exit, code, reason) that log.json allows, from its if/then rules."""
    schema = load_schema("log")
    defs = _defs()
    rules = {
        r["if"]["properties"]["outcome"]["const"]: r["then"]
        for r in schema["allOf"]
        if "outcome" in r["if"]["properties"]
    }
    items = {"log:sent/0/-/-"}
    items |= {f"log:refused/20/refused/{r}" for r in defs["refusal_reason"]["enum"]}
    items |= {f"log:failed/12/{c}/-" for c in rules["failed"]["properties"]["code"]["enum"]}
    for branch in rules["outcome_unknown"]["anyOf"]:
        props = branch["properties"]
        codes = props["code"].get("enum") or [props["code"]["const"]]
        items |= {f"log:outcome_unknown/{props['exit']['const']}/{c}/-" for c in codes}
    return items


def required() -> set[str]:
    defs = _defs()
    send = load_schema("cli/send")
    validate = load_schema("cli/validate")
    items: set[str] = {f"exit:{e}" for e in defs["exit_code"]["enum"]} | set(NON_GOLDENABLE)
    items |= {f"error:{c}" for c in defs["error_code"]["enum"]}
    items |= {f"refusal:{r}" for r in defs["refusal_reason"]["enum"]}
    items |= {f"details:{k}" for k in defs["error_details"]["properties"]}
    names = validate["oneOf"][0]["properties"]["checks"]["items"]["properties"]["name"]["enum"]
    items |= {f"check:{n}:{state}" for n in names for state in ("ok", "failed")}
    items |= {f"send:{o}" for o in send["properties"]["outcome"]["enum"]}
    items |= {f"send:truncated:{b}" for b in ("true", "false")}
    items |= {f"send:warning:{w}" for w in send["properties"]["warnings"]["items"]["enum"]}
    items |= _log_combinations()
    items |= {f"request:level:{lvl}" for lvl in defs["level"]["enum"]}
    items |= {
        f"request:data:{k}"
        for k in send["properties"]["rendered"]["properties"]["data"]["properties"]
    }
    items |= {
        "request:title-absent",
        "request:title-cut",
        "request:message-cut",
        "request:non-ascii",
    }
    items |= set(VARIANTS)
    # The clear command (docs/interface.md, `clear`): its goldens are named `clear*` and are
    # counted apart, so they never stand in for a send golden.
    clear = load_schema("cli/clear")
    items |= {f"clear:{o}" for o in clear["properties"]["outcome"]["enum"] if o != "disabled"}
    items |= {"clear:request", "clear:log:sent", "clear:log:failed"}
    return items


def _output_exit(doc: Mapping[str, Any]) -> int:
    if "error" in doc:
        return code_to_exit()[doc["error"]["code"]]
    if "checks" in doc:
        failed = [c["name"] for c in doc["checks"] if not c["ok"]]
        if not failed:
            return 0
        return 2 if failed[0] == "config" else 12
    return {"sent": 0, "dry_run": 0, "disabled": 22}[doc["outcome"]]


CLEAR_PREFIX = "clear"


def _is_clear(name: str) -> bool:
    return name.startswith(CLEAR_PREFIX)


def _output_items(doc: Mapping[str, Any], name: str = "") -> set[str]:
    if _is_clear(name) and "outcome" in doc:
        return {f"clear:{doc['outcome']}"}
    items = {f"exit:{_output_exit(doc)}"}
    if "error" in doc:
        err = doc["error"]
        code, details = err["code"], err["details"]
        items.add(f"error:{code}")
        if err["reason"] is not None:
            items.add(f"refusal:{err['reason']}")
        items |= {f"details:{k}" for k in (details or {})}
        if code == "internal":
            after = "after" if err["unknown_outcome"] else "before"
            items.add(f"variant:internal:{after}-writing")
        if code == "wrong_host_response" and details is None:
            items.add("variant:wrong_host_response:not-http")
        if code == "network_error" and details:
            items |= {f"variant:network_error:{k}" for k in ("tls", "timeout") if details.get(k)}
        if code == "outcome_unknown":
            items.add(
                "variant:outcome_unknown:" + ("retryable" if err["retryable"] else "not-retryable")
            )
    elif "checks" in doc:
        items |= {f"check:{c['name']}:{'ok' if c['ok'] else 'failed'}" for c in doc["checks"]}
        if doc["enabled"] is False:
            items.add("variant:validate:enabled-false")
    else:
        items.add(f"send:{doc['outcome']}")
        if "truncated" in doc:
            items.add(f"send:truncated:{str(doc['truncated']).lower()}")
        items |= {f"send:warning:{w}" for w in doc.get("warnings", [])}
    return items


def _request_items(text: str) -> set[str]:
    doc = json.loads(text)
    items: set[str] = set()
    title = doc.get("title")
    if title is None:
        items.add("request:title-absent")
    else:
        # A title that is only the prefix renders as the prefix alone, without the space.
        prefixed = [
            lvl for lvl, p in PREFIXES.items() if title == p.rstrip() or title.startswith(p)
        ]
        items.add(f"request:level:{prefixed[0] if prefixed else 'info'}")
        if title.endswith(TITLE_CUT_MARK):
            items.add("request:title-cut")
    if doc["message"].endswith(MESSAGE_CUT_MARK):
        items.add("request:message-cut")
    items |= {f"request:data:{k}" for k in doc.get("data", {})}
    if not text.isascii():
        items.add("request:non-ascii")
    return items


def _log_items(text: str) -> set[str]:
    items: set[str] = set()
    for line in text.splitlines():
        rec = json.loads(line)
        items.add(f"log:{rec['outcome']}/{rec['exit']}/{rec['code'] or '-'}/{rec['reason'] or '-'}")
    return items


def covered(listing: Listing) -> set[str]:
    items: set[str] = set()
    for name, text in listing.get("output", {}).items():
        items |= _output_items(json.loads(text), name)
    for name, text in listing.get("request", {}).items():
        items |= {"clear:request"} if _is_clear(name) else _request_items(text)
    for name, text in listing.get("log", {}).items():
        if _is_clear(name):
            states = {json.loads(line)["outcome"] for line in text.splitlines()}
            items |= {f"clear:log:{'sent' if s == 'sent' else 'failed'}" for s in states}
        else:
            items |= _log_items(text)
    return items


def output_schema(doc: Mapping[str, Any], name: str = "") -> str:
    """The schema that governs an output golden, by its shape (and, for a clear golden, its
    name: its shape is the one of a send output)."""
    if "error" in doc:
        return "cli/error"
    if _is_clear(name):
        return "cli/clear"
    return "cli/validate" if "checks" in doc else "cli/send"


def problems(listing: Listing) -> list[str]:
    """Golden files that are not valid JSON documents of their schema."""
    found: list[str] = []
    for name, text in listing.get("output", {}).items():
        try:
            doc = json.loads(text)
        except ValueError:
            found.append(f"output/{name}: not JSON")
            continue
        if not text.endswith("\n") or text.count("\n") != 1:
            found.append(f"output/{name}: not exactly one LF-terminated line")
        for err in schema_errors(output_schema(doc, name), doc)[:1]:
            found.append(f"output/{name}: {output_schema(doc, name)}: {err.message}")
    rendered = fragment_validator("cli/send", "/properties/rendered")
    clear_rendered = fragment_validator("cli/clear", "/properties/rendered")
    for name, text in listing.get("request", {}).items():
        try:
            request = json.loads(text)
        except ValueError:
            found.append(f"request/{name}: not JSON")
            continue
        schema = "cli/clear" if _is_clear(name) else "cli/send"
        check = clear_rendered if _is_clear(name) else rendered
        for err in list(check.iter_errors(request))[:1]:
            found.append(f"request/{name}: {schema} rendered: {err.message}")
    for name, text in listing.get("log", {}).items():
        for number, line in enumerate(text.splitlines(), 1):
            for err in schema_errors("log", json.loads(line))[:1]:
                found.append(f"log/{name}:{number}: {err.message}")
    return found


def missing(listing: Listing) -> list[str]:
    """Required items that no golden in `listing` shows, sorted; the allowlist is subtracted."""
    return sorted(required() - covered(listing) - set(NON_GOLDENABLE))
