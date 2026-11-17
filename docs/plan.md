# ha-notice: implementation plan

Implements [interface.md](interface.md) and [design.md](design.md). The issues for each stage are expanded into bite-sized test-first steps when they are picked up; this plan fixes the order, the conventions and the module map.

## Conventions for every stage

- **Gateway boundary.** All HTTP and clock access goes through `src/ha_notice/gateway.py`; modules never import `urllib` or `time` directly. Tests substitute fakes.
- **Fakes.** A fake Home Assistant server in `tests/` returns each row of the interface's Home Assistant edge table, serves `GET /api/` and `GET /api/services`, and can delay, drop after the request, redirect or answer 200 with a wrong body. There are no sibling tools to pin.
- **Process and live split.** Process tests run the CLI as a subprocess against the fake server. `live` tests (pytest marker, never in CI) send marked notifications to the maintainer's own service and need a person to look at the phone; they are listed in the live-verification issue.
- **Golden files.** `--json` outputs, request bodies and log records have golden files; schemas have positive and negative samples.
- **Spike regressions.** Every behavior in design.md's live-verification table becomes a fake-server test or a `live` test.
- **Secrets.** A test sets a recognizable fake token and asserts it appears in no argv, URL, output, log or error, and is sent to no host other than the base URL's.
- **`make verify`** passes before every commit; each paragraph in markdown is one line.

## Module map

| Module | Stage | Responsibility |
|---|---|---|
| `gateway.py` | 0 | HTTP and clock. |
| `cli.py` | 0, 3, 4 | Parsing, dispatch, exit codes, output. |
| `payload.py` | 1 | Input parsing, validation, sanitizer, command keywords. |
| `render.py` | 1 | Request body and `data` allowlist. |
| `config.py` | 2 | Config, drop-ins, env overrides. |
| `log.py` | 2 | Log records and rotation. |
| `hass.py` | 3, 4 | URL joining, request, response mapping, retries, probe calls. |

## Stage 0: Scaffold and gateway

**Goal**: A package that installs, prints `--version`, and has the gateway and the fake server in place.
**Success Criteria**: `make verify` green; schemas load; the fake server serves each response row.
**Tests**: version output golden; fake server contract tests; schema positive and negative samples.
**Status**: Not Started

## Stage 1: Input, sanitizer, command keywords and rendering

**Goal**: Validate and render a notification without any network.
**Success Criteria**: `send --dry-run` prints the exact request body for stdin, file and flag input, with the `data` allowlist, tag, link and truncation applied.
**Tests**: sanitizer table; command-keyword table with near misses (`clear_notifications`, `command`, a keyword inside a longer message); every refusal reason; `level_data` validation; tag derivation; flag and stdin parity.
**Status**: Not Started

## Stage 2: Config, state directory and log

**Goal**: Config loading with validation and the safe state directory and log.
**Success Criteria**: invalid config exits 2 naming the key; `base_url` and `service` have no default; log records match the schema and never contain text, URL, service or token.
**Tests**: config precedence and env overrides; base URL grammar (userinfo, query, trailing slash, path prefix, `http` without `allow_insecure_http`); state directory checks; log golden files and rotation.
**Status**: Not Started

## Stage 3: Send

**Goal**: A real `send` against the fake server with the full response table.
**Success Criteria**: every row of the Home Assistant edge table maps to its exit code and envelope; the token is sent only as the header to the base URL's host; a double or trailing slash never reaches the host.
**Tests**: response table including the opaque 400 hint; 429 and 5xx retry timing; drop after send gives `outcome_unknown` with no retry and `tag_set`; TLS failure; redirect not followed; token leak test; `enabled: false` exits 22.
**Status**: Not Started

## Stage 4: `validate`, live verification and docs

**Goal**: `validate [--probe] [--test-message]`, the live suite and user documentation.
**Success Criteria**: probe distinguishes a bad token, an unreachable host and a missing service; the live suite settles the still-to-verify items; README documents token creation, the service name and cron use.
**Tests**: validate golden files; probe against the fake server; confirmation on `/dev/tty` and `--yes`; live tests (plain, tag replacement, link tap, `level_data` effect, a long message, `GET` shapes, an unreachable-host timeout).
**Status**: Not Started

## Version roadmap

- **0.x**: Stages 0 to 4.
- **1.0** when the live suite has passed and the tool has run in daily use through a routing tool for two weeks without an interface change.
- **1.x, additive**: notification actions with allowlisted URI schemes, notification replacement and clearing by tag (`clear_notification` through a dedicated command, never through `message`), non-companion notify services.
- **2.0**: nothing planned.
