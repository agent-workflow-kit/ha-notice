# ha-notice: implementation plan

Implements [interface.md](interface.md) and [design.md](design.md). The issues for each stage are expanded into bite-sized test-first steps when they are picked up; this plan fixes the order, the conventions and the module map.

## Conventions for every stage

- **Gateway boundary.** All HTTP and clock access goes through `src/ha_notice/gateway.py`; modules never import `http.client`, `urllib` or `time` directly (the gateway uses `http.client`; `urllib` is not used at all). Tests substitute fakes.
- **Fakes.** A fake Home Assistant server in `tests/` returns each row of the interface's Home Assistant edge table, serves `GET /api/`, and can delay, stall name resolution, trickle a response, drop after the request, redirect or answer 200 with a wrong body. It serves HTTPS with a self-signed certificate (to test `details.tls` and `ca_file`) and plain HTTP with `allow_insecure_http` for the rest. There are no sibling tools to pin.
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
| `config.py` | 1 | Config, drop-ins, YAML, no environment overrides. |
| `log.py` | 2 | Log records and rotation. |
| `hass.py` | 3, 4 | URL building, request, response mapping, retries, deadline, probe call. |

## Stage 0: Scaffold and gateway

**Goal**: A package that installs, prints `--version`, and has the gateway and the fake server in place.
**Success Criteria**: `make verify` green; schemas load; the fake server serves each response row.
**Tests**: version output golden; fake server contract tests; schema positive and negative samples.
**Status**: Not Started

## Stage 1: Config, input, sanitizer, command keywords and rendering

**Goal**: Load and validate config, then validate and render a notification without any network.
**Success Criteria**: invalid config exits 2 naming the key; `send --dry-run` prints the exact request body for stdin, file and flag input, with the `data` allowlist, tag, link and truncation applied, and needs neither `base_url`, `service` nor the token.
**Tests**: config table (`base_url` fuzz: percent-encoded host, `host:abc`, `host:99999`, backslash, non-ASCII, `//` in the prefix; the userinfo, query, trailing slash, path prefix and `http` without `allow_insecure_http` cases; `token_env` outside `HA_`); duration table (`10`, `"10s"`, `"1m"`, `"500ms"` below the 1s minimum, `"1h"` refused, `.nan`, `true`, `"1e3"` refused, `-1`); input table (empty stdin, `[]`, `null`, `"x"`, BOM, duplicate keys, `NaN`, 100000-deep nesting, 1 MiB + 1 bytes, FIFO as `--file`, `--file /dev/zero`, a directory, a symlink to a regular file accepted); sanitizer table (U+061C, U+2028, U+2029, U+0085, U+E0041, U+00AD, U+FE0F, U+FFFE, U+FFFF, U+FDD0, a U+3164-only message is `empty_message`, `"a\n \n \nb"` collapses, a title with LF and U+2028 is one line, a fullwidth space only is `empty_message`); link table (`HTTPS://x.example` accepted and rendered lowercase, a trailing LF refused, `https://a.example\@evil.example`, `https://:80/`, `http://[::1]/`, `javascript:x` is `link_scheme`, `example.com:80/x` is `link_scheme`, non-ASCII, 1025 characters, `link_hosts` suffix match); command-keyword table (`UPDATE_WIDGETS`, `request_location_update`, fullwidth `ｔｔｓ`, `command_x`, `clear_foo_bar`, `update_deps finished` allowed, `Updated: x` allowed, a NUL inside the word); cut table with exact outputs, including 2000-byte cuts of 4-byte characters; the `data` allowlist test (no key outside `url`, `clickAction`, `tag`, `group`); flag and stdin parity; the usage-error-with-`--json` test; golden hash and serialization test.
**Status**: Not Started

## Stage 2: State directory and log

**Goal**: The safe state directory and the log, with state problems never failing a send.
**Success Criteria**: log records match the schema and never contain text, URL, service or token; an unusable state directory leaves the exit code unchanged and prints one warning.
**Tests**: unusable directory tests (symlinked directory, mode 0755, read-only, wrong owner); concurrent rotation with two processes; `HOME` unset; a relative `XDG_STATE_HOME` ignored; log golden files and rotation; the outcome rule (`outcome_unknown` whenever `unknown_outcome` is true).
**Status**: Not Started

## Stage 3: Send

**Goal**: A real `send` against the fake server with the full response table and the deadline.
**Success Criteria**: every row of the Home Assistant edge table maps to its exit code and envelope; the token is sent only as the header to the base URL's host; a double or trailing slash never reaches the host; the whole send finishes within `timeout` plus 1 s.
**Tests**: response table including the opaque 400 hint; 429 x3 and `Retry-After` (`nan`, `-5`, `1e999`, an HTTP date, `5` clamped to 30 and to the deadline); connect-refused retried once; a 5xx not retried; drop after the first byte gives `outcome_unknown` with no retry and `retryable` true only with a tag; a stalled name resolution, a stall after the first byte and a byte-by-byte response (total wall time under `timeout` plus 1 s); a SIGTERM test; TLS failure and `ca_file`; a fake proxy and a fake CA in `SSL_CERT_FILE` (zero connections reach the proxy, the fake CA does not verify); redirect not followed (a second server gets zero requests); an injected `InvalidURL` or `ValueError` carrying a fake secret (absent from stdout, stderr and the log); a token with CR LF and with non-Latin-1 characters; the token leak test; `enabled: false` exits 22; the insecure-http warning.
**Status**: Not Started

## Stage 4: `validate`, live verification and docs

**Goal**: `validate [--probe] [--test-message]`, the live suite and user documentation.
**Success Criteria**: probe distinguishes a bad token and an unreachable host; the live suite settles the still-to-verify items; README documents token creation, the service name and cron use.
**Tests**: validate golden files with the check names `config`, `credential`, `probe`, `test_message`; probe against the fake server (`GET /api/` only); `validate` never prompts; `validate` with `enabled: false` exits 22 without a request; live tests (plain, tag replacement, link tap, a long message, the `GET /api/` response, an unreachable-host timeout).
**Status**: Not Started

## Version roadmap

- **0.x**: Stages 0 to 4.
- **1.0** when the live suite has passed and the tool has run in daily use through a routing tool for two weeks without an interface change.
- **1.x, additive**: per-level `data` keys (`importance`, `channel`, `ttl`, `priority`, `push`) after a live phone test, `--service` or `--group` flags if a router needs them, notification actions with allowlisted URI schemes, notification replacement and clearing by tag (`clear_notification` through a dedicated command, never through `message`), non-companion notify services.
- **2.0**: nothing planned.
