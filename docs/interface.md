# ha-notice: interface

Status: 0.1.0-design, 2026-11-17. Written before implementation (architecture section 18.1). This document is the single normative source for ha-notice's rules; `docs/design.md`, the README and the architecture link to its headings and do not restate them.

ha-notice sends one notification through a Home Assistant `notify` service over the REST API (in practice a companion-app push to a phone). It is stateless: it keeps no database, only `log.jsonl`. It runs no hooks and takes no policy decisions: when to send, what to send and how often belong to its caller.

References: architecture (`../awkit-docs/architecture.md`) sections 5.1, 13.2, 13.3, 15 and 20; design guide (`../awkit-docs/design-guide.md`).

## Concepts

### Notification

A notification is a JSON object ([schemas/notification.json](../schemas/notification.json)):

| Field | Type | Required | Rule |
|---|---|---|---|
| `title` | string | no | One line (newlines become spaces); cut at 256 characters after sanitizing (see [Rendering](#rendering)). Input over 100000 characters exits 20 `invalid_payload`. |
| `message` | string | yes | Input over 100000 characters exits 20 `invalid_payload`. Must not be empty after sanitizing (else exit 20 `empty_message`) and must not be a [command message](#command-messages) (else exit 20 `command_keyword`). |
| `level` | `info`, `warn`, `action`, `error` | no | Default `info`. Ordered `info < warn < action < error`; the order matters to callers, not to ha-notice. |
| `link` | string | no | `http` or `https` URL, at most 1024 characters, no whitespace or control characters, no userinfo. Anything else exits 20 `link_invalid` (`link_scheme` for another scheme). The schema checks only the syntactic gate (http or https, no userinfo, no whitespace or control characters, at most 1024 characters); the tool names `link_invalid` or `link_scheme`. |

Unknown fields exit 20 `invalid_payload` (`details.pointer`); ha-notice never forwards free-form data. Input is read from stdin as JSON (`send --stdin-json`, also the default when stdin is not a terminal and no text flag is given), from a file (`--file <path|->`), or from flags (`--title`, `--message`, `--level`, `--link`). Flag text is untrusted and goes through the same [sanitizer](#sanitizer) as stdin text; flags exist for humans. Giving both a JSON source and a text flag exits 2 `usage`.

### Sanitizer

Applied to `title` and `message` before sending, in this order:

1. Invalid UTF-8 or lone surrogates: exit 20 `invalid_payload`.
2. CRLF and CR become LF.
3. Control characters (category Cc) except LF are removed; the tab becomes a space.
4. Invisible and direction-changing format characters are removed: U+200B to U+200F, U+202A to U+202E, U+2060 to U+2064, U+2066 to U+2069, U+FEFF.
5. Runs of more than two LF become two; leading and trailing whitespace is trimmed.

Template syntax (`{{ … }}`, `{% … %}`) is not escaped: Home Assistant was tested not to render templates in REST-supplied `title` and `message` ([Residual risks](#residual-risks) says what that rests on).

### Command messages

The companion apps treat a message equal to a keyword as a command to the phone instead of text. After sanitizing, a `message` is refused (exit 20 `command_keyword`) when it equals, ignoring case and surrounding whitespace, one of `clear_notification`, `clear_badge`, `remove_channel`, `request_location_update`, `update_complications`, `update_widgets`, `tts`, or starts with `command_` or `kiosk_`. The list is a floor: it is kept in the interface so a new keyword is a documented change. The tool never sends `data.tts_text` or any `command` field.

### Rendering

- `title` is the notification title: a title longer than 256 characters after sanitizing is cut with a final `…` (256 characters in all, before the prefix is added) and the result has `truncated: true`; then the level's entry in `level_prefix` (defaults: none for `info`, `WARN:`, `ACTION:`, `ERROR:`; one-line strings up to 16 characters) joined with a space to the title, or the prefix alone, or the title alone, or omitted when both are empty.
- `message` is the notification text, limited to `max_chars` characters (default 4000, 500 to 20000, in Unicode code points). A longer message is cut and ends with `…[truncated]`, and the result has `truncated: true`.
- `data` is built only from this allowlist, never from caller input other than `link` and the dedupe key:
  - `url` and `clickAction`: both set to `link` when it is given.
  - `tag`: `awkit-` plus the first 24 hex characters of the SHA-256 of the dedupe key, set when `--dedupe-key` is given and config `tag_from_dedupe_key` is `true` (default). Home Assistant replaces an earlier notification with the same tag, so a retry does not show twice.
  - `group`: config `default_group` when set.
  - the keys of `level_data[<level>]` (default `{}`): `group`, `importance` (`min`, `low`, `default`, `high`, `max`), `channel` (`^[A-Za-z0-9_ -]{1,64}$`), `ttl` (integer 0 to 86400), `priority` (`normal`, `high`) and `push` (an object whose only key is `interruption-level`: `passive`, `active`, `time-sensitive`, `critical`). Anything else in config is `config_invalid`.

## Commands

### `send`

`ha-notice send [--stdin-json | --file <path|->] [--title <t>] [--message <m>] [--level <l>] [--link <url>] [--dedupe-key <k>]`

Order, with the exit code of each refusal:

1. Parse flags (exit 2 `usage`).
2. Load config (exit 2 `config_invalid`). `enabled: false` prints `{"outcome": "disabled"}` and exits 22 here, before input is read.
3. Read and validate input (exit 2 `usage` for conflicting sources; exit 20 with reason `invalid_payload`, `empty_message`, `command_keyword`, `link_invalid` or `link_scheme`).
4. Render the request body ([Rendering](#rendering)). With `--dry-run`, print the result with `rendered` (the JSON body that would be sent, no secrets) and exit 0: the credential is not read, nothing is sent and no log record is written.
5. Read the token from the environment variable named by `token_env` (exit 20 with reason `credential_missing`, `details.env`).
6. POST to the service ([Home Assistant edge](#home-assistant-edge)) and map the response to an exit code ([Exit codes](#exit-codes)).
7. Append the [log record](#log) and print the result.

With `tls_verify: false`, each send also prints a warning on stderr (never in a log field).

`--dedupe-key` has the grammar `^[A-Za-z0-9._:@/-]{1,128}$`. Without `tag_from_dedupe_key` it is only recorded (hashed) in the log.

### `validate`

`ha-notice validate [--probe] [--test-message]`

Offline, it checks the config and that the token variable is set. When the config loads, it prints `{ok, checks: [{name, ok, message}]}` ([schemas/cli/validate.json](../schemas/cli/validate.json)) and exits 0 when every check passes. Otherwise it still prints the document, with `ok: false`, and exits with the exit code of the first failing check: 20 with reason `credential_missing`, or 12 for a tool or host problem. When the config cannot load, it prints the [error envelope](#error-envelope) and exits 2 `config_invalid`. It writes no log record.

`--probe` adds two read-only calls and sends no notification: `GET /api/` (reachable, token accepted) and `GET /api/services` (the configured `notify` service exists), and adds `probe: {api_ok, service_found}` to the output (both booleans; `service_found` is false when the first call failed). A rejected token is a failing check with exit 12 `auth_required`; a missing service is exit 12 `host_rejected` with `details.service`. `--test-message` (needs `--probe`) then sends one marked test notification (`ha-notice validate: test message`) after a confirmation on `/dev/tty`, or at once with `--yes`, and adds a check named `test_message`; if the confirmation is declined, the check is omitted.

## Global flags

| Flag | Meaning |
|---|---|
| `--json` | Machine output on stdout ([Output](#output)). |
| `--config <path>` | Config file instead of `~/.config/ha-notice/config.yaml` (drop-ins are read next to it). |
| `--dry-run` | `send` only: build and print, send nothing, read no credential, write no log record. |
| `--yes` | `validate --test-message` only: skip the confirmation. Never overrides a refusal. |
| `--actor <actor>` | Recorded in the log. `human:<user>` when stdin is a terminal, else `auto:unknown` (design guide section 4.4); a caller passes `auto:<name>`. |
| `--verbose`, `--quiet` | More or less human output on stderr. |
| `--version` | Print `ha-notice <version>`. |

## Home Assistant edge

- The request URL is `<base_url>/api/services/notify/<service>`. `base_url` is `https://host[:port][/prefix]` (or `http://` only with `allow_insecure_http: true`), with no userinfo, query or fragment; trailing slashes are stripped before joining, because a double or trailing slash is a 404 on the host. `service` matches `^[a-z0-9_]{1,64}$`.
- The token is read only from the environment variable named by `token_env` (default `HA_TOKEN`), trimmed, sent only as `Authorization: Bearer <token>`, never in argv, URL, logs, output or errors, and never on any request to a host other than `base_url`'s.
- Request: `POST`, `Content-Type: application/json`, `User-Agent: ha-notice/<version>`, body `{"title", "message", "data"}` (`title` and `data` omitted when empty), through the standard library's HTTP client in `gateway.py`. Certificate verification is on unless config `tls_verify` is `false`; `ca_file` names an extra CA bundle. Redirects are not followed. At most 64 KiB of the response is read.

| Response | Result |
|---|---|
| 200 with a JSON list (an empty list in testing) | `sent` (exit 0). |
| 200 with anything else | Exit 12 `wrong_host_response`, `unknown_outcome: true`. |
| 400 | Exit 12 `host_rejected`, `retryable: false`. The host's 400 is opaque (an unknown service, a missing message and an unknown field answer alike), so `details.hint` says to run `validate --probe`. |
| 401 | Exit 12 `auth_required`, `retryable: false`. |
| 403 | Exit 12 `permission_denied`, `retryable: false`. |
| 404, 405 | Exit 12 `wrong_host_response`, `retryable: false`, with a message that `base_url` or its path prefix is probably wrong. |
| 429 | Retried up to twice with waits of 2 s and 4 s (or `Retry-After`, at most 30 s) within `timeout`; then exit 12 `rate_limited`, `retryable: true`. |
| 5xx | Retried once after 2 s within `timeout`; then exit 12 `upstream_error`, `retryable: true`. |
| Any other status | Exit 12 `wrong_host_response`, `retryable: false`. |
| Connection refused, DNS or TLS failure before the request is fully sent | Exit 12 `network_error`, `retryable: true` (`details.tls: true` for a certificate failure, with `retryable: false`). |
| Timeout or connection loss after the request is fully sent | Exit 12 `outcome_unknown`, `retryable: true`, `unknown_outcome: true`. ha-notice never retries this case itself; when a tag was set, a caller's retry replaces the earlier notification instead of duplicating it, and the output says `tag_set: true`. |

The API answers success whether or not the push reached a phone and offers no way to learn that it did not. Output says `sent`, never `delivered`.

## Output

With `--json`, `send` prints one object ([schemas/cli/send.json](../schemas/cli/send.json)): `{outcome, tool, level, truncated, bytes, duration_ms, http_status, tag_set, dedupe_key, rendered}`. `outcome` is `sent`, `dry_run` or `disabled`; `bytes` is the UTF-8 size of the request body; `dedupe_key` echoes the caller's own `--dedupe-key` (or null); `http_status` is null for a dry run; `rendered` is present only for a dry run. Disabled output is `{"outcome": "disabled"}` and nothing else. Without `--json`, human text goes to stderr and stdout is empty.

Errors print the [error envelope](#error-envelope) on stdout with `--json` and a one-line message on stderr otherwise.

## Exit codes

Codes 0–21 follow design guide section 4.2. ha-notice defines one code of 22 or above.

| Exit | Meaning | Codes, or reasons for exit 20 |
|---|---|---|
| 0 | Accepted by Home Assistant (`sent`) or a dry run. | |
| 1 | Internal error. | Code: `internal` |
| 2 | Usage or invalid configuration. | Codes: `usage`, `config_invalid` |
| 12 | Failed for a reportable reason. | Codes: `host_rejected`, `auth_required`, `permission_denied`, `rate_limited`, `upstream_error`, `network_error`, `outcome_unknown`, `wrong_host_response`, `state_unsafe` |
| 20 | Refused before sending: `code` is `refused` and `reason` is required. | Reasons (not codes): `invalid_payload`, `empty_message`, `command_keyword`, `link_invalid`, `link_scheme`, `credential_missing` |
| 22 | Nothing sent: the tool is disabled in config. | Outcome `disabled` (not an error; output `{"outcome": "disabled"}`) |

Exits 10, 11, 13 and 21 are never used: ha-notice stores no objects, has no hooks and asks no human. A caller treats exit 22 as a successful no-op.

### Error envelope

`{"error": {"code", "message", "reason", "details", "retryable", "retry_after_s", "unknown_outcome"}}` ([schemas/cli/error.json](../schemas/cli/error.json)); only `code` and `message` are required. Exit 20 has `code: refused` with `reason` set (null elsewhere). `retry_after_s` is set only when known; `retryable` and `unknown_outcome` are always both booleans on exit 12 and null elsewhere, as follows:

| Code | `retryable` | `unknown_outcome` |
|---|---|---|
| `state_unsafe`, `host_rejected`, `auth_required`, `permission_denied` | false | false |
| `wrong_host_response` | false | true for a 200 with a bad body, else false |
| `rate_limited`, `upstream_error` | true | false |
| `network_error` | true (false for a certificate failure, `details.tls: true`) | false |
| `outcome_unknown` | true | true |

`details` by code or reason: code `config_invalid` → `key`; reason `invalid_payload` → `pointer`; reason `credential_missing` → `env`; code `host_rejected` → `http_status`, `hint`, `service`; code `network_error` → `tls`. Messages never contain the token or any part of it.

## Hooks

None in 0.x. ha-notice sends one notification and takes no policy decisions; gating and routing belong to the caller. A `post-send` hook that notifies on failure could call this tool again and loop, which is the other reason there are none. Adding hooks later is additive.

## Config

`~/.config/ha-notice/config.yaml` (respecting `XDG_CONFIG_HOME`), then `config.d/*.yaml` in lexical order; maps merge, other lists replace. Schema: [schemas/config.json](../schemas/config.json); example: [config.example.yaml](../config.example.yaml). Invalid config exits 2 `config_invalid` naming the key. Precedence: flags, then environment (scalar keys only), then config, then defaults. There is no per-repo override: the tool has no notion of a repository. `base_url` and `service` have no default, so nothing is sent until they are set.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` makes `send` exit 22 without reading input or the credential. |
| `base_url` | none (required) | Home Assistant base URL, `https://host[:port][/prefix]`. |
| `service` | none (required) | The `notify` service name (for example a `mobile_app_` service). |
| `token_env` | `HA_TOKEN` | Name of the environment variable holding a long-lived access token. |
| `allow_insecure_http` | `false` | Allow an `http://` base URL (the token then travels in cleartext). |
| `tls_verify` | `true` | `false` disables certificate checks (self-signed servers); a warning on stderr on every send. |
| `ca_file` | unset | Extra CA bundle path. |
| `level_prefix` | `{info: "", warn: "WARN:", action: "ACTION:", error: "ERROR:"}` | Title prefixes, at most 16 characters each. |
| `level_data` | `{}` | Per-level allowlisted `data` keys ([Rendering](#rendering)). |
| `default_group` | unset | `data.group` for every notification; `^[A-Za-z0-9_ -]{1,64}$`. |
| `tag_from_dedupe_key` | `true` | Derive `data.tag` from `--dedupe-key`. |
| `max_chars` | `4000` | Message limit, 500 to 20000. |
| `timeout` | `10s` | Budget for one `send`, including retries, 1s to 120s; a number of seconds or a string like `10s`, `1m`, `500ms`. |
| `log` | `true` | `false` writes no `log.jsonl`. |

Durations use the design guide's duration grammar (a number of seconds or a string like `10s`, `1m`, `500ms`); the tool enforces the stated ranges at load (exit 2 `config_invalid`, `details.key`).

## Environment variables

- `HA_NOTICE_<KEY>` sets a scalar config key (`HA_NOTICE_ENABLED`, `HA_NOTICE_BASE_URL`, `HA_NOTICE_SERVICE`, `HA_NOTICE_TOKEN_ENV`, `HA_NOTICE_ALLOW_INSECURE_HTTP`, `HA_NOTICE_TLS_VERIFY`, `HA_NOTICE_CA_FILE`, `HA_NOTICE_DEFAULT_GROUP`, `HA_NOTICE_TAG_FROM_DEDUPE_KEY`, `HA_NOTICE_MAX_CHARS`, `HA_NOTICE_TIMEOUT`, `HA_NOTICE_LOG`); `level_prefix` and `level_data` cannot be set from the environment.
- The variable named by `token_env` holds the credential. Under cron or any hook it must be in the calling process's environment; the docs recommend a mode-0600 env file sourced by the cron line. ha-notice never reads shell startup files or secret files itself.

## Log

`~/.local/state/ha-notice/log.jsonl` (respecting `XDG_STATE_HOME`), mode 0600, appended without following symlinks; one record per `send` outcome that reaches step 3 or later ([schemas/log.json](../schemas/log.json)): `sent`, `refused` (exit 20), `failed` (exit 12 except `outcome_unknown`) or `outcome_unknown`. Not logged: exit 1, exit 2, exit 22 (`disabled`) and dry runs. Fields: `{ts, tool, version, outcome, exit, code, reason, level, bytes, truncated, duration_ms, http_status, message_sha256, dedupe_key_sha256, tag_set, actor, actor_source}`. `outcome` is one of `sent`, `refused`, `failed`, `outcome_unknown`. `code` is `refused` for exit 20, the failure code for exit 12 and null on success; `reason` is null unless `refused`. `actor_source` is `flag` (from `--actor`), `tty` (stdin is a terminal) or `default` (`auto:unknown`). Nullable fields are always present. `message_sha256` and `dedupe_key_sha256` are the first 16 hex characters of the SHA-256 of the notification text and of the key. Records never contain a title, message, link, base URL, service name or credential. The file rotates at 1 MiB, keeping 3 files. A log write failure warns on stderr and never changes the exit code. There is no audit file: a notification changes nothing in a system of record.

## Files

| Path | Content |
|---|---|
| `~/.config/ha-notice/config.yaml`, `config.d/*.yaml` | Config. |
| `~/.local/state/ha-notice/log.jsonl` (and `.1` to `.3`) | Log records. |

`~/.local/state/ha-notice/` is created with mode 0700, opened without following symlinks and checked to be a directory owned by the user with mode 0700 on every send (else exit 12 `state_unsafe`). There is no database and no migration.

## Labels

ha-notice creates no long-lived objects and takes no labels.

## TUI

None in v1.

## Residual risks

- **No delivery confirmation.** Success is returned whether or not the push is delivered, and the message may still be cut or dropped on the phone (the display limit is unknown; the API accepted 100000 characters).
- **Templates were tested, not guaranteed.** Not rendering `{{ … }}` in REST-supplied text was observed on one Home Assistant version; a future version or a custom notify service could render it. The tool does not escape template syntax, so a caller who sends untrusted text to such a service takes that risk.
- **The command list is a floor.** The companion apps may add commands; text that is a command on a platform not listed here would be sent as a command.
- **The token is a long-lived credential.** Any same-user process that can read the environment variable or its source can use it for the whole Home Assistant API, not only `notify`; use a token for a dedicated user where possible.
- **Cleartext and self-signed servers.** `allow_insecure_http` and `tls_verify: false` trade the token's safety for convenience; both are off by default; each send with either set warns on stderr.
- **Taps open links.** `link` becomes the tap action and is limited to `http` and `https`; the apps accept more schemes (`app://`, intents, settings), and the host API does not reject them, which is why the tool does.
- **Lock-screen exposure.** Title and message appear on the phone's lock screen according to the phone's settings; callers must not send secrets.
- **Opaque errors.** Several different mistakes return the same 400, so diagnosis depends on `validate --probe`, whose read-only `GET` endpoints are specified from Home Assistant's documentation and not yet exercised live ([design.md](design.md), Live verification).

## Platform notes

Linux and WSL are required. macOS is expected to work (standard library only) but is not a required platform.
