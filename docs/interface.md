# ha-notice: interface

Status: 0.1.0-design, 2026-11-17. Written before implementation (architecture section 18.1). This document is the single normative source for ha-notice's rules; `docs/design.md`, the README and the architecture link to its headings and do not restate them.

ha-notice sends one notification through a Home Assistant `notify` service over the REST API (in practice a companion-app push to a phone). It is stateless: it keeps no database, only `log.jsonl`. It runs no hooks and takes no policy decisions: when to send, what to send and how often belong to its caller.

References: architecture (`../awkit-docs/architecture.md`) sections 5.1, 13.2, 13.3, 15 and 20; design guide (`../awkit-docs/design-guide.md`).

## Concepts

### Notification

A notification is a JSON object ([schemas/notification.json](../schemas/notification.json)):

| Field | Type | Required | Rule |
|---|---|---|---|
| `title` | string | no | One line; cut at 256 characters after sanitizing (see [Rendering](#rendering)). Input over 100000 characters exits 20 `invalid_payload`. |
| `message` | string | yes | Input over 100000 characters exits 20 `invalid_payload`. Must not be empty after sanitizing (else exit 20 `empty_message`) and must not be a [command message](#command-messages) (else exit 20 `command_keyword`). |
| `level` | `info`, `warn`, `action`, `error` | no | Default `info`. Ordered `info < warn < action < error`; the order matters to callers, not to ha-notice. |
| `link` | string | no | Optional; see the link rule below. 1 to 1024 printable ASCII characters. |

**Link rule.**

```text
link is optional and is checked in this order. (1) It is a string of 1 to 1024 printable ASCII characters (U+0021 to U+007E); anything else, including whitespace, control characters, non-ASCII characters and an empty string, is reason link_invalid (callers percent-encode paths and give hosts as punycode). (2) If it starts with a scheme token ([A-Za-z][A-Za-z0-9+.-]*:) whose lowercase form is not http or https, the reason is link_scheme. (3) It must match (?i:https?)://(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?(?:[/?#][\x21-\x7e]*)? as a whole, and a port must be 1 to 65535, else link_invalid (no userinfo, no empty host, no backslash between host and path). The scheme is lowercased wherever the link is rendered. The schema pattern is a coarse gate for the same rule; the tool is authoritative. A link names a place to open and is never a promise that it is safe: a caller that builds links from untrusted text takes that risk.
```

When config `link_hosts` is set, the link's host (lowercased, without port) must equal an entry or end with `.` plus an entry, else exit 20 `link_invalid` with `details.pointer` `/link`. With `link_hosts` unset a producer can aim the tap target at any web address; the push does not show the URL.

**Input.**

```text
Exactly one source is used: JSON on stdin (send --stdin-json, also the default when stdin is not a terminal and no text flag is given), JSON from --file <path> (--file - is stdin, the same source), or flags. A JSON source together with --title, --message, --level or --link, or --stdin-json together with --file <path>, exits 2 usage. Flags alone need --message; stdin that is a terminal with no source and no --message exits 2 usage. A --file that does not exist, cannot be read or is not a regular file (the tool opens it with O_NONBLOCK and checks the opened descriptor; a symlink to a regular file is fine) exits 2 usage.
At most 1048576 bytes are read from a source. More, input that is not valid UTF-8 or that begins with a byte order mark, JSON that fails to parse, nests too deeply (RecursionError), repeats an object key or contains NaN or Infinity, a top-level value that is not an object, or input that does not arrive within the deadline (the [Deadline](#home-assistant-edge)) exits 20 refused, reason invalid_payload, details.pointer "".
Fields: an unknown field, a field of the wrong type (null is a wrong type: absent fields are omitted), a level outside info, warn, action, error, or a title or message of more than 100000 characters exits 20 invalid_payload with details.pointer set to "/<field>". A flag value is checked like the same JSON field and uses the same pointer. A message that is empty after sanitizing is empty_message (the schema has no minLength for it). Error messages and details never contain an input value, only the pointer and the rule.
Flag and combination errors (an unknown flag, a missing value, a bad --actor) exit 2 usage.
```

Flag text is untrusted and goes through the same [sanitizer](#sanitizer) as stdin text; flags exist for humans. ha-notice never forwards free-form data.

### Sanitizer

```text
Applied to title and message before rendering, in this order. Every pattern in this document is matched against the whole string (re.fullmatch); a trailing newline never passes.
1. Input is read as bytes and decoded as strict UTF-8, never through the locale. Invalid UTF-8 or a lone surrogate: exit 20 refused, reason invalid_payload.
2. CRLF, CR, U+0085, U+2028 and U+2029 become LF. The tab becomes a space.
3. These characters are removed: every character of category Cc other than LF, and of categories Cf, Cs and Co; the noncharacters U+FDD0 to U+FDEF and U+FFFE and U+FFFF of every plane; and the blank-looking fillers U+034F, U+115F, U+1160, U+17B4, U+17B5, U+180B to U+180D, U+2800, U+3164, U+FE00 to U+FE0F, U+FFA0 and U+E0100 to U+E01EF. This removes zero-width, direction and tag characters, the soft hyphen and the byte order mark. It also removes the zero-width joiner and variation selector 16, so some emoji sequences are shown as separate or text-style emoji.
4. Trailing whitespace of every line is removed (str.rstrip), then runs of more than two LF become two, then leading and trailing whitespace is removed (str.strip, Unicode whitespace).
5. title only: every LF becomes a space, runs of spaces become one space, and the result is stripped again.
A message that is empty after step 4 is refused with reason empty_message. A title that is empty after step 5 is absent.
```

Template syntax (`{{ … }}`, `{% … %}`) is not escaped: Home Assistant was tested not to render templates in REST-supplied `title` and `message` ([Residual risks](#residual-risks) says what that rests on).

### Command messages

The companion apps treat a message equal to a keyword as a command to the phone instead of text. After sanitizing, and before any cut, take `unicodedata.normalize("NFKC", message).casefold().strip()`. The message is refused (exit 20 `command_keyword`, no details) when that value equals `tts` or matches `(command|kiosk|update|clear|remove|request)_[a-z0-9_]*` as a whole. A message with a space, a second word or a second line (`update_deps finished`) is not refused. The title is not checked. The families cover every keyword found in the documentation (`clear_notification`, `clear_badge`, `remove_channel`, `request_location_update`, `update_complications`, `update_widgets`, the `command_` and `kiosk_` families); `tts` is from memory and unverified. The tool never sends `data.tts_text` or any `command` field.

### Rendering

```text
Limits count Unicode code points. A title longer than its limit L is cut to its first L-1 characters plus … (L in all, before the level prefix is added) and truncated is true. The prefix is added after the cut and does not count. A message cut for length keeps as many characters as fit, has trailing whitespace removed, and ends with the marker so that the result, marker included, is within the limit; truncated is true. A cut may split a combining or emoji sequence; that is accepted. When the title is empty and the prefix is not, the title line is the prefix alone with no trailing space; when both are empty the title is absent.
```

- `title` is the notification title: limit 256 characters before the prefix; then the level's entry in `level_prefix` (defaults: none for `info`, `WARN:`, `ACTION:`, `ERROR:`; one-line strings up to 16 characters) joined with a space to the title, so a rendered title is at most 273 characters.
- `message` is the notification text, limited to `max_chars` code points (default 1000, 100 to 2000) and to 2000 UTF-8 bytes (not configurable), whichever is reached first; the cut is at a code point boundary and ends with the marker `…[truncated]`.
- `truncated` is true when the title or the message was cut.
- `data` is built only from this allowlist, never from caller input other than `link` and the dedupe key, in this order and omitted when empty:
  - `url` and `clickAction`: both set to the `link` (scheme lowercased) when it is given.
  - `tag`: `awkit-` plus the first 24 hex characters of the SHA-256 of the dedupe key's UTF-8 bytes, set whenever `--dedupe-key` is given. Home Assistant replaces an earlier notification with the same tag, whatever its level, so a retry does not show twice; a producer that must keep levels apart includes the level in its key.
  - `group`: config `default_group` when set.

The differing cut markers and default prefixes across the notifier tools are intentional ([design.md](design.md)).

## Commands

### `send`

`ha-notice send [--stdin-json | --file <path|->] [--title <t>] [--message <m>] [--level <l>] [--link <url>] [--dedupe-key <k>]`

Order, with the exit code of each refusal:

1. Parse flags (exit 2 `usage`).
2. Load config (exit 2 `config_invalid`). `enabled: false` prints `{"outcome": "disabled"}` (one line "disabled in config" on stderr without `--json`) and exits 22 here, before input is read.
3. Read and validate input ([Input](#notification); exit 2 `usage` for conflicting sources; exit 20 with reason `invalid_payload`, `empty_message`, `command_keyword`, `link_invalid` or `link_scheme`). The deadline starts here.
4. Render the request body ([Rendering](#rendering)). With `--dry-run`, print the result with `rendered` (the JSON body that would be sent, no secrets) and exit 0: needs neither `base_url`, `service` nor the credential, sends nothing and writes no log record.
5. A missing `base_url` or `service`, or an unreadable `ca_file`, exits 2 `config_invalid` with `details.key`. Read the token from the environment variable named by `token_env` (exit 12 `credential_invalid`, `details.env`).
6. POST to the service ([Home Assistant edge](#home-assistant-edge)) and map the response to an exit code ([Exit codes](#exit-codes)).
7. Append the [log record](#log) and print the result.

```text
Every JSON document that the tool sends, hashes or measures is serialized with json.dumps(obj, ensure_ascii=False, separators=(",", ":")), keys in the order given in this document, and encoded as UTF-8. bytes in the output and the log is the length of the request payload in that form (the request body).
message_sha256 is the first 16 hex characters of the SHA-256 of the UTF-8 bytes of the sanitized title (empty string when absent), a LF, and the sanitized message, before any cut, prefix or link, so the same input gives the same value in every notifier. dedupe_key_sha256 is the first 16 hex characters of the SHA-256 of the key's UTF-8 bytes. Both are null when not computed (a refusal before the text was sanitized, or no key).
--dedupe-key takes any non-empty string of at most 1024 characters (valid UTF-8, else exit 2 usage). It is only hashed; the send output echoes the caller's own key or null. --decision-id (repeatable) is accepted for uniformity with the design guide and ignored: the log is hash-only and there is no audit file.
--actor must match ^(human|auto):[A-Za-z0-9._@/-]{1,64}$ (else exit 2 usage). Without it the actor is human:<user> when stdin is a terminal (actor_source tty) and auto:unknown otherwise (default), where <user> is the login name from the password database with every character outside [A-Za-z0-9._@-] replaced by _ and cut to 64 characters; the design guide's me.name does not exist here because the tool has no me key.
```

The request body keys are in the order `title`, `message`, `data`, and `data` keys in the order `url`, `clickAction`, `tag`, `group`.

### `validate`

```text
validate never prompts. It prints {ok, enabled, checks: [{name, ok, message}]} (schemas/cli/validate.json), where enabled is the configured value. Checks run in the order listed for the tool; a failed check ends the run and later checks are omitted, so ok is true only when every printed check is ok. It exits 0 when ok is true, otherwise with the exit code of the failing check (config: 2; credential, probe and test_message: the exit code of the corresponding failure, 12). When the config cannot be loaded it prints the error envelope instead and exits 2. Without --json it prints one line per check on stderr.
--test-message sends one notification through the normal render and send path (level info, title "ha-notice", message "validate: test message"; no dedupe key or tag) and adds the check test_message; its message says that delivery is not observable and tells the user to look at the destination. It is a send: it is logged like a send, and it exits 22 like send when the tool is disabled. --probe makes only the calls that send no notification. Automation does not call --test-message.
```

Checks, in order: `config` (including that `base_url` and `service` are set and valid and that `ca_file` exists), `credential` (the variable is set, and holds 1 to 4096 printable ASCII characters), `probe` (only with `--probe`: `GET /api/`) and `test_message` (only with `--test-message`). With `--probe` the output gains `probe: {api_ok}` (boolean). When `enabled` is false, `validate` prints its document with `enabled: false` and only the `config` and `credential` checks, makes no `--probe` or `--test-message` call and exits 22.

## Global flags

| Flag | Meaning |
|---|---|
| `--json` | Machine output on stdout ([Output](#output)). |
| `--config <path>` | Config file instead of `~/.config/ha-notice/config.yaml` (drop-ins are read next to it). |
| `--dry-run` | `send` only: build and print, send nothing, read no credential, write no log record. |
| `--dedupe-key <k>`, `--decision-id <id>` | See the hashing rules under [`send`](#send) under [`send`](#send). |
| `--actor <actor>` | Recorded in the log; grammar in the hashing rules under [`send`](#send). |
| `--verbose`, `--quiet` | More or less human output on stderr; never a request line, header, URL or response body. `--quiet` does not suppress the `insecure_http` warning. |
| `--version` | Print `ha-notice <version>`. |

## Home Assistant edge

- The request URL is `<base_url>/api/services/notify/<service>`, built from the validated parts. `base_url`, after one trailing `/` run is removed, matches `(?i:https?)://(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~-]+)*` as a whole, with port 1 to 65535 and no path segment equal to `.` or `..`; `http` only with `allow_insecure_http: true`. The scheme and host are lowercased and the port is kept as written. A non-ASCII host is given as punycode. A value that fails exits 2 `config_invalid` (`details.key: base_url`); a `ValueError` from any parser is the same. `service` matches `[a-z0-9_]{1,64}` as a whole. A double or trailing slash is a 404 on the host, so none is sent.
- The token is read only from the environment variable named by `token_env` (default `HA_TOKEN`), trimmed, sent only as `Authorization: Bearer <token>`, never in argv, URL, logs, output or errors. `base_url` comes from the user's config.
- Request: `POST`, body `{"title", "message", "data"}` (`title` and `data` omitted when empty). `GET /api/` for `validate --probe` uses the same client, headers and deadline.

```text
All HTTP goes through gateway.py using http.client.HTTPSConnection (HTTPConnection only when allow_insecure_http is true), built from the validated host and port; urllib is not used. Proxy environment variables are not read and no proxy is supported in 0.x. Redirects are never followed and a Location header is never read, printed or logged: a 3xx answer is wrong_host_response. Headers are Content-Type: application/json, Accept: application/json, Connection: close and User-Agent: ha-notice/<version>. HTTP debug output is never enabled and --verbose never prints a request line, a header, a URL or a response body.
The TLS context is ssl.SSLContext(PROTOCOL_TLS_CLIENT) with check_hostname on, CERT_REQUIRED and a minimum of TLS 1.2. Trust comes from ssl.get_default_verify_paths().openssl_cafile and .openssl_capath (the compiled defaults), plus the config ca_file; SSL_CERT_FILE and SSL_CERT_DIR are ignored. If neither default path exists, the first existing file of /etc/ssl/certs/ca-certificates.crt, /etc/pki/tls/certs/ca-bundle.crt and /etc/ssl/cert.pem is used; if none exists the send is network_error with details.tls true.
The response is read in chunks of at most 1 KiB until 64 KiB is reached; a body that is longer, is not valid UTF-8 or fails the hardened JSON parse of the [Input](#notification) rules (duplicate keys and NaN refused, RecursionError caught) is a bad body.
Secrets: a credential is validated whole before any header or URL is built (the token must be 1 to 4096 printable ASCII characters), else exit 12 credential_invalid. No exception text from http.client, ssl or socket is ever printed or logged: the exit 1 handler prints the exception class name and a fixed message only, and an exception from the network layer is mapped by its class to a code of [Exit codes](#exit-codes). A credential, or any part of it, never appears in argv, a URL printed anywhere, a log record, an error message, a verbose line or an exit 1 message.
```

`ca_file` must be an absolute path (no `~`); a missing or unreadable file exits 2 `config_invalid` (`details.key: ca_file`) at step 5, and the file is added to the default trust.

**Deadline.**

```text
Config timeout is one wall-clock deadline for the whole send, counted from the start of input reading (step 3) to the end of step 6. It covers reading input, name resolution, connecting, TLS, writing the request, reading the response and retry waits. The network phase runs in a worker thread; the main thread waits for it with the time that remains and, at the deadline, reports the result below, writes the log record, prints the output and exits without waiting for the worker. A first SIGINT or SIGTERM is treated as the deadline having passed.
The result at the deadline depends on how far the request got. Before the first byte of the request was written: exit 12 network_error (retryable true, details.timeout true). After the first byte was written: exit 12 outcome_unknown. Input that has not arrived at the deadline is invalid_payload (the [Input](#notification) rules). A wait (a retry wait) that is longer than the time that remains ends the send at once with the code of the last result, without sleeping.
```

`connect_timeout` (default 3s) limits the connect phase; its expiry is `network_error` with `details.timeout: true`, so an unreachable host does not hold a caller for the whole `timeout`.

**Retries.**

```text
429: retried up to twice, after 2 s and then 4 s, or after the Retry-After value when it is 1 to 3 digits (seconds, at most 30; any other form is ignored); a wait longer than the time left in the deadline ends the send at once with rate_limited and retry_after_s set to that wait. A failure before the first request byte was written (name resolution, connection refused or timed out, a TLS handshake failure that is not a certificate verification failure) is retried once after 2 s inside the deadline, then is network_error. Nothing else is retried: a 5xx is upstream_error with unknown_outcome true, and any failure after the first request byte was written (timeout, reset, early end of the response) is outcome_unknown. Any 2xx other than the success form, including a 200 whose body is not the success form, is wrong_host_response with unknown_outcome true; any other status that is not listed is wrong_host_response with unknown_outcome false.
The log outcome is outcome_unknown whenever the envelope's unknown_outcome is true, and failed for any other exit 12.
```

| Response | Result |
|---|---|
| 200 with a JSON list (any list, whatever the content type; an empty list in testing) | `sent` (exit 0). |
| Any other 2xx, or a 200 whose body is not a JSON list | Exit 12 `wrong_host_response`. |
| 3xx | Exit 12 `wrong_host_response`. |
| 400 | Exit 12 `host_rejected` with `details.http_status` and `details.hint` (the fixed string `check the notify service name and the message; run validate --test-message`). The host's 400 is opaque: an unknown service, a missing message and an unknown field answer alike. |
| 401, 403 | Exit 12 `auth_required` with `details.http_status`. |
| 404, 405 | Exit 12 `wrong_host_response`; the message says `base_url` or its path prefix is probably wrong. |
| 429 | Retried as above; then exit 12 `rate_limited`. |
| 5xx | Exit 12 `upstream_error`; no retry. |
| Any other status | Exit 12 `wrong_host_response`. |
| Connection refused, DNS or TLS handshake failure, or connect timeout before the first request byte | Retried once as above; then exit 12 `network_error`. A certificate verification failure (`ssl.SSLCertVerificationError` only) is `network_error` with `details.tls: true` and a message that names `ca_file`. |
| Timeout or connection loss after the first request byte | Exit 12 `outcome_unknown`. |

`GET /api/` (probe) reuses this mapping: a 200 with a JSON object body is `probe.api_ok: true`; 401 and 403 are `auth_required`; 404 and 405 `wrong_host_response`; 5xx `upstream_error`; failures as for send.

The API answers success whether or not the push reached a phone and offers no way to learn that it did not. Output says `sent`, never `delivered`.

## Output

```text
Global flags may appear before or after the subcommand. The tool looks for --json in argv before it parses anything, so a usage error with --json prints the envelope (code usage) on stdout; --help and --version are exempt. Errors always print one line on stderr; with --json they also print the error envelope on stdout. With --json a successful send prints one object on stdout; without it human text goes to stderr and stdout is empty (a dry run prints the rendered text on stderr). A disabled tool prints {"outcome":"disabled"} on stdout with --json and one line on stderr without it, and exits 22 either way. stderr is advisory (warnings, verbose lines); the contract is the exit code plus the stdout JSON.
```

With `--json`, `send` prints one object ([schemas/cli/send.json](../schemas/cli/send.json)): `{outcome, tool, level, truncated, bytes, duration_ms, http_status, tag_set, dedupe_key, warnings, rendered}`. `outcome` is `sent`, `dry_run` or `disabled`; `bytes` is the UTF-8 size of the request body; `dedupe_key` echoes the caller's own `--dedupe-key` (or null); `http_status` is null for a dry run; `warnings` is an array of fixed strings, `[]` when none (the only value in 0.x is `insecure_http`); `rendered` is present only for a dry run. `allow_insecure_http: true` prints one stderr line on every real send (not on a dry run, and not in `validate` without a request) and adds `insecure_http` to `warnings`. Disabled output is `{"outcome": "disabled"}` and nothing else.

## Exit codes

```text
Codes 0 to 21 follow design guide section 4.2. Exit 0: sent or a dry run. Exit 1: internal error. Exit 2: usage or invalid configuration (codes usage, config_invalid). Exit 12: failed for a reportable reason (the codes of the tool, below). Exit 20: refused before sending because of the payload; code refused with a required reason. Exit 22: nothing sent because the tool is disabled in config (not an error; output {"outcome":"disabled"}). Exits 10, 11, 13 and 21 are never used: the tool stores no objects, has no hooks and never prompts. A caller treats exit 22 as a successful no-op.
The error envelope is {"error": {"code", "message", "reason", "details", "retryable", "retry_after_s", "unknown_outcome"}}; only code and message are required and the other keys are present with null when they do not apply. reason is set only on exit 20. retry_after_s is set only for rate_limited (the last wait performed, or the wait that did not fit the deadline). retryable means that sending the same notification again is safe. unknown_outcome means that the notification may already have been delivered. They are set as follows.
- Exit 2 and exit 20: retryable null, unknown_outcome null.
- Exit 1: retryable false; unknown_outcome true when the failure happened after the first byte of the request was written else false. The envelope on exit 1 is best effort: exit 1 with no envelope means the outcome is unknown.
- Exit 12: both are booleans: not sent and permanent (false, false): host_rejected, auth_required, credential_invalid; not sent and worth retrying (true, false): rate_limited, network_error (but false, false for a certificate failure, details.tls true); request accepted or possibly accepted (false, true): outcome_unknown, upstream_error and wrong_host_response when the host answered 2xx and the answer is not the success form (any other wrong_host_response is false, false). outcome_unknown and upstream_error are retryable true when a tag was sent (a retry replaces the earlier notification), else false.
details by code or reason: config_invalid: key (a config key, or the file path for a file that cannot be read or parsed); reason invalid_payload: pointer; credential_invalid: env; auth_required: http_status; host_rejected: http_status and hint; network_error: tls, timeout. A message never contains an input value or a credential.
```

| Exit | Meaning | Codes, or reasons for exit 20 |
|---|---|---|
| 0 | Accepted by Home Assistant (`sent`) or a dry run. | |
| 1 | Internal error. | Code: `internal` |
| 2 | Usage or invalid configuration. | Codes: `usage`, `config_invalid` |
| 12 | Failed for a reportable reason. | Codes: `host_rejected`, `auth_required`, `credential_invalid`, `rate_limited`, `upstream_error`, `network_error`, `outcome_unknown`, `wrong_host_response` |
| 20 | Refused before sending because of the payload: `code` is `refused` and `reason` is required. | Reasons (not codes): `invalid_payload`, `empty_message`, `command_keyword`, `link_invalid`, `link_scheme` |
| 22 | Nothing sent: the tool is disabled in config. | Outcome `disabled` (not an error; output `{"outcome": "disabled"}`) |

A router has one rule: 20 drop and surface, 12 read `retryable` and `unknown_outcome`, 22 no-op.

### Error envelope

The envelope is defined by [Exit codes](#exit-codes) above ([schemas/cli/error.json](../schemas/cli/error.json)). In ha-notice `details.hint` is set only on a 400 (`host_rejected`) and `retry_after_s` only on `rate_limited`. The envelope has no `tag_set`: `retryable` carries it.

## Hooks

None in 0.x. ha-notice sends one notification and takes no policy decisions; gating and routing belong to the caller. A `post-send` hook that notifies on failure could call this tool again and loop, which is the other reason there are none. Adding hooks later is additive.

## Calling from automation

```text
Canonical call: ha-notice send --stdin-json --json --actor auto:<name>, the payload on stdin, absent fields omitted (never null). Decide by exit code: 0 sent; 22 disabled, a successful no-op; 20 the payload was refused, do not retry (a caller may retry once without link after link_invalid or link_scheme, putting the URL in the message); 12 read retryable and unknown_outcome: retry only when retryable is true, and when unknown_outcome is true the notification may already have been delivered; 2 a usage or config fault of the caller or the deployment; 1 an internal error (no envelope means the outcome is unknown). The tool exits before reading stdin when it is disabled or its config is invalid, so a caller ignores EPIPE or SIGPIPE on the stdin write and decides by the exit code alone. The tool does no queueing: a caller sends one notification at a time per tool and does not start several in parallel. To send to several destinations use one config file per destination with --config. A permission profile for an agent allows only send --stdin-json --json --actor ... and denies --config, --file and the text flags, because those choose the destination and read arbitrary files. ha-notice refuses a message that is only a companion-app command word ([Command messages](#command-messages)), so producers send sentences.
```

## Config

```text
Config is read from ~/.config/ha-notice/config.yaml (XDG_CONFIG_HOME is honoured when it is an absolute path), then config.d/*.yaml in lexical order; maps merge. A missing default config file means defaults; a missing file named by --config exits 2 config_invalid with details.key "--config". Files are parsed with yaml.safe_load, must be at most 65536 bytes and regular files (symlinks are followed; the opened descriptor is checked), and the top level must be a mapping; a file that cannot be read or parsed exits 2 config_invalid with details.key set to its path. Unknown keys are refused. Booleans are only the YAML booleans true and false; a boolean is never accepted for a number, and a number must be finite. There are no environment overrides and no per-repo override: precedence is flags, then config, then defaults. The environment variable that holds a credential is named by the config key shown in the table; it is the only variable the tool reads for a secret.
Durations (timeout and others) are a number of seconds, or a string matching [0-9]+(\.[0-9]+)?(ms|s|m)? (no unit means seconds); the tool enforces the range of each key at load with a check that is false for NaN (lo <= x <= hi). Invalid config exits 2 config_invalid, details.key naming the key; a message names the key and the rule and never the value (for a name key that looks like a URL it says "must be a variable name").
```

Schema: [schemas/config.json](../schemas/config.json); example: [config.example.yaml](../config.example.yaml). `base_url` and `service` have no default, so nothing is sent until they are set. `level_prefix` values are run through the sanitizer rule (one line) at load; a value that the sanitizer would change is `config_invalid`, it is not rewritten.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` makes `send` exit 22 without reading input or the credential. |
| `base_url` | none (required) | Home Assistant base URL, `https://host[:port][/prefix]` ([Home Assistant edge](#home-assistant-edge)). |
| `service` | none (required) | The `notify` service name, the part after `notify.` (for example a `mobile_app_` service). |
| `token_env` | `HA_TOKEN` | Name of the environment variable holding a long-lived access token; matches `^HA_[A-Z0-9_]{1,60}$` so a config cannot name another secret. |
| `allow_insecure_http` | `false` | Allow an `http://` base URL (the token then travels in cleartext). |
| `ca_file` | unset | Extra CA bundle, an absolute path; the way to trust a self-signed server. There is no key that turns verification off. |
| `link_hosts` | unset | List of 1 to 32 lowercase host names, each `[a-z0-9.-]{1,253}`; see the link rule. |
| `level_prefix` | `{info: "", warn: "WARN:", action: "ACTION:", error: "ERROR:"}` | Title prefixes, at most 16 characters each. |
| `default_group` | unset | `data.group` for every notification; `^[A-Za-z0-9_ -]{1,64}$`. |
| `max_chars` | `1000` | Message limit in code points, 100 to 2000. |
| `timeout` | `10s` | The one deadline of a `send` ([Deadline](#home-assistant-edge)), 1s to 120s. |
| `connect_timeout` | `3s` | Limit for the connect phase, 1s to 30s; must not exceed `timeout`, else `config_invalid`. |
| `log` | `true` | `false` writes no `log.jsonl`. |

## Environment variables

- The variable named by `token_env` holds the credential. Under cron or any hook it must be in the calling process's environment; the docs recommend a mode-0600 env file sourced by the cron line. A token stored under another name is aliased to `HA_TOKEN` in that env file. ha-notice never reads shell startup files or secret files itself.
- `XDG_CONFIG_HOME`, `XDG_STATE_HOME` and `HOME` locate the config and state; these are the only other variables read. There are no `HA_NOTICE_*` overrides.

## Log

```text
The state directory is $XDG_STATE_HOME/ha-notice when XDG_STATE_HOME is set to an absolute path, else $HOME/.local/state/ha-notice (HOME from the password database when unset). It is created with mode 0700, opened with O_DIRECTORY and O_NOFOLLOW, and checked on that descriptor to be owned by the user with no group or other permissions; every file below it is opened relative to that descriptor (dir_fd), the log with O_APPEND and mode 0600. It is used only when it is needed (a log record). If it cannot be used the tool warns once on stderr, writes no log record, and the exit code is unchanged: a state problem never blocks or fails a send.
log.jsonl holds one record per outcome that reaches step 3 or later. Not logged: exit 1, exit 2, exit 22 and dry runs. A write takes an exclusive flock on log.lock for the few microseconds it needs, rotates when the file is 1 MiB or more (log.jsonl.2 to .3, .1 to .2, log.jsonl to .1), and appends the record with one write of less than 1 KiB. A log write failure (including a full disk) warns on stderr and never changes the exit code. config log false writes nothing.
outcome is sent (exit 0), refused (exit 20), outcome_unknown (exit 12 whenever the envelope's unknown_outcome is true) or failed (any other exit 12). code is refused for exit 20, the error code for exit 12 and null on success; reason is the refusal reason for exit 20 and null otherwise. actor_source is flag, tty or default. duration_ms (integer, never null) is the time from the start of step 3 to just before the log write. Nullable and always present: level (null when no valid level was read), bytes, truncated and message_sha256 and dedupe_key_sha256 (null for a refusal before rendering, or when not computed), http_status (null unless a response arrived). Records never contain a title, message, link, URL, base URL, service, host or credential. There is no audit file: a notification changes nothing in a system of record.
```

[schemas/log.json](../schemas/log.json). Fields: `{ts, tool, version, outcome, exit, code, reason, level, bytes, truncated, duration_ms, http_status, message_sha256, dedupe_key_sha256, tag_set, actor, actor_source}`. `tag_set` is a nullable boolean (null when the request was not built). ha-notice has no `attempts` field and takes no send lock. The log's `message_sha256` and `dedupe_key_sha256` follow the hashing rules under [`send`](#send).

## Files

| Path | Content |
|---|---|
| `~/.config/ha-notice/config.yaml`, `config.d/*.yaml` | Config. |
| `~/.local/state/ha-notice/log.jsonl` (and `.1` to `.3`) | Log records. |
| `~/.local/state/ha-notice/log.lock` | Lock held while a log record is written and rotated. |

The state directory follows the state rules under [Log](#log) above. There is no database and no migration.

## Labels

ha-notice creates no long-lived objects and takes no labels.

## TUI

None in v1.

## Residual risks

- **No delivery confirmation.** Success is returned whether or not the push is delivered, and the message may still be cut or dropped on the phone. The display limit is unknown (the API accepted 100000 characters); the defaults of 1000 characters and 2000 bytes are conservative until the phone check ([design.md](design.md), Live verification).
- **Templates were tested, not guaranteed.** Not rendering `{{ … }}` in REST-supplied text was observed on one Home Assistant version; a future version or a custom notify service could render it. The tool does not escape template syntax, so a caller who sends untrusted text to such a service takes that risk.
- **The command rule is a guess at the apps' matching.** The rule assumes the apps match the whole message; a platform that also matches after other normalization could still treat other text as a command, and the companion apps may add commands.
- **The token is a long-lived credential.** A person who can edit the user's config can send the token anywhere (`base_url` comes from the config); the token is valid for the whole Home Assistant API, not only `notify`; use a token for a dedicated user where possible.
- **Cleartext and self-signed servers.** `allow_insecure_http` trades the token's safety for convenience; it is off by default and each real send with it set warns on stderr. A self-signed server is trusted through `ca_file`; no key turns verification off.
- **Taps open links.** `link` becomes the tap action and is limited to `http` and `https`; the apps accept more schemes (`app://`, intents, settings), and the host API does not reject them, which is why the tool does. With `link_hosts` unset a producer can aim the tap target at any web address; the push does not show the URL.
- **Lock-screen exposure.** Title and message appear on the phone's lock screen according to the phone's settings; callers must not send secrets.
- **Opaque errors.** Several different mistakes return the same 400, so diagnosis depends on `validate --test-message` and on checking `service`.
- **Tag replacement.** A producer who can guess a dedupe key can replace an unread notification with the same key; the router owns the key policy.
- **`level` is advisory.** The prefix does not authenticate the sender: a producer can write `ERROR:` in a title.
- **Same-user boundary.** A process that can write the user's config or set an XDG path can redirect the tool; the state directory is checked but the config is trusted.
- **Short hashes.** `message_sha256` is a 64-bit unsalted hash; a short message can be confirmed against the log by a reader of the 0600 file.

## Platform notes

Linux and WSL are required. macOS is expected to work but is not a required platform.
