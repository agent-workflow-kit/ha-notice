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
| `message` | string | yes | Input over 100000 characters exits 20 `invalid_payload`. Must not be empty after sanitizing or absent (else exit 20 `empty_message`) and must not be a [command message](#command-messages) (else exit 20 `command_keyword`). |
| `level` | `info`, `warn`, `action`, `error` | no | Default `info`. Ordered `info < warn < action < error`; the order matters to callers, not to ha-notice. |
| `link` | string | no | 1 to 1024 printable ASCII characters, `http` or `https`; see the link rule below. |

**Link rule.** `link` is optional and is checked in this order. (1) It is a string of 1 to 1024 printable ASCII characters (U+0021 to U+007E); anything else, including whitespace, control characters, non-ASCII characters and an empty string, is reason `link_invalid` (callers percent-encode paths and give hosts as punycode). (2) If it starts with a scheme token (`[A-Za-z][A-Za-z0-9+.-]*:`) whose lowercase form is not `http` or `https`, the reason is `link_scheme`. (3) It must match, as a whole, `(?i:https?)://HOST(?::[0-9]{1,5})?(?:[/?]T*)?(?:#T*)?` where `HOST` is `(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])` and `T` is `(?:[A-Za-z0-9\-._~:/?@!$&'()*+,;=]|%[0-9A-Fa-f]{2})`; a port must be 1 to 65535 (taken from the match, never from a URL parser), and the text between the brackets must be a valid IPv6 address (`ipaddress.IPv6Address`); else the reason is `link_invalid`. There is no userinfo, empty host, backslash, quote, angle bracket, brace, bar, caret, backtick or invalid percent escape. The link is not parsed again: no code calls a URL parser on it. The scheme is lowercased wherever the link is rendered. The schema pattern is a coarse gate (printable ASCII, 1 to 1024); the tool is authoritative. A link names a place to open and is never a promise that it is safe: a caller that builds links from untrusted text takes that risk.

When config `link_hosts` is set, the link's host (lowercased, without port; a bracket host is never matched, so it is refused) must equal an entry or end with `.` plus an entry, else exit 20 `link_invalid` with `details.pointer` `/link`. An entry matches itself and every subdomain, so do not list a shared hosting domain. With `link_hosts` unset a producer can aim the tap target at any web address; the push does not show the URL. `link_hosts` is the only protection against an arbitrary tap target.

**Input.** Exactly one source is used: JSON on stdin (`send --stdin-json`, also the default when stdin is not a terminal and no text flag is given), JSON from `--file <path>` (`--file -` is stdin, the same source), or flags. These are flag and combination errors and exit 2 `usage` at step 1, before the config is consulted, so they win over a disabled tool: a JSON source together with `--title`, `--message`, `--level` or `--link`; `--stdin-json` together with `--file <path>` (`--stdin-json --file -` names one source and is accepted); `--stdin-json` or `--file -` when stdin is a terminal; stdin that is a terminal with no source and no `--message`; flags without `--message`; an unknown flag, a missing value, a bad `--actor`. A `--file` that does not exist, cannot be read or is not a regular file (the tool opens it with `O_NONBLOCK` and checks the opened descriptor; a symlink to a regular file is fine) exits 2 `usage` at step 3. A closed or unreadable stdin is empty input.

Input is read through the gateway in slices of at most 100 ms, so the main thread notices the deadline and a signal between slices; a regular `--file` is read in chunks of 64 KiB with the same checks between chunks. At most 1048576 bytes are read from a source. More, input that is not valid UTF-8 or that begins with a byte order mark, JSON that fails to parse (any `ValueError`, `RecursionError` or `OverflowError`, whatever the Python version's limit for very long integers or nesting), repeats an object key or contains NaN or Infinity, or a top-level value that is not an object exits 20 refused, reason `invalid_payload`, `details.pointer` `""`.

Input that does not arrive within the deadline (a producer that stalls) exits 12 `unavailable` with `details.phase` `input`, `retryable` true and `unknown_outcome` false: nothing was sent, and the caller owns the resend. A SIGTERM, SIGINT or SIGHUP received before the send starts exits 128+N with no envelope, sends nothing and writes no log record; the sender of the signal knows ([Deadline](#home-assistant-edge)).

Fields: an unknown field, a field of the wrong type (null is a wrong type: absent fields are omitted), a level outside `info`, `warn`, `action`, `error`, or a title or message of more than 100000 characters exits 20 `invalid_payload` with `details.pointer` set to `/<field>` (a field name that does not match `[A-Za-z0-9_-]{1,64}` is reported as `/?`). A flag value is checked like the same JSON field and uses the same pointer. A message that is absent or empty after sanitizing is `empty_message` (reason `empty_message`, no pointer; the schema has no `minLength` for it). Error messages and details never contain an input value, only the pointer and the rule.

The tool may exit without reading all of stdin (a refusal before step 3, an over-size input, any exit 20), so a caller ignores EPIPE and SIGPIPE on the stdin write.

Flag text is untrusted and goes through the same [sanitizer](#sanitizer) as stdin text; flags exist for humans. ha-notice never forwards free-form data.

### Sanitizer

Applied to title and message before rendering, in this order. Every pattern in this document is matched against the whole string (`re.fullmatch`); a trailing newline never passes.

1. Input is read as bytes and decoded as strict UTF-8, never through the locale. Invalid UTF-8 or a lone surrogate: exit 20 refused, reason `invalid_payload`.
2. CRLF, CR, U+0085, U+2028 and U+2029 become LF. The tab becomes a space.
3. The characters in the table below are removed; nothing else is. The table and this rule are one list.
4. Trailing whitespace of every line is removed (`str.rstrip`), then runs of more than two LF become two, then leading and trailing whitespace is removed (`str.strip`, Unicode whitespace).
5. title only: every LF becomes a space, runs of spaces become one space, and the result is stripped again.

| Class | Characters | Action |
|---|---|---|
| Cc | every control character other than LF | Removed (the tab became a space in step 2). |
| Cs, Co | surrogates, private use | Removed. |
| Cn | unassigned code points and noncharacters, including U+FDD0 to U+FDEF and U+FFFE and U+FFFF of every plane | Removed. Membership follows the running Python's Unicode tables; the golden test pins a fixed list of code points. |
| Zl, Zp | U+2028, U+2029 | Became LF in step 2. |
| Listed Cf and default-ignorable | U+00AD, U+061C, U+180E, U+200B, U+200E, U+200F, U+202A to U+202E, U+2060 to U+206F, U+FEFF, U+FFF9 to U+FFFB, U+E0000 to U+E007F, U+E0100 to U+E01EF; the fillers U+115F, U+1160, U+3164 and U+FFA0; U+2800; the Mongolian selectors U+180B to U+180D and U+180F | Removed. |
| Kept | U+FE00 to U+FE0F (variation selectors for emoji and CJK text), U+200C and U+200D (ZWNJ and ZWJ: Persian, Indic and emoji sequences), the Arabic number signs U+0600 to U+0605, U+06DD, U+070F and U+08E2, and every other Cf character not listed above | Kept. |

Some listed characters are visible in some script and are removed on purpose: U+2800 (Braille blank), the Mongolian free variation selectors, and the tag block (a flag emoji built from tag characters becomes its base emoji). Because the zero-width joiner and the variation selectors are kept, emoji sequences are shown as sent.

A text is empty when it has no character other than Unicode whitespace and characters of the categories Mn, Mc and Me. A message that is empty after step 4 is refused with reason `empty_message` (so is a message that is absent from the JSON object). A title that is empty after step 5, or absent, is absent.

Template syntax (`{{ … }}`, `{% … %}`) is not escaped: Home Assistant was tested not to render templates in REST-supplied `title` and `message` ([Residual risks](#residual-risks) says what that rests on).

### Command messages

The companion apps treat a message equal to a keyword as a command to the phone instead of text. After sanitizing, and before any cut, take `unicodedata.normalize("NFKC", message).casefold().strip()`. The message is refused (exit 20 `command_keyword`, no details) when that value equals `tts` or matches `(command|kiosk|update|clear|remove|request)_[a-z0-9_]*` as a whole. A message with a space, a second word or a second line (`update_deps finished`) is not refused. A legitimate message that is equal to a keyword, or that is one token starting `command_` or `kiosk_` (or any other listed family), is refused with `command_keyword`; the router's recovery is to prefix the text (for example its source and a colon). Exit 20 here never means that anything was sent. The title is not checked. The families cover every keyword found in the documentation (`clear_notification`, `clear_badge`, `remove_channel`, `request_location_update`, `update_complications`, `update_widgets`, the `command_` and `kiosk_` families); `tts` is from memory and unverified. The tool never sends `data.tts_text` or any `command` field.

### Rendering

Limits count Unicode code points. A title longer than its limit L is cut to its first L-1 characters plus … (L in all, before the level prefix is added) and `truncated` is true. The prefix is added after the cut and does not count. A message that does not fit its budget is cut: the kept text is the longest prefix of the sanitized message such that kept with trailing whitespace removed plus the marker fits every limit of the tool; `truncated` is true. A cut may split a combining or emoji sequence; that is accepted. When the title is empty and the prefix is not, the title line is the prefix alone with no trailing space; when both are empty the title is absent.

- `title` is the notification title: limit 256 characters before the prefix; then the level's entry in `level_prefix` (defaults: none for `info`, `WARN:`, `ACTION:`, `ERROR:`; one-line strings up to 16 characters) joined with a space to the title, so a rendered title is at most 273 characters.
- `message` is the notification text, limited to `max_chars` code points (default 1000, 100 to 2000) and to 2000 UTF-8 bytes (not configurable), whichever is reached first; the cut is at a code point boundary and ends with the marker `…[truncated]`.
- `truncated` is true when the title or the message was cut.
- `data` is built only from this allowlist, never from caller input other than `link` and the dedupe key, in this order and omitted when empty:
  - `url` and `clickAction`: both set to the `link` (scheme lowercased) when it is given.
  - `tag`: `awkit-` plus the first 24 hex characters of the SHA-256 of the dedupe key's UTF-8 bytes, set whenever `--dedupe-key` is given. Home Assistant replaces an earlier notification with the same tag, whatever its level, so a retry does not show twice. Replacement by tag was observed on one phone; a late first request can replace a newer notification with the same tag, which is accepted and documented, so a router that cares puts the level or a sequence number in its key.
  - `group`: config `default_group` when set.

## Commands

### `send`

`ha-notice send [--stdin-json | --file <path|->] [--title <t>] [--message <m>] [--level <l>] [--link <url>] [--dedupe-key <k>] [--decision-id <id>]`

Order, with the exit code of each refusal:

1. Parse flags and check flag combinations (exit 2 `usage`).
2. Find the home directory and load config (exit 2 `config_invalid`; a failed home lookup is `details.key` `home`, see [Config](#config)): the syntax of every key that is present is checked, including that `base_url` and `ca_file` are well formed and that `ca_file` is an absolute path. Then `enabled: false` prints `{"outcome": "disabled"}` (one line "disabled in config" on stderr without `--json`) and exits 22 here, before input is read. Then, unless `--dry-run`, a missing `base_url` or `service`, or an unreadable `ca_file`, exits 2 `config_invalid` with `details.key`, so a bad destination is found before stdin is read.
3. Read and validate input ([Input](#notification); exit 2 `usage` for a `--file` problem; exit 20 with reason `invalid_payload`, `empty_message`, `command_keyword`, `link_invalid` or `link_scheme`; exit 12 `unavailable` when the input does not arrive in time). The deadline starts here.
4. Render the request body ([Rendering](#rendering)). With `--dry-run`, print the result with `rendered` (the JSON body that would be sent, no secrets) and exit 0: needs neither `base_url`, `service` nor the credential, sends nothing and writes no log record.
5. Read the token from the environment variable named by `token_env` (exit 12 `credential_invalid`, `details.env`).
6. POST to the service ([Home Assistant edge](#home-assistant-edge)) and map the response to an exit code ([Exit codes](#exit-codes)).
7. Print the result and flush stdout, then append the [log record](#log) (the log step is bounded and never changes what was printed).

Every JSON document that the tool sends, hashes or measures is serialized with `json.dumps(obj, ensure_ascii=False, separators=(",", ":"))`, keys in the order given in this document, and encoded as UTF-8. `bytes` in the output and the log is the length of the request payload in that form (the request body).

`message_sha256` is the first 16 hex characters of the SHA-256 of the UTF-8 bytes of the sanitized title (empty string when absent), a LF, and the sanitized message, before any cut, prefix or link. `dedupe_key_sha256` is the first 16 hex characters of the SHA-256 of the key's UTF-8 bytes. Both are null when not computed (a refusal before the text was sanitized, or no key).

`--dedupe-key` takes any non-empty string of at most 1024 characters (valid UTF-8, else exit 2 `usage`); a caller passes the `=` form with a hex digest of the key. It is only hashed; the send output echoes the caller's own key or null. `--decision-id` (repeatable) is accepted for uniformity with the design guide and ignored: the log is hash-only and there is no audit file. Both are `send` flags.

`--actor` must match `(human|auto):[A-Za-z0-9._@/-]{1,64}` as a whole (else exit 2 `usage`). Without it the actor is `human:<user>` when stdin is a terminal (`actor_source` `tty`) and `auto:unknown` otherwise (`default`), where `<user>` is the login name from the password database with every character outside `[A-Za-z0-9._@-]` replaced by `_` and cut to 64 characters, or `unknown` when the lookup fails; the design guide's `me.name` does not exist here because the tool has no `me` key.

The request body keys are in the order `title`, `message`, `data`, and `data` keys in the order `url`, `clickAction`, `tag`, `group`.

### `validate`

`ha-notice validate [--probe] [--test-message]`

`validate` never prompts. It prints `{ok, enabled, checks: [{name, ok, message}]}` ([schemas/cli/validate.json](../schemas/cli/validate.json)), where `enabled` is the configured value; plain `validate` ignores `enabled` except to report it, so a tool with `enabled: false` still reports its config and environment faults. Checks run in the order listed for the tool; a failed check ends the run and later checks are omitted, so `ok` is true only when every printed check is ok. It exits 0 when `ok` is true, otherwise with the exit code of the failing check (`config`: 2; every other check: 12). When the config cannot be loaded it prints the error envelope instead and exits 2. Without `--json` it prints one line per check on stderr.

`--test-message` sends one notification through the normal render and send path (level `info`, title `ha-notice`, message `validate: test message`; no dedupe key or tag) and adds the check `test_message`; its message says that delivery is not observable and tells the user to look at the destination. It is a send: it is logged like a send. A failed `test_message` check carries only the exit code (12), so a caller treats any non-zero exit as "look at the destination". `--probe` makes only the calls that send no notification. With `enabled` false, `--probe` and `--test-message` make no call: `validate` prints `{"outcome":"disabled"}` ([schemas/cli/send.json](../schemas/cli/send.json)) and exits 22 before any check, as `send` does at step 2. For `--probe` and `--test-message` the deadline and `duration_ms` start when that check starts; `--dry-run` has no effect on `validate`. Automation does not call `--test-message`; a doctor runs `validate --json [--config <path>]` and reads `enabled`.

Checks, in order: `config` (every key valid, `base_url` and `service` set, `ca_file` readable), `credential` (the variable is set and, after `str.strip`, holds 1 to 4096 characters, each U+0021 to U+007E), `probe` (only with `--probe`: the call described under [Home Assistant edge](#home-assistant-edge)) and `test_message` (only with `--test-message`). With `--probe` the output gains `probe: {api_ok}` (boolean), present whenever the probe check ran and false on any failure. A request made by `validate` prints the `insecure_http` warning on stderr like a send; `validate.json` carries no `warnings`.

## Global flags

| Flag | Meaning |
|---|---|
| `--json` | Machine output on stdout ([Output](#output)). |
| `--config <path>` | Config file instead of `.config/ha-notice/config.yaml` under the home directory; drop-ins are read from `config.d/` beside it. |
| `--dry-run` | `send` only: build and print, send nothing, read no credential, write no log record. |
| `--actor <actor>` | Recorded in the log; grammar in the hashing rules under [`send`](#send). |
| `--verbose`, `--quiet` | See [Output](#output). `--quiet` does not suppress the `insecure_http` warning. |
| `--version` | Print `ha-notice <version>`. |
| `-h`, `--help` | Print the usage text on stdout and exit 0, before or after the subcommand. |

Parse rules (each violation is exit 2 `usage` at step 1): a value flag given twice, also once on each side of the subcommand; `--verbose` together with `--quiet`; a bare `--` anywhere; any short option other than `-h`; an empty `--actor` or `--dedupe-key`. An empty `--config` or `--file` is not a parse error: it is judged later like any other path (a missing config file is `config_invalid`, a bad `--file` is exit 2 at step 3). Usage messages are fixed strings and never contain input.

## Home Assistant edge

- The request URL is `<base_url>/api/services/notify/<service>`, built from the validated parts. `base_url`, after one trailing `/` run is removed, matches `(?i:https?)://(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~-]+)*` as a whole, with port 1 to 65535 and no path segment equal to `.` or `..`; `http` only with `allow_insecure_http: true`. The scheme and host are lowercased and the port is kept as written. A non-ASCII host is given as punycode. A value that fails exits 2 `config_invalid` (`details.key: base_url`); a `ValueError` from any parser is the same. `service` matches `[a-z0-9_]{1,64}` as a whole. A double or trailing slash is a 404 on the host, so none is sent.
- The token is read only from the environment variable named by `token_env` (default `HA_TOKEN`), trimmed with `str.strip()`, sent only as `Authorization: Bearer <token>`, never in argv, URL, logs, output or errors. `base_url` comes from the user's config.
- Request: `POST`, body `{"title", "message", "data"}` (`title` and `data` omitted when empty). `GET /api/` for `validate --probe` uses the same client, headers and deadline and sends no `Content-Type`.

All HTTP goes through gateway.py using `http.client.HTTPSConnection` (`HTTPConnection` only when `allow_insecure_http` is true), built from the validated host and port; urllib is not used. The gateway resolves, connects and completes the TLS handshake before the request is built (`conn.connect()`, then the gate of the Deadline paragraph moves to writing, then `conn.request`). Proxy environment variables are not read and no proxy is supported in 0.x. Redirects are never followed and a Location header is never read, printed or logged: a 3xx answer is `wrong_host_response`. Headers are `Content-Type: application/json` (not on a GET), `Accept: application/json`, `Accept-Encoding: identity` (`http.client` sends it unasked), `Connection: close` and `User-Agent: ha-notice/<version>`; the Host header is the authority as validated. HTTP debug output is never enabled and `--verbose` never prints a request line, a header, a URL or a response body.

The TLS context is `ssl.SSLContext(PROTOCOL_TLS_CLIENT)` with `check_hostname` on, `CERT_REQUIRED` and a minimum of TLS 1.2. Trust comes from the compiled defaults `ssl.get_default_verify_paths().openssl_cafile` (used when it is a regular file that loads at least one CA certificate) and `.openssl_capath` (used when it is a directory with at least one entry), plus the config `ca_file`; `SSL_CERT_FILE` and `SSL_CERT_DIR` are ignored, and the spec never uses `.cafile` or `.capath`, which follow them. What is checked: usability can be verified only for a bundle file. A directory is used when it exists and has an entry; whether it holds certificates the library can load is not checked, so if the default trust is a directory only and the server's certificate does not verify, the failure is reported as `network_error` with `details.tls` true, not retryable. If neither compiled path is usable, the first regular file of `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt` and `/etc/ssl/cert.pem` that loads at least one CA certificate is used. When the default trust is empty (nothing above is usable), `ca_file` alone is the whole trust; with a non-empty default trust `ca_file` is added to it. With no default trust and no `ca_file` the send is `network_error` with `details.tls` true and a message that says no usable CA certificates were found. A certificate chain or host name failure is `network_error` with `details.tls` true. There is no option to disable verification.

The response is read in chunks of at most 1 KiB until the cap (64 KiB) is reached; a body that is longer, is not valid UTF-8 or fails the hardened JSON parse of the [Input](#notification) rules (duplicate keys, NaN, `ValueError`, `RecursionError` and `OverflowError` refused) is a bad body.

The code of a failure is chosen by phase, not by the class of the exception, and the phase is read from the state of the deadline gate alone (see Deadline): the gate enters `writing` before the first write attempt, and the number of bytes that reached the socket is never observed. An exception while the gate is `idle` (any class) is `network_error` (`details.tls` and `details.timeout` from the class) and may be retried once. Once the gate is `writing`, any failure without a complete HTTP response is never `network_error` and is never retried: an exception that means the connection or the answer was lost (`OSError`, `ssl.SSLError`, a timeout, `http.client.RemoteDisconnected`, `IncompleteRead`) is `outcome_unknown`; an answer that arrives but is not HTTP (`BadStatusLine`, `LineTooLong`, `UnknownProtocol` and any other `http.client.HTTPException`) is `wrong_host_response` with `unknown_outcome` true. No exception text from `http.client`, `ssl` or `socket` is ever printed or logged: the exit 1 handler prints the fixed message `internal error` only, never the class name.

Secrets: a credential is validated whole before any header or URL is built (the token must be 1 to 4096 characters, each U+0021 to U+007E, after `str.strip`), else exit 12 `credential_invalid`. A credential, or any part of it, never appears in argv, a URL printed anywhere, a log record, an error message, a verbose line or an exit 1 message.

`ca_file` must be an absolute path (no `~`); a missing or unreadable file exits 2 `config_invalid` (`details.key: ca_file`) at step 2 unless `--dry-run`, and the file is added to the default trust.

**Deadline.** Config `timeout` is one monotonic deadline for the whole send, counted from the start of input reading (step 3) to the end of step 6. It covers reading input, name resolution, connecting, TLS, writing the request, reading the response and retry waits. Input is read by the main thread in slices ([Input](#notification)). The network phase runs in a daemon worker thread. A gate with three states, idle, writing and abandoned, guarded by one lock, decides who wins, and it alone classifies the phase. The worker connects (name resolution, TCP, TLS) while the gate is idle. Every attempt (the first request, each 429 retry and each connection retry) takes the idle-to-writing step atomically under the lock, immediately before its first call that can put request bytes on the socket, and refuses to go on if the gate is abandoned. The worker releases the lock before the socket call; nothing blocking runs under the lock, so the main thread's acquire is a short critical section and cannot deadlock. A fully read 429 response returns the gate to idle (the host accepted nothing), so the next connection starts from idle. The worker publishes a complete response to a result slot under the same lock. At the deadline the main thread takes the lock and decides: first it checks the result slot, and a complete response wins over the deadline; otherwise, if the gate is idle it becomes abandoned and the result is exit 12 `network_error` (retryable true, `details.timeout` true), and if the gate is writing the result is exit 12 `outcome_unknown` (once writing was entered, any failure without a complete HTTP response is `unknown_outcome`, never `network_error`). The worker closes its socket when it finds the gate abandoned. Then the main thread prints the output and flushes stdout, writes the log record and ends the process with `os._exit`; the worker is never joined. The worker's body catches `BaseException` and hands it to the main thread as an exit 1 internal error (the exit 1 handler then prints the fixed message `internal error` only, never the class name); `threading.excepthook` prints nothing. A deadline that passes while input is being read is exit 12 `unavailable` ([Input](#notification)). A wait (a retry wait) that is longer than the time that remains ends the send at once with the code of the last result, without sleeping.

SIGINT, SIGTERM and SIGHUP are handled once. A signal received before the send starts (that is, before the worker is started at step 6, so also during input) exits 128+N with no envelope on stdout, sends nothing and writes no log record; a bare line on stderr is allowed. A signal during the send is the stop path: the handler records that the deadline has passed, which the main thread notices within 100 ms (the wait on the worker), and the result is the one of the gate at that moment, as at the deadline. Later signals are ignored while the result is reported. The documented worst case is the `timeout` plus 3 s: up to 100 ms to notice, the bounded print and the log step with its one-second lock poll ([Log](#log)). A caller that kills the tool must wait at least `timeout` plus 10 s.

`connect_timeout` (default 3s, 1s to 30s) limits only the connect phase and never exceeds the time that remains; its expiry is `network_error` with `details.timeout: true`, so an unreachable host does not hold a caller for the whole `timeout`.

**Retries.** 429 is retried up to twice, after 2 s and then 4 s; the Retry-After header is never read. A failure while the gate is idle (name resolution, connection refused or timed out, a TLS handshake failure that is not a certificate verification failure) is retried once after 2 s; this includes the connection of a 429 retry, because a fully read 429 returned the gate to idle. The two counters are independent: at most two 429 retries and at most one connection retry per send, all inside the deadline. A wait longer than the time left in the deadline ends the send at once with the code of the last result (`rate_limited` with `retry_after_s` set to that wait, or `network_error`). Nothing else is retried: a 5xx is `upstream_error` with `unknown_outcome` true, and any failure once the gate is writing and no complete HTTP response arrived is `outcome_unknown`. Any 2xx other than the success form, including a 200 whose body is not the success form, is `wrong_host_response` with `unknown_outcome` true; any other status that is not listed is `wrong_host_response` with `unknown_outcome` false.

The log outcome is `outcome_unknown` whenever the envelope's `unknown_outcome` is true (exit 12, and exit 1 as described under [Log](#log)), and `failed` for any other exit 12.

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
| Connection refused, DNS or TLS handshake failure, or connect timeout while the gate is idle | Retried once as above; then exit 12 `network_error`. A certificate verification failure is `network_error` with `details.tls: true` and a message that names `ca_file`. |
| Timeout or connection loss once the gate is writing | Exit 12 `outcome_unknown`. |
| An answer once the gate is writing that is not HTTP | Exit 12 `wrong_host_response` with `unknown_outcome` true. |

**Probe.** `--probe` runs `GET /api/` with the same client, deadline, status mapping and retries as `send`. A 200 whose body is a JSON object is `probe.api_ok: true`; every other result fails the check with exit 12 and a message that names the code: 401 and 403 `auth_required`, 404 and 405 `wrong_host_response` (the message names `base_url`), 5xx `upstream_error`, a 200 that is not a JSON object `wrong_host_response`, failures as for send. A probe delivers nothing, so it reports no `unknown_outcome`, is not logged, and prints the `insecure_http` warning like any request.

The API answers success whether or not the push reached a phone and offers no way to learn that it did not. Output says `sent`, never `delivered`.

## Output

Global flags may appear before or after the subcommand. Flags are exact: abbreviations of long options are not accepted, and `--flag=value` is the same flag as `--flag value` (a value that starts with `-` must use the `=` form). stdout and stderr are written as UTF-8 bytes with errors replaced, never through the locale. A failure to write to stdout or stderr at any point (`BrokenPipeError`, any `OSError` or any other `Exception`) is ignored and the process ends with the exit code of the result after one flush attempt of each stream.

The tool looks for `--json` in argv before it parses anything, so a usage error with `--json` prints the envelope (code `usage`) on stdout; `--help` and `--version` are exempt. Any `--json` or `--json=...` token in argv selects the envelope, even though `--json=...` is itself a usage error. Errors always print one line on stderr; with `--json` they also print the error envelope on stdout. The envelope is written and flushed on stdout before the stderr line. With `--json` a successful send prints one object on stdout; without it human text goes to stderr and stdout is empty (a dry run prints the rendered text on stderr). A disabled tool prints `{"outcome":"disabled"}` on stdout with `--json` and one line on stderr without it, and exits 22 either way. stderr is advisory (warnings, verbose lines); the contract is the exit code plus the stdout JSON.

Without `--json` the human lines on stderr are fixed: `sent (<level>, <duration_ms> ms)` for a send, the rendered text for a dry run, `disabled in config`, and `<code>: <message>` for an error (`refused (<reason>): <message>` for exit 20). They contain no title, message, link, dedupe key or other input-derived text. `--quiet` suppresses every stderr line except errors and warnings; `--verbose` adds one line per phase (input, render, send, log) with the elapsed milliseconds and never a request line, header, URL, host, body or credential.

With `--json`, `send` prints one object ([schemas/cli/send.json](../schemas/cli/send.json)): `{outcome, tool, level, truncated, bytes, duration_ms, http_status, tag_set, dedupe_key, warnings, rendered}`. `outcome` is `sent`, `dry_run` or `disabled`; `bytes` is the UTF-8 size of the request body; `dedupe_key` echoes the caller's own `--dedupe-key` (or null); `http_status` is null for a dry run; `warnings` is an array of fixed strings, `[]` when none (the only value in 0.x is `insecure_http`); `rendered` is present only for a dry run. `allow_insecure_http: true` prints one stderr line on every request (a real `send`, `validate --probe` and `validate --test-message`; not a dry run, and not `validate` without a request) and adds `insecure_http` to `warnings` of the `send` output; `validate` output has no `warnings`. Disabled output is `{"outcome": "disabled"}` and nothing else.

## Exit codes

Codes 0 to 21 follow design guide section 4.2. Exit 0: sent or a dry run. Exit 1: internal error. Exit 2: usage or invalid configuration (codes `usage`, `config_invalid`). Exit 12: failed for a reportable reason (the codes of the tool, below). Exit 20: refused before sending because of the payload; code `refused` with a required reason. Exit 22: nothing sent because the tool is disabled in config (not an error; output `{"outcome":"disabled"}`). Exits 10, 11, 13 and 21 are never used: the tool stores no objects, has no hooks and never prompts. A caller treats exit 22 as a successful no-op. Exit 128+N (129 SIGHUP, 130 SIGINT, 143 SIGTERM) means that the tool received that signal before the send started: nothing was sent, there is no envelope and no log record.

The error envelope is `{"error": {"code", "message", "reason", "details", "retryable", "retry_after_s", "unknown_outcome"}}`; only `code` and `message` are required and the other keys are present with null when they do not apply. `message` is a fixed string of the tool, never a response body, header, exception text or input value. `reason` is set only on exit 20. `retry_after_s` is set only for `rate_limited` (the wait that was last performed, or the wait that did not fit the deadline; it is the tool's own backoff, not a server hint). `retryable` means that sending the same notification again is safe. `unknown_outcome` means that the notification may already have been delivered. They are set as follows.

- Exit 2 and exit 20: `retryable` null, `unknown_outcome` null.
- Exit 1: `retryable` false; `unknown_outcome` true when the failure happened after the gate reached `writing`, else false. The envelope on exit 1 is best effort: exit 1 with no envelope means the outcome is unknown. Any unexpected `Exception`, also one raised while parsing, is exit 1 `internal` with the fixed message `internal error`: neither the class nor the text of the exception is printed. `BaseException` that is not an `Exception` (`SystemExit`, `KeyboardInterrupt`) is not caught by this rule; it belongs to the signal handling of the Deadline paragraph.
- Exit 12: both are booleans, set per code. Not sent and permanent (false, false): `host_rejected`, `auth_required`, `credential_invalid`, and `wrong_host_response` for a status that is not 2xx. Not sent and worth retrying (true, false): `rate_limited`, `unavailable` (`details.phase` `input`), `network_error` (false, false when `details.tls` is true). Possibly delivered (R, true): `outcome_unknown` and `upstream_error`, where R is true exactly when a tag was sent (a retry replaces the earlier notification, so it is safe only while no newer notification with the same key has been sent; a late first request can still replace a newer notification with the same tag, which is accepted and documented). Possibly delivered (false, true): `wrong_host_response` after a 2xx, always, because the answer shows that the endpoint is not Home Assistant's notify API and a retry would not help.

`details` by code or reason, null when none applies: `config_invalid`: `key` (a config key name matching `[A-Za-z0-9_]{1,64}`, else `"?"`; `"--config"` for a missing `--config` file; `"home"` when the home directory lookup failed; or the file path for a file that cannot be read or parsed); reason `invalid_payload`: `pointer`; reason `link_invalid` from `link_hosts`: `pointer` `"/link"`; `credential_invalid`: `env`; `unavailable`: `phase` (always `input`); every code that came from a response (`auth_required`, `host_rejected`, `rate_limited`, `upstream_error`, `wrong_host_response`): `http_status`, and `host_rejected` also `hint`; `network_error`: `tls`, `timeout`. A message never contains an input value or a credential, and no stderr line contains input-derived text.

| Exit | Meaning | Codes (reasons for exit 20) |
|---|---|---|
| 0 | Accepted by Home Assistant (`sent`) or a dry run. | |
| 1 | Internal error. | Code: `internal` |
| 2 | Usage or invalid configuration. | Codes: `usage`, `config_invalid` |
| 12 | Failed for a reportable reason. | Codes: `host_rejected`, `auth_required`, `credential_invalid`, `rate_limited`, `upstream_error`, `network_error`, `outcome_unknown`, `wrong_host_response`, `unavailable` |
| 20 | Refused before sending because of the payload: `code` is `refused` and `reason` is required. | Reasons (not codes): `invalid_payload`, `empty_message`, `command_keyword`, `link_invalid`, `link_scheme` |
| 22 | Nothing sent: the tool is disabled in config. | Outcome `disabled` (not an error; output `{"outcome": "disabled"}`) |
| 128+N | A signal arrived before the send started. | No envelope, no log record |

A router has one rule: 20 drop and surface, 12 read `retryable` and `unknown_outcome` (`unavailable` is retry later), 22 no-op.

### Error envelope

The envelope is defined by [Exit codes](#exit-codes) above ([schemas/cli/error.json](../schemas/cli/error.json)). In ha-notice `details.hint` is set only on a 400 (`host_rejected`), `details.phase` only on `unavailable` and `retry_after_s` only on `rate_limited`. The envelope has no `tag_set`: `retryable` carries it.

## Hooks

None in 0.x. ha-notice sends one notification and takes no policy decisions; gating and routing belong to the caller. A `post-send` hook that notifies on failure could call this tool again and loop, which is the other reason there are none. Adding hooks later is additive.

## Calling from automation

Canonical call: `ha-notice send --stdin-json --json --actor auto:<name> [--dedupe-key=<hex>]`, the payload on stdin, absent fields omitted (never null). A caller that has a key passes the `=` form with a hex digest of the key, never the raw id. Decide by exit code:

| Exit | Meaning | Caller action |
|---|---|---|
| 0 | sent | Record it. |
| 22 | disabled, a successful no-op | Nothing. A shell caller writes `rc=$?; [ "$rc" = 22 ] && rc=0`. |
| 20 | the payload was refused | Do not retry; surface once per reason. After `link_invalid` or `link_scheme` a caller may retry once without `link`, putting the URL in the message. |
| 12 (false, false) | not sent; it will fail again until a person changes the config or the credential | Do not retry; surface once per code and destination. |
| 12 (true, false) | not sent, worth retrying | Retry with the caller's own backoff and cap. What the tool did first depends on the code: `rate_limited` was retried inside the deadline after 2 s and 4 s as far as the deadline allowed (`retry_after_s` is the tool's own last wait, not a server hint); `network_error` was retried once after 2 s when the deadline allowed; `unavailable` (the input did not arrive in time) was not retried. |
| 12 `unavailable` | nothing was sent: the input did not arrive before the deadline (`details.phase` `input`) | Retry later, with the same cap. |
| 128+N | the tool received a signal before the send started | Nothing was sent and there is no envelope or log record; the sender of the signal knows. |
| 12 (false, true) | possibly delivered | Do not retry; record it as possibly sent. For `wrong_host_response` the flags say retry is false: a persistent 2xx with a bad body means `base_url` is not the notify API, so a person fixes the config. |
| 12 (true, true) | possibly delivered, and a retry replaces the earlier notification | Retry with a cap, only while no newer notification with the same key has been sent. |
| 2, 1 | a usage or config fault, or an internal error | Do not retry; surface as a fault of the deployment. Exit 1 with no envelope: the outcome is unknown. |

The caller must prevent what refuses a payload: cut title and message to at most 100000 characters, always supply a non-empty message (copy the title into it if needed), use one of the four levels, and percent-encode links and give hosts as punycode. The documented worst case is `timeout` plus 3 s, so the caller's own kill timeout must be no earlier than `timeout` plus 10 s; a caller that kills the tool earlier gets no envelope and treats the outcome as unknown. SIGTERM is preferred: before the send it exits 128+N, during the send the tool treats it as the deadline. The tool may exit without reading all of stdin, so a caller ignores EPIPE and SIGPIPE on the stdin write and decides by the exit code alone. The tool keeps no send lock and tolerates parallel calls; a parallel call may skip its log record when the log lock stays busy for 1 s. To send to several destinations use one config file per destination with `--config`. `--config` and `--file` choose which files the tool reads and, through the config, the host that receives the token; no rule on the command text can make that safe, because the environment of the process is trusted, so an agent that must not choose a destination does not call the tool: it calls the caller's router. The log depends on a usable state directory; a state problem only warns on stderr and skips the log record. A doctor runs `ha-notice validate --json [--config <path>]`, reads `enabled`, and treats a failed `credential` check of a tool with `enabled` false as information. ha-notice refuses a message that is only a companion-app command word ([Command messages](#command-messages)); a legitimate message that equals a keyword or is one token starting `command_` or `kiosk_` is refused with `command_keyword` (exit 20 never means that anything was sent), so on `command_keyword` a router retries once with the text prefixed by its source and a colon (a message with a second word is never a command), and a template author makes every message a sentence. A router that must have an `error` or `action` survive an unknown outcome passes `--dedupe-key`, because a key makes `outcome_unknown` and `upstream_error` retryable.

## Config

Config is read from `.config/ha-notice/config.yaml` under the user's home directory from the password database (`pwd.getpwuid(os.getuid()).pw_dir`); neither `HOME` nor `XDG_CONFIG_HOME` is read. If the lookup fails (for example a uid with no entry), or the home it returns is empty, relative or not an existing directory, the tool exits 2 `config_invalid` (`details.key` `home`) before reading or sending anything, even with `--config`; the user name in the default actor falls back to `unknown`. There is no `HOME` or XDG fallback. `--config <path>` reads that file instead. Drop-ins are `config.d/*.yaml` in the directory that holds the config file, in lexical order; maps merge. A missing default config file means defaults; a missing file named by `--config` exits 2 `config_invalid` with `details.key` `"--config"`. Files must be at most 65536 bytes and regular files (symlinks are followed; the opened descriptor is checked), and are opened with `O_NONBLOCK` and parsed with PyYAML `safe_load` through a loader subclass that rejects duplicate keys and restricts the implicit resolvers: the only booleans are `true` and `false`, and the only numbers are decimal integers (and, for a duration key, a decimal float such as `1.5`), so `no`, `off`, `yes`, `010`, `1:30`, `0x10`, `1_0`, `1e3`, `.inf` and `.nan` stay strings and fail the type check or the duration grammar; the top level must be a mapping. A file that cannot be read, is not a regular file, or cannot be parsed (any YAML parser error, a duplicate key, `RecursionError` or `MemoryError` while loading) exits 2 `config_invalid` with `details.key` set to the file path and a fixed message: the YAML error text (it quotes the file), any snippet and every value are never printed. Merging and validation look only at known keys: an unknown key is refused before its value is examined. Booleans are only the YAML booleans `true` and `false`; a boolean is never accepted for a number, and a number must be finite. There are no environment overrides and no per-repo override: precedence is flags, then config, then defaults, and the environment variable that holds a credential is named by the config key shown in the table; it is the only variable the tool reads for a secret. Validation messages are built from the key and the rule only (Pydantic's input value is never used).

Durations (`timeout` and others) are a number of seconds, or a string matching `[0-9]+(\.[0-9]+)?(ms|s|m)?` (no unit means seconds); each key has its own default and range, and no key constrains another. The tool enforces the range of each key at load with a check that is false for NaN (`lo <= x <= hi`). Invalid config exits 2 `config_invalid`, `details.key` naming the key; a message names the key and the rule and never the value (for a name key that looks like a URL it says "must be a variable name").

Schema: [schemas/config.json](../schemas/config.json); example: [config.example.yaml](../config.example.yaml). The schema patterns end with `(?![\s\S])` because a JSON Schema `$` accepts a trailing LF; the tool uses a full match (`re.fullmatch`) for every pattern. `base_url` and `service` have no default, so nothing is sent until they are set.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` makes `send` exit 22 without reading input or the credential (after the syntax of the config is checked). |
| `base_url` | none (required for a send) | Home Assistant base URL, `https://host[:port][/prefix]` ([Home Assistant edge](#home-assistant-edge)). A dry run does not need it. |
| `service` | none (required for a send) | The `notify` service name, the part after `notify.` (for example a `mobile_app_` service). A dry run does not need it. |
| `token_env` | `HA_TOKEN` | Name of the environment variable holding a long-lived access token; matches `HA_[A-Z0-9_]{1,60}` as a whole, so a config cannot name another secret. |
| `allow_insecure_http` | `false` | Allow an `http://` base URL (the token then travels in cleartext). |
| `ca_file` | unset | Extra CA bundle, an absolute path; the way to trust a self-signed server. There is no key that turns verification off. |
| `link_hosts` | unset | List of 1 to 32 host names in lowercase, each of at least two labels `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?` joined by single dots, no leading or trailing dot, at most 253 characters; an entry that does not match is `config_invalid` (`details.key: link_hosts`). See the link rule. |
| `level_prefix` | `{info: "", warn: "WARN:", action: "ACTION:", error: "ERROR:"}` | Title prefixes, at most 16 characters each; run through the title rule (sanitizer steps 1 to 5) and must come out unchanged, else `config_invalid`. |
| `default_group` | unset | `data.group` for every notification; `[A-Za-z0-9_-]{1,64}` as a whole. |
| `max_chars` | `1000` | Message limit in code points, 100 to 2000. |
| `timeout` | `10s` | The one deadline of a `send` ([Deadline](#home-assistant-edge)), 1s to 120s. |
| `connect_timeout` | `3s` | Limit for the connect phase, 1s to 30s; never longer than the time that remains in the deadline. |
| `log` | `true` | `false` writes no `log.jsonl`. |

## Environment variables

- The variable named by `token_env` holds the credential. Under cron or any hook it must be in the calling process's environment; the docs recommend a mode-0600 env file sourced by the cron line. A token stored under another name is aliased to `HA_TOKEN` in that env file. ha-notice never reads shell startup files or secret files itself.
- No other variable is read: `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are not read (the config and the state directory are found from the password database), and there are no `HA_NOTICE_*` overrides.

## Log

The state directory is `.local/state/ha-notice` under the home directory from the password database; `XDG_STATE_HOME` is not read. It is created with mode 0700, opened with `O_DIRECTORY` and `O_NOFOLLOW`, and checked on that descriptor to be owned by the user with no group or other permissions. Every file below it is opened relative to that descriptor (`dir_fd`) with `O_NOFOLLOW`, `O_NONBLOCK` and `O_CLOEXEC` (the log also with `O_APPEND` and mode 0600) and must be a regular file on `fstat`; a FIFO, a symlink or a device makes the state unusable instead of blocking the tool. It is used only when it is needed (a log record). If it cannot be used the tool warns once on stderr, writes no log record, and the exit code is unchanged: a state problem never blocks or fails a send.

`log.jsonl` holds one record per outcome that reaches step 3 or later. An exit 1 after the gate reached `writing` (the request may have been sent; the envelope's `unknown_outcome` is true) is logged, best effort within the log bound, as outcome `outcome_unknown` with code `internal`. Not logged: any other exit 1 (before the request was started), exit 2, exit 22, a signal exit 128+N and dry runs. The result is printed and flushed before the log step. A write takes an exclusive flock on `log.lock`, polled without blocking every 20 ms for at most 1 s (if the lock is not obtained, the record is skipped with the same warning), rotates when the file is 1 MiB or more (`log.jsonl.2` to `.3`, `.1` to `.2`, `log.jsonl` to `.1`), reopens `log.jsonl` after a rotation, and appends the record with one write of less than 1 KiB. The log step is outside the deadline, is bounded as stated, and a log write failure (including a full disk or a timeout) warns on stderr and never changes the exit code. config `log` false writes nothing.

`outcome` is `sent` (exit 0), `refused` (exit 20), `outcome_unknown` (exit 12 whenever the envelope's `unknown_outcome` is true, and exit 1 with `unknown_outcome` true) or `failed` (any other exit 12). `code` is `refused` for exit 20, the error code for exit 12 (`unavailable` included), `internal` for the logged exit 1 and null on success; `reason` is the refusal reason for exit 20 and null otherwise. `actor_source` is `flag`, `tty` or `default`. `duration_ms` (integer, never null) is the time from the start of step 3 to the moment the result was fixed (just before it is printed). Nullable and always present: `level` (null when no valid level was read), `bytes`, `truncated` and `message_sha256` and `dedupe_key_sha256` (null for a refusal before rendering, or when not computed), `http_status` (null unless a response arrived). Records never contain a title, message, link, URL, base URL, service, host or credential. There is no audit file: a notification changes nothing in a system of record. `ts` is UTC, `YYYY-MM-DDTHH:MM:SS.mmmZ`.

[schemas/log.json](../schemas/log.json). Fields: `{ts, tool, version, outcome, exit, code, reason, level, bytes, truncated, duration_ms, http_status, message_sha256, dedupe_key_sha256, tag_set, actor, actor_source}`. `tag_set` is a nullable boolean (null when the request was not built). The log's `message_sha256` and `dedupe_key_sha256` follow the hashing rules under [`send`](#send).

## Files

| Path | Content |
|---|---|
| `.config/ha-notice/config.yaml`, `config.d/*.yaml` under the home directory | Config. |
| `<state directory>/log.jsonl` (and `.1` to `.3`) | Log records. |
| `<state directory>/log.lock` | Lock held while a log record is written and rotated. |

The state directory follows the state rules under [Log](#log) above. There is no database and no migration.

## Labels

ha-notice creates no long-lived objects and takes no labels.

## TUI

None in v1.

## Residual risks

- **No delivery confirmation.** Success is returned whether or not the push is delivered, and the message may still be cut or dropped on the phone. The display limit is unknown (the API accepted 100000 characters); the defaults of 1000 characters and 2000 bytes are conservative until the phone check ([design.md](design.md), Live verification).
- **Templates were tested, not guaranteed.** Not rendering `{{ … }}` in REST-supplied text was observed on one Home Assistant version; a future version or a custom notify service could render it. The tool does not escape template syntax, so a caller who sends untrusted text to such a service takes that risk.
- **Android message markup.** The Android app may render a small HTML subset in the message (unverified, [design.md](design.md) V20); until checked, a producer may be able to style or mislabel text.
- **The command rule is a guess at the apps' matching, and over-broad.** A legitimate message that equals a keyword or starts `command_` or `kiosk_` is refused (the router prefixes the text). The rule assumes the apps match the whole message; a platform that also matches after other normalization could still treat other text as a command, and the companion apps may add commands.
- **The token is a long-lived credential.** A person who can edit the user's config can send the token anywhere (`base_url` comes from the config); the token is valid for the whole Home Assistant API, not only `notify`; use a token for a dedicated user where possible.
- **The environment is trusted.** Interpreter and loader variables (`PYTHONPATH`, `LD_PRELOAD`, `OPENSSL_CONF`) run code in the tool with the credential in reach; the tool does not read the variables that would redirect it (proxy, CA, key log, the config path) but a caller that can set the environment of the process is inside the trust boundary.
- **`--config` selects the destination.** It names the host that receives the token; no rule on the command text prevents it.
- **Cleartext and self-signed servers.** `allow_insecure_http` trades the token's safety for convenience; it is off by default and each real request with it set warns on stderr. A self-signed server is trusted through `ca_file`; no key turns verification off.
- **Taps open links.** `link` becomes the tap action and is limited to `http` and `https`; the apps accept more schemes (`app://`, intents, settings), and the host API does not reject them, which is why the tool does. With `link_hosts` unset a producer can aim the tap target at any web address; the push does not show the URL.
- **Lock-screen exposure.** Title and message appear on the phone's lock screen according to the phone's settings; callers must not send secrets.
- **Opaque errors.** Several different mistakes return the same 400, so diagnosis depends on `validate --test-message` and on checking `service`.
- **Tag replacement.** A producer who can guess a dedupe key can replace an unread notification with the same key; the router owns the key policy. Replacement by tag was observed on one phone only, and a late first request can replace a newer notification with the same tag; this is accepted and documented, and a router that cares puts the level or a sequence number in its key.
- **`level` is advisory.** The prefix does not authenticate the sender: a producer can write `ERROR:` in a title.
- **Same-user boundary.** A process that can write the user's config or `config.d` can redirect the tool; the state directory is checked but the config is trusted.
- **Short hashes.** `message_sha256` is a 64-bit unsalted hash; a short message can be confirmed against the log by a reader of the 0600 file.

## Platform notes

Linux and WSL are required. macOS is expected to work but is not a required platform.
