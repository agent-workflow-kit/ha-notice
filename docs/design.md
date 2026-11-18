# ha-notice: design

Status: 0.1.0-design, 2026-11-17. The rules are in [interface.md](interface.md), the single normative source; this document records decisions, modules and tests and links to interface headings without restating them. Architecture: `../awkit-docs/architecture.md` (v1.22).

## Role and layer

L1 primitive: send one notification through a Home Assistant `notify` service over the REST API (in practice a companion-app push to a phone). Works fully standalone. It is designed to be called by a routing tool without knowing that tool exists.

## Why the notifiers differ

ha-notice is one of three channel notifiers with the same contract (`slack-notice`, `wsl-notice`); the differences are deliberate. Timeout floors: Slack 3 s (spacing plus one retry), ha 1 s with a separate connect phase, WSL 5 s (cold start plus the interop retry). `max_chars` versus `max_title` and `max_body`: one text field versus a separate title line. Cut markers and default prefixes differ because each destination renders text differently. `link_hosts` exists only where the URL is hidden from the reader (the push and the toast), not in Slack, which shows bare URLs. A send lock exists only where Slack throttles. A tag-conditional retry exists only here, because a tag makes a repeat replace the earlier notification. The deadline uses a worker thread where HTTP name resolution cannot be interrupted, and a single thread where the only blocking calls are on pipes.

## Uses

| Dependency | Layer | Binding | Notes |
|---|---|---|---|
| Home Assistant REST API over HTTP(S) | L0 third party | none (not an edge of the tool graph) | One POST per notification; one read-only `GET /api/` for `validate --probe`; see [Home Assistant edge](interface.md#home-assistant-edge). |
| Python standard library `http.client` and `ssl` | L0 | none | No third-party HTTP dependency, no `urllib`. All HTTP is in `gateway.py`: `http.client` connections built from the validated host and port, no proxy, no redirects, one TLS context of our own (the default context honours `SSL_CERT_FILE`, which is why it is not used). Timeouts of `http.client` are per operation (measured: a server trickling one byte per 0.4 s held a send for 31.6 s against a 1 s socket timeout), so the deadline is a daemon worker thread, a three-state gate and `os._exit` rather than `SIGALRM` or a single thread; every request sends `Accept-Encoding: identity`. |
| Pydantic (config validation) | library | none | Required by the design guide for config. Errors are converted to messages from `loc` and `type` only, because the default message contains the input value. Added in stage 1 (config). |
| PyYAML (config parser) | library | none | The design guide mandates YAML config; `yaml.safe_load` with a loader subclass that rejects duplicate keys and restricts the implicit resolvers (`no`, `off`, `010`, `1:30`, `0x10` stay strings), files opened with `O_NONBLOCK` and capped at 64 KiB, YAML errors never printed. Added in stage 1 with Pydantic. |
| `jsonschema` (development only) | test library | none | Validates the samples, the example config and golden outputs against `schemas/` (draft 2020-12, local cross-file `$ref`s) in `tests/harness.py`. Never imported by `src/`, so the installed tool has no runtime dependency on it. PyYAML is also a development dependency from this stage (it reads `config.example.yaml` in the schema test) and becomes a runtime dependency in stage 1 (row above); `types-pyyaml` is its type stubs. `referencing` (development only, already a dependency of `jsonschema`) is declared directly because `tests/harness.py` imports it to resolve the cross-file `$ref`s from the local schema files. CI's `schemas` job separately runs `check-jsonschema`, which uses the same library. |

No tool dependencies: ha-notice composes nothing.

## Decisions

| ID | Decision | Rationale |
|---|---|---|
| D-1 | Stateless: no state database, no outbox, no retries after exit; one `log.jsonl`. See [Files](interface.md#files), [Log](interface.md#log). | Deduplication, quiet hours, history and deferral belong to the routing tool (maintainer decision, 2026-11-17). |
| D-2 | Common input contract: `title`, `message`, `level`, `link`; unknown fields refused; text from stdin, a file or flags, all sanitized alike; one input-reading rule (1 MiB cap, regular files, hardened JSON parse). See [Notification](interface.md#notification). | Architecture 13.2 rule 2; short argv text is untrusted (maintainer decision, 2026-11-17). The cap is 1 MiB because 100000 characters take at most 4 bytes each plus JSON escapes. |
| D-3 | `data` is built from an allowlist of `url`, `clickAction`, `tag` and `group`, in that order, never from caller input beyond `link` and the dedupe key. Per-level `data` keys (`importance`, `channel`, `ttl`, `priority`, `push`), a tag switch are not in 0.x, and no switch turns certificate checks off. See [Rendering](interface.md#rendering). | The API accepts any `data` unchecked, including `app://` and `javascript:` URLs (spike B). The per-level keys are unverified on a phone and `critical` changes how a phone treats a message; they can return additively after a live test. |
| D-4 | Refuse a whole message that is a command word: after NFKC and case folding, `tts` or `(command\|kiosk\|update\|clear\|remove\|request)_[a-z0-9_]*`; a message with a space or second line is not refused. See [Command messages](interface.md#command-messages). | The phone matches the whole message. Evidence: the companion-app documentation for the families; `tts` is from memory, unverified. Consequence for callers: a single-token message can be refused, so producers send sentences ([Calling from automation](interface.md#calling-from-automation)). |
| D-5 | `link` is printable ASCII matched by one regex over RFC 3986 characters (callers percent-encode everything else), with no URL parser anywhere; the scheme is lowercased when rendered, and the link becomes both `url` and `clickAction`; optional `link_hosts` (unset by default; entries of at least two labels) restricts its host. | Taps follow the link; printable ASCII removes bidi, zero-width and homograph display issues in one rule; other schemes open apps and intents. |
| D-6 | The dedupe key becomes `data.tag` (`awkit-` plus 24 hex of the key's SHA-256; the level is not part of it), so a retry or a later notification with the same key replaces the earlier one. | Observed on one phone: a second notification with the same tag replaced the first. A late first request can replace a newer notification with the same tag: accepted and documented; a router that cares puts the level or a sequence number in its key. |
| D-7 | Template syntax is not escaped. | Verified on a phone: `{{ 1+1 }}` and `{% if %}` appeared literally in title and message. Residual risk recorded. |
| D-8 | `base_url` and `service` have no default; the URL is built from parsed parts under an explicit grammar; `https` unless `allow_insecure_http`; certificate checks are always on (a self-signed server uses `ca_file`). See [Config](interface.md#config). | A double or trailing slash is a 404; a wrong default could send a token to a wrong host. |
| D-9 | The token only from the variable named by `token_env`, restricted to `HA_[A-Z0-9_]{1,60}` (full match), only in the `Authorization` header and only to `base_url`'s host. No `HA_NOTICE_*` environment overrides. See [Home Assistant edge](interface.md#home-assistant-edge). | Design guide section 7. An environment variable that selects the destination or the secret is an attack path; the restricted name stops a config from naming another secret. |
| D-10 | Exit codes as in [Exit codes](interface.md#exit-codes). Exit 20 means only that the payload was refused; environment faults (no usable credential) are exit 12 `credential_invalid`, so a router has one rule: 20 drop, 12 read the flags (`unavailable`, a deadline during input, is retry later), 22 no-op. No 5xx retry; 429 and connect-phase failures are retried; `outcome_unknown` and `upstream_error` are `(R, true)` with R true only when a tag was sent (a retry replaces the earlier notification, so it is safe only while no newer notification with the same key has been sent: the order effect); `wrong_host_response` after a 2xx is never retryable because the endpoint is not the notify API; a status outside 100..599, or a non-final 1xx (100..199), is treated like a non-HTTP answer (`wrong_host_response`, `unknown_outcome` true, `details` null); an exception that is neither `OSError` nor `HTTPException` while idle is a bug (exit 1 `internal`, never retried). | A duplicate is worse than a lost message: a 5xx can follow processing and the host has no idempotency, but a tagged retry replaces the earlier notification (maintainer decision, 2026-11-17). |
| D-11 | `validate` never prompts and has no `--yes`; `--probe` is one `GET /api/`; sending a test needs `--test-message`. Plain `validate` ignores `enabled` except to report it; `--probe` and `--test-message` on a disabled tool make no call and exit 22. There is no `GET /api/services` call. Exit 22 means the requested action was not performed; plain `validate` is a doctor call that must still report faults of a disabled tool. | The services list is the whole catalogue (larger than the response cap) and its shape was never exercised; a wrong service is diagnosed by `--test-message`. |
| D-12 | No hooks in 0.x and no audit file; `config_invalid` is exit 2. See [Hooks](interface.md#hooks), [Log](interface.md#log). | The tool takes no policy decisions and keeps no audit trail. |
| D-13 | One monotonic deadline from the start of input reading. Input is read by the main thread in 100 ms slices (a worker would lose the race rule; the slice is the cost). The network phase runs in a daemon worker thread behind a three-state gate (idle, writing, abandoned) that alone classifies the phase: every attempt takes idle to writing atomically and refuses when abandoned, a fully read 429 returns the gate to idle, and a complete response in the result slot wins over the deadline. The process ends with `os._exit`; `connect_timeout` bounds only the connect phase. Name resolution cannot be interrupted, so it lives in the worker. See [Home Assistant edge](interface.md#home-assistant-edge). | Per-operation socket timeouts let a trickling server hold a send far past `timeout` (31.6 s measured); the gate closes the race in which the main thread reports a not-sent failure while the worker writes. A deadline that passes during input is exit 12 `unavailable` (`details.phase` `input`, nothing sent); a signal before the send starts exits 128+N with no envelope and no log record. |
| D-14 | A state-directory problem never fails a send: one stderr warning, no log record. The log is the only state. Every state file is opened with `O_NOFOLLOW`, `O_NONBLOCK` and a regular-file check, and the log lock is polled for at most 1 s, so a hostile path cannot block the tool. The result is printed and flushed before the log step, so the documented worst case is `timeout` plus 3 s and a caller kills no earlier than `timeout` plus 10 s. An exit 1 after the gate reached `writing` is logged as `outcome_unknown` (code `internal`). See [Log](interface.md#log). | A notifier that fails because its log cannot be written loses the alert it exists to carry. |
| D-15 | Sanitizer by Unicode category plus an explicit list, one table in the interface: Cc (except LF), Co and Cn are removed, and of Cf and the default-ignorable set only the listed characters (zero-width space, direction marks and embeddings, word joiner range, byte order mark, tag block, fillers, Braille blank, Mongolian selectors, soft hyphen). A lone surrogate is refused (exit 20 `invalid_payload`), not removed. Variation selectors U+FE00 to U+FE0F, ZWNJ, ZWJ and the Arabic number signs are kept, because real scripts need them. Cn membership follows the running Python's Unicode version, so the golden test pins a fixed list of code points; combining joiners (Mn) are handled by the emptiness rule, which treats a text of only whitespace and Mn, Mc and Me characters as empty. See [Sanitizer](interface.md#sanitizer). | Narrow removal keeps Persian, Indic, Arabic and emoji text intact; the few visible characters that are removed (U+2800, the Mongolian selectors, tag-block flags) are named in the interface. |
| D-16 | Hashes and request bodies use one JSON serialization (`ensure_ascii=False`, compact separators, UTF-8) and one hash input, so a golden test is possible. | See [`send`](interface.md#send). |
| D-17 | No configuration is selected by the environment: the config and the state directory are found from the password-database home; `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are not read. If the password-database lookup fails, or returns an empty, relative or missing directory, the tool exits 2 `config_invalid` (`details.key` `home`); there is no fallback. Tests use `--config` and a fake gateway `home_dir()` and `uid()`. See [Config](interface.md#config). | Same reason as the removed `HA_NOTICE_*` overrides: a variable that chooses the config chooses the host that receives the token. Deviation from the design guide's "respect XDG" is recorded as a carry-forward in the guide. |

## Resolved open topics

- Payload shape: [Notification](interface.md#notification).
- Channel config: [Config](interface.md#config); the user's existing hook script that hardcodes the token is replaced by `token_env` in the user's own config.
- Escaping: none needed for the host (templates are not rendered); control, invisible and noncharacter code points are removed ([Sanitizer](interface.md#sanitizer)).

## Live verification

Verified in design (private spike, 2026-11-17; the user's own phone service, marked test notifications):

| Behavior | Result |
|---|---|
| Success | 200 with a JSON list (`[]`). |
| Errors | No token 401; unknown service, missing message, unknown field and invalid JSON 400 with opaque bodies; GET 405; trailing or double slash 404; no error echoed the token or input. |
| Content type | `text/plain` with valid JSON accepted. |
| `data` | Accepted unchecked: `url`, `clickAction`, `tag`, `group`, `channel`, `importance`, `ttl`, `priority`, `actions`; `app://` and `javascript:` URLs accepted. |
| Templates | Not rendered (confirmed on the phone). |
| Tag | Replaces an earlier notification (confirmed on the phone). |
| Length | 1000, 10000 and 100000 characters accepted by the API. |
| Timing | About 0.1 to 0.15 s per call. |

Still to verify (live tests in the plan; the interface states a conservative default for each):

- V7: `GET /api/` with a long-lived token (the documentation says `{"message": "API running."}`, never run live; any 200 JSON object counts as ok).
- V8: the phone's display limit for long text (FCM payload size about 4 KB from documentation, not tested; the defaults are 1000 characters and 2000 bytes; the user looks at the phone for the 1000, 10000 and 100000 character notifications of spike B).
- V9: whether both `url` (iOS) and `clickAction` (Android) are needed for a tap link (documentation only; both are sent).
- V10: the command keywords and prefix families, and `tts` (documentation; `tts` from memory).
- The 401 body for a wrong (not missing) token; an unreachable host's timeout (the test hit an instant refusal only); a self-signed certificate through `ca_file`; a base URL with a path prefix; whether other notify services (not companion apps) accept the same body.
- The compiled default CA paths of a uv-managed Python on the user's machine (V18; the default is that a path is usable by loading, not by existence, and the fixed fallback list covers the rest).
- V20: the Android companion app may render a small HTML subset (`<b>`, `<a href>`) in `message` (documentation from memory, unverified). If so a producer could show text that names one site while the link target is another, which defeats `link_hosts`. Default: not escaped. Live check: one notification with `<b>x</b>` and `<a href="https://example.org">y</a>` in `message`, a person looks at the phone. An escaping option is not added until the behaviour is seen.

Later (additive, after a live phone test): whether `importance`, `channel`, `ttl`, `priority` and `push.interruption-level` take effect from a REST call, as optional per-level `data` keys.

## Modules

| Module | Responsibility |
|---|---|
| `cli.py` | Argument parsing, command dispatch, catching unexpected exceptions as exit 1. |
| `output.py` | The output sink (UTF-8, failures ignored, stdout before stderr), the exit-code table, the error envelope and the human lines. |
| `config.py` | Config loading from the password-database home, drop-ins, strict YAML parse, Pydantic validation (no environment overrides, no environment-selected path). |
| `payload.py` | Input reading and hardened JSON parse, notification validation, sanitizer, command-keyword check. |
| `link.py` | The link rule (syntax, scheme, port, IPv6 literal); no URL parser. |
| `render.py` | Request body: title, message, `data` allowlist, truncation. |
| `send.py` | The `send` pipeline: config, disabled check, input, validation, render, dry-run output; hands the rendered request to the delivery step. |
| `hass.py` | URL building, request building, one attempt, the probe call. |
| `retry.py` | The retry loop: 429 and connect-phase retries, waits, attempt facts; the gate seam for the deadline. |
| `deadline.py` | The whole-send deadline: the three-state `WritingGate` (one lock, never held across a socket call, with the result slot), the daemon worker thread that runs the retry loop, the main-thread wait and the decision at the deadline, and `finish` (`exit_process` when the worker may still run). |
| `response.py` | Pure mapping of one answer or exception (with the gate state) to a success or an error spec; no I/O. |
| `state.py` | Opens the state directory through the gateway (home from the password database, mode 0700, no symlink, owner check) and the files below it; any problem is one `StateUnusable` and the fixed warning, printed once. |
| `log.py` | Log record writing, bounded lock, rotation and reopen. |
| `gateway.py` | The only place that opens network connections, clocks, name resolution, `home_dir()` and `uid()`, `read_source(fd_or_path, max_bytes, remaining)` (bytes, or a timed-out result that `cli` maps to exit 12 `unavailable` with `details.phase` `input`, as [Input](interface.md#notification) says), state-directory access and the worker-thread deadline; `http.client` with an own TLS context (no proxy, no redirects, `SSL_CERT_FILE` ignored); tests substitute fakes. The gateway bounds only each connect (one deadline over resolution, every address and TLS) and each socket operation; `http.client` has no overall bound (a server may send `100 Continue` responses without end), so the deadline of the whole send is enforced by the caller's worker thread and `os._exit`, never by the gateway. The surface is the `Gateway` protocol in `gateway.py` (clocks, `resolve`, `home_dir`, `uid`, `login_name`, `isatty`, `read_source`, the state-directory calls, `ca_candidates`, `new_tls_context(ca_files, ca_dirs, ca_pems)` (loads only what it is given; `hass.py` selects the trust and reads each CA file once), `has_entries`, `connect`, `exit_process`); `tests/fake_gateway.py` implements it and `tests/test_gateway_conformance.py` keeps the two faithful. |

## Data model, concurrency, errors

No stored objects. The log lock is the only file lock; the in-process gate lock (`deadline.py`) guards the gate state and the result slot in short sections and is never held across a socket call. Errors use the envelope in [Error envelope](interface.md#error-envelope); log failures never change an exit code.

## Test strategy

- Process tests call `cli.main(argv, env, gateway)` in-process with a fake gateway (name resolution, monotonic clock, home directory and uid, input reading, state-directory hooks, CA path candidates, the connection script); no test-only environment seam is allowed. A few real-socket tests stay: a local HTTPS server with a self-signed certificate and `ca_file`, and a plain-HTTP server with `allow_insecure_http`.
- All HTTP goes through `gateway.py`; a fake Home Assistant server returns each row of [Home Assistant edge](interface.md#home-assistant-edge), including slow responses, a stall in name resolution, a response that trickles byte by byte, a connection drop after the request and a redirect (a second server must see zero requests); a fake proxy and a fake CA in `SSL_CERT_FILE` must be ignored. The server is `tests/fake_ha.py`; its self-signed certificate is made at test time by the `openssl` binary in a test-only subprocess (private HOME, two-day lifetime; the tool itself never runs a subprocess and no dependency is added), and CI needs `openssl` on the path.
- The harness is `tests/harness.py` (schema loading and validation, `Golden` compare and update) with the `golden` fixture and `--update-golden` option in `tests/conftest.py`: goldens live in `tests/golden/{output,request,log}/`, are compared as exact text, and are rewritten (existing files only, atomically; new goldens are created by hand in the owning issue) only by `pytest --update-golden`, which is refused when `CI` is set. Schema samples are in `tests/samples/<schema>.json`; each negative sample names the location and the schema keyword where it must fail.
- Golden files for `--json` output, request bodies and the shared hash and serialization (levels, tags, links, truncation, the `data` allowlist), schema tests with positive and negative samples, a sanitizer table test, a link table test, a table test of command keywords and their near misses, and a test that the token appears in no argv, URL, output, log or error and is sent to no other host.
- `live` tests (never in CI) send marked notifications to the user's own service; the still-to-verify items become assertions when run.

## Residual risks pointer

The environment is trusted and `--config` selects the destination: see [Residual risks](interface.md#residual-risks).

## Platforms

Linux and WSL required; macOS expected (standard library only), untested.
