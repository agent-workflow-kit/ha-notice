# ha-notice: design

Status: 0.1.0-design, 2026-11-17. The rules are in [interface.md](interface.md), the single normative source; this document records decisions, modules and tests and links to interface headings without restating them. Architecture: `../awkit-docs/architecture.md` (v1.22).

## Role and layer

L1 primitive: send one notification through a Home Assistant `notify` service over the REST API (in practice a companion-app push to a phone). Works fully standalone. It is one of three sibling channel notifiers with the same contract (`slack-notice`, `wsl-notice`), each designed to be called by a routing tool above it without knowing that tool exists.

## Uses

| Dependency | Layer | Binding | Notes |
|---|---|---|---|
| Home Assistant REST API over HTTP(S) | L0 third party | none (not an edge of the tool graph) | One POST per notification; one read-only `GET /api/` for `validate --probe`; see [Home Assistant edge](interface.md#home-assistant-edge). |
| Python standard library `http.client` and `ssl` | L0 | none | No third-party HTTP dependency, no `urllib`. All HTTP is in `gateway.py`: `http.client` connections built from the validated host and port, no proxy, no redirects, one TLS context of our own (the default context honours `SSL_CERT_FILE`, which is why it is not used). Timeouts of `http.client` are per operation, so the deadline is a worker thread plus `os._exit` rather than `SIGALRM` (a signal handler does not run during name resolution). |
| Pydantic (config validation) | library | none | Required by the design guide for config. Errors are converted to messages from `loc` and `type` only, because the default message contains the input value. Added in stage 1 (config). |
| PyYAML (config parser) | library | none | The design guide mandates YAML config; `yaml.safe_load` only, files capped at 64 KiB. Added in stage 1 with Pydantic. |

No tool dependencies: ha-notice composes nothing.

## Decisions

| ID | Decision | Rationale |
|---|---|---|
| D-1 | Stateless: no state database, no outbox, no retries after exit; one `log.jsonl`. See [Files](interface.md#files), [Log](interface.md#log). | Deduplication, quiet hours, history and deferral belong to the routing tool (maintainer decision, 2026-11-17). |
| D-2 | Common input contract: `title`, `message`, `level`, `link`; unknown fields refused; text from stdin, a file or flags, all sanitized alike; one input-reading rule (1 MiB cap, regular files, hardened JSON parse). See [Notification](interface.md#notification). | Architecture 13.2 rule 2; short argv text is untrusted (maintainer decision, 2026-11-17). The cap is 1 MiB because 100000 characters take at most 4 bytes each plus JSON escapes. |
| D-3 | `data` is built from an allowlist of `url`, `clickAction`, `tag` and `group`, in that order, never from caller input beyond `link` and the dedupe key. Per-level `data` keys (`importance`, `channel`, `ttl`, `priority`, `push`), a tag switch and a `tls_verify` switch are not in 0.x. See [Rendering](interface.md#rendering). | The API accepts any `data` unchecked, including `app://` and `javascript:` URLs (spike B). The per-level keys are unverified on a phone and `critical` changes how a phone treats a message; they can return additively after a live test. |
| D-4 | Refuse a whole message that is a command word: after NFKC and case folding, `tts` or `(command\|kiosk\|update\|clear\|remove\|request)_[a-z0-9_]*`; a message with a space or second line is not refused. See [Command messages](interface.md#command-messages). | The phone matches the whole message. Evidence: the companion-app documentation for the families; `tts` is from memory, unverified. Consequence for callers: a single-token message can be refused, so producers send sentences ([Calling from automation](interface.md#calling-from-automation)). |
| D-5 | `link` is printable ASCII, one regex, case-insensitive scheme lowercased when rendered, and becomes both `url` and `clickAction`; optional `link_hosts` (unset by default) restricts its host. | Taps follow the link; printable ASCII removes bidi, zero-width and homograph display issues in one rule; other schemes open apps and intents. |
| D-6 | The dedupe key becomes `data.tag` (`awkit-` plus 24 hex of the key's SHA-256; the level is not part of it), so a retry or a later notification with the same key replaces the earlier one. | Verified on a phone: a second notification with the same tag replaced the first. A producer that must keep levels apart includes the level in its key. |
| D-7 | Template syntax is not escaped. | Verified on a phone: `{{ 1+1 }}` and `{% if %}` appeared literally in title and message. Residual risk recorded. |
| D-8 | `base_url` and `service` have no default; the URL is built from parsed parts under an explicit grammar; `https` unless `allow_insecure_http`; certificate checks are always on (a self-signed server uses `ca_file`). See [Config](interface.md#config). | A double or trailing slash is a 404; a wrong default could send a token to a wrong host. |
| D-9 | The token only from the variable named by `token_env`, restricted to `^HA_[A-Z0-9_]{1,60}$`, only in the `Authorization` header and only to `base_url`'s host. No `HA_NOTICE_*` environment overrides. See [Home Assistant edge](interface.md#home-assistant-edge). | Design guide section 7. An environment variable that selects the destination or the secret is an attack path; the restricted name stops a config from naming another secret. |
| D-10 | Exit codes as in [Exit codes](interface.md#exit-codes). Exit 20 means only that the payload was refused; environment faults (no usable credential) are exit 12 `credential_invalid`, so a router has one rule: 20 drop, 12 read the flags, 22 no-op. No 5xx retry; 429 and connect-phase failures are retried; `outcome_unknown` and `upstream_error` are `retryable` only when a tag was sent. | A duplicate is worse than a lost message: a 5xx can follow processing and the host has no idempotency, but a tagged retry replaces the earlier notification (maintainer decision, 2026-11-17). |
| D-11 | `validate` never prompts and has no `--yes`; `--probe` is one `GET /api/`; sending a test needs `--test-message`. There is no `GET /api/services` call. | The services list is the whole catalogue (larger than the response cap) and its shape was never exercised; a wrong service is diagnosed by `--test-message`. |
| D-12 | No hooks in 0.x and no audit file; `config_invalid` is exit 2. See [Hooks](interface.md#hooks), [Log](interface.md#log). | As in slack-notice. |
| D-13 | One wall-clock deadline from the start of input reading, enforced by a worker thread and `os._exit`, not `SIGALRM`; `connect_timeout` bounds the connect phase. See [Home Assistant edge](interface.md#home-assistant-edge). | Per-operation socket timeouts let a trickling server hold a send far past `timeout`. |
| D-14 | A state-directory problem never fails a send: one stderr warning, no log record. The log is the only state. See [Log](interface.md#log). | A notifier that fails because its log cannot be written loses the alert it exists to carry. |
| D-15 | Sanitizer by Unicode category plus a short filler list, not by hand-listed ranges; category Cn is not used. See [Sanitizer](interface.md#sanitizer). | Cn membership changes with the Unicode version of the running Python. Emoji joiners and variation selectors are removed, so some emoji sequences are shown as separate or text-style emoji. |
| D-16 | Hashes and request bodies use one JSON serialization (`ensure_ascii=False`, compact separators, UTF-8) and one hash input, so a golden test and a cross-tool correlation are possible. The cut markers and default prefixes differ across the notifiers on purpose. | See [`send`](interface.md#send). |

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
- The compiled default CA paths of a uv-managed Python on the user's machine (V18; the fixed fallback list is the conservative default).

Later (additive, after a live phone test): whether `importance`, `channel`, `ttl`, `priority` and `push.interruption-level` take effect from a REST call, as optional per-level `data` keys.

## Modules

| Module | Responsibility |
|---|---|
| `cli.py` | Argument parsing, command dispatch, exit-code mapping, output. |
| `config.py` | Config loading, drop-ins, YAML parse, Pydantic validation (no environment overrides). |
| `payload.py` | Input reading and hardened JSON parse, notification validation, sanitizer, link rule, command-keyword check. |
| `render.py` | Request body: title, message, `data` allowlist, truncation. |
| `hass.py` | URL building, request building, response mapping, 429 and connect retries, the deadline, the probe call. |
| `log.py` | Log record writing and rotation. |
| `gateway.py` | The only place that opens network connections, clocks and the worker-thread deadline; `http.client` with an own TLS context (no proxy, no redirects, `SSL_CERT_FILE` ignored); tests substitute fakes. |

## Data model, concurrency, errors

No stored objects. The log lock is the only lock. Errors use the envelope in [Error envelope](interface.md#error-envelope); log failures never change an exit code.

## Test strategy

- All HTTP goes through `gateway.py`; a fake Home Assistant server returns each row of [Home Assistant edge](interface.md#home-assistant-edge), including slow responses, a stall in name resolution, a response that trickles byte by byte, a connection drop after the request and a redirect (a second server must see zero requests); a fake proxy and a fake CA in `SSL_CERT_FILE` must be ignored.
- Golden files for `--json` output, request bodies and the shared hash and serialization (levels, tags, links, truncation, the `data` allowlist), schema tests with positive and negative samples, a sanitizer table test, a link table test, a table test of command keywords and their near misses, and a test that the token appears in no argv, URL, output, log or error and is sent to no other host.
- `live` tests (never in CI) send marked notifications to the user's own service; the still-to-verify items become assertions when run.

## Platforms

Linux and WSL required; macOS expected (standard library only), untested.
