# ha-notice: design

Status: 0.1.0-design, 2026-11-17. The rules are in [interface.md](interface.md), the single normative source; this document records decisions, modules and tests and links to interface headings without restating them. Architecture: `../awkit-docs/architecture.md` (v1.22).

## Role and layer

L1 primitive: send one notification through a Home Assistant `notify` service over the REST API (in practice a companion-app push to a phone). Works fully standalone. It is one of three sibling channel notifiers with the same contract (`slack-notice`, `wsl-notice`), each designed to be called by a routing tool above it without knowing that tool exists.

## Uses

| Dependency | Layer | Binding | Notes |
|---|---|---|---|
| Home Assistant REST API over HTTP(S) | L0 third party | none (not an edge of the tool graph) | One POST per notification; two read-only GETs for `validate --probe`; see [Home Assistant edge](interface.md#home-assistant-edge). |
| Python standard library HTTP client | L0 | none | No third-party HTTP dependency. |
| Pydantic (config validation) | library | none | Required by the design guide for config; the only third-party runtime dependency. |

No tool dependencies: ha-notice composes nothing.

## Decisions

| ID | Decision | Rationale |
|---|---|---|
| D-1 | Stateless: no state database, no outbox, no retries after exit; one `log.jsonl`. See [Files](interface.md#files), [Log](interface.md#log). | Deduplication, quiet hours, history and deferral belong to the routing tool (user decision S-2). |
| D-2 | Common input contract: `title`, `message`, `level`, `link`; unknown fields refused; text from stdin, a file or flags, all sanitized alike. See [Notification](interface.md#notification). | Architecture 13.2 rule 2; short argv text is untrusted (S-3). |
| D-3 | `data` is built from an allowlist (`url`, `clickAction`, `tag`, `group` and per-level `importance`, `channel`, `ttl`, `priority`, `push`), never from caller input beyond `link` and the dedupe key. See [Rendering](interface.md#rendering). | The API accepts any `data` unchecked, including `app://` and `javascript:` URLs (spike B). |
| D-4 | Refuse command messages: a message equal to a companion-app command keyword, or starting `command_` or `kiosk_`, exits 20 `command_keyword`. See [Command messages](interface.md#command-messages). | A message equal to such a keyword makes the phone run a command (clear a notification, report its location) instead of showing text; research from the companion-app documentation, not sent in tests. |
| D-5 | `link` becomes `url` and `clickAction`, `http` and `https` only. | Taps follow the link; other schemes open apps and intents. |
| D-6 | The dedupe key becomes `data.tag` (hash), so a retry replaces the earlier notification. | Verified on a phone: a second notification with the same tag replaced the first. |
| D-7 | Template syntax is not escaped. | Verified on a phone: `{{ 1+1 }}` and `{% if %}` appeared literally in title and message. Residual risk recorded. |
| D-8 | `base_url` and `service` have no default; the URL is joined without double or trailing slashes; `https` unless `allow_insecure_http`; certificate checks on unless `tls_verify: false`. See [Config](interface.md#config). | A double or trailing slash is a 404; a public default would send nothing useful and a wrong default could send a token to a wrong host. |
| D-9 | The token only from the variable named by `token_env`, only in the `Authorization` header and only to `base_url`'s host. See [Home Assistant edge](interface.md#home-assistant-edge). | Design guide section 7. |
| D-10 | Exit codes and outcomes as in [Exit codes](interface.md#exit-codes); exit 22 for a disabled tool; `unknown_outcome` and no automatic retry after a timeout that follows a sent request. | A caller with a tag can retry safely; one without can choose (S-7). |
| D-11 | `validate --probe` uses two read-only GETs (`/api/` and `/api/services`) and sends nothing; `--test-message` sends a marked test after confirmation. | The host's 400 is opaque, so only a probe can say which mistake was made. |
| D-12 | No hooks in 0.x and no audit file; `config_invalid` is exit 2. See [Hooks](interface.md#hooks), [Log](interface.md#log). | As in slack-notice D-9 and D-6. |

## Resolved open topics

- Payload shape: [Notification](interface.md#notification).
- Channel config: [Config](interface.md#config); the user's existing hook script that hardcodes the token is replaced by `token_env` in the user's own config.
- Escaping: none needed for the host (templates are not rendered); control and invisible characters are removed ([Sanitizer](interface.md#sanitizer)).

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

Still to verify (live tests in the plan): `GET /api/` and `GET /api/services` responses and the shape of the services list; the phone's display limit for long text; whether `importance`, `channel` and `push.interruption-level` take effect from a REST call; the 401 body for a wrong (not missing) token; an unreachable host's timeout (the test hit an instant refusal only); a self-signed certificate; a base URL with a path prefix; whether other notify services (not companion apps) accept the same body.

## Modules

| Module | Responsibility |
|---|---|
| `cli.py` | Argument parsing, command dispatch, exit-code mapping, output. |
| `config.py` | Config loading, drop-ins, env overrides, Pydantic validation. |
| `payload.py` | Input parsing, notification validation, sanitizer, command-keyword check. |
| `render.py` | Request body: title, message, `data` allowlist, truncation. |
| `hass.py` | URL joining, request building, response mapping, retries, probe calls. |
| `log.py` | Log record writing and rotation. |
| `gateway.py` | The only place that opens network connections and clocks; tests substitute fakes. |

## Data model, concurrency, errors

No stored objects and no locks. Errors use the envelope in [Error envelope](interface.md#error-envelope); log failures never change an exit code.

## Test strategy

- All HTTP goes through `gateway.py`; a fake Home Assistant server returns each row of [Home Assistant edge](interface.md#home-assistant-edge), including slow responses, a connection drop after the request and a redirect.
- Golden files for `--json` output and request bodies (levels, tags, links, truncation, `level_data`), schema tests with positive and negative samples, a sanitizer table test, a table test of command keywords and their near misses, and a test that the token appears in no argv, URL, output, log or error and is sent to no other host.
- `live` tests (never in CI) send marked notifications to the user's own service; the still-to-verify items become assertions when run.

## Platforms

Linux and WSL required; macOS expected (standard library only), untested.
