# ha-notice

Sends one notification through a Home Assistant `notify` service over the REST API, in practice a push to your phone.

ha-notice is a small command line tool for scripts, cron jobs and hooks. It takes a title, a message, a level and an optional link, cleans the text, builds the request from an allowlist and posts it. When to send, what to send and how often are your caller's decisions. The normative rules are in [docs/interface.md](docs/interface.md); this README is the practical guide.

## What it does

- Sends a notification (`title`, `message`, `level`, `link`) to the `notify` service named in your config, with the access token read from the environment variable named by `token_env`.
- Sanitizes text, adds a per-level title prefix (`WARN:`, `ACTION:`, `ERROR:` by default), cuts long titles and messages and builds the request from an allowlist only ([Rendering](docs/interface.md#rendering)).
- Derives a notification tag from `--dedupe-key`, so a retry replaces the earlier notification instead of showing twice.
- Is stateless: it keeps no database, only a log of what it sent or refused (never the text).
- Works fully standalone: it calls no other tool and needs no other service than Home Assistant.

## Installation

You need Python 3.12 or newer and Linux or WSL (macOS is expected to work). The tool depends only on the standard library and PyYAML.

With [uv](https://docs.astral.sh/uv/):

```sh
uv tool install git+https://github.com/agent-workflow-kit/ha-notice
```

With pip, preferably in a virtual environment or with pipx:

```sh
pip install git+https://github.com/agent-workflow-kit/ha-notice
```

To pin a release, append `@v<version>` (a tag from the repository's releases) to the URL. Check the install with `ha-notice --version`.

## Quick start

1. Create a long-lived access token. In Home Assistant open your profile (your user name at the bottom of the sidebar), choose the Security tab, scroll to Long-lived access tokens and create one. A dedicated Home Assistant user for notifications limits what a leaked token can do, because the token is valid for the whole Home Assistant API.
2. Put the token in an environment variable. The variable's name is set by `token_env` in the config (default `HA_TOKEN`) and must match `HA_[A-Z0-9_]{1,60}` as a whole, so a config cannot name another secret. For a shell session: `export HA_TOKEN=...`. The token is read only from this variable, never from argv, a config file or a prompt, so do not put it in the config or on a command line that your shell history records; read it from a mode-0600 file or a secret manager instead. For cron and hooks, keep the token in a mode-0600 env file that the cron line sources; see [Calling from automation](#calling-from-automation).
3. Find the service name. This needs a Home Assistant administrator, because Developer tools is admin only; if the dedicated user is not an administrator, ask one or look it up with your own account. Open Developer tools, then Actions (older versions call it Services), and search for `notify.`. A phone running the companion app is a service named `notify.mobile_app_<device>`; the config key `service` is the part after `notify.`.
4. Write the config at `.config/ha-notice/config.yaml` under the account's home directory. Only two keys are required:

   ```yaml
   base_url: https://homeassistant.example:8123
   service: mobile_app_your_phone
   ```

   The home directory is the one in the password database, which `~` may not match. The `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` variables are not read, and a failed lookup is exit 2 `config_invalid` (key `home`). Use `--config <path>` to read another file. All keys are listed in [Configuration](#configuration).
5. Check the setup with `ha-notice validate --probe`, then send a first notification:

   ```sh
   ha-notice send --title "Disk" --message "Almost full" --level warn
   ```

## Sending

A notification has a `title` (optional), a `message` (required), a `level` (`info`, `warn`, `action` or `error`, default `info`) and an optional `link`. Exactly one input source is used.

From flags, meant for humans:

```sh
ha-notice send --title "Disk" --message "Almost full" --level warn --link https://example.org/dashboard
```

From JSON on stdin, meant for programs. This is also the default when stdin is not a terminal and no text flag is given. Leave absent fields out; never send null:

```sh
echo '{"title": "Build", "message": "Finished", "level": "warn"}' | ha-notice send --stdin-json
```

From a file with `--file <path>` (`--file -` is stdin). A JSON source cannot be combined with `--title`, `--message`, `--level` or `--link`; that is exit 2.

Other `send` flags: `--dedupe-key=<key>` (see [Replacing a notification](#replacing-a-notification)), `--actor (human|auto):<name>` recorded in the log, and `--decision-id`, which is accepted for uniformity and ignored. Global flags (`--json`, `--config`, `--dry-run`, `--actor`, `--verbose`, `--quiet`, `--version`) may stand before or after the subcommand; see [Global flags](docs/interface.md#global-flags).

Without `--json` a successful send prints `sent (<level>, <duration_ms> ms)` on stderr and nothing on stdout. With `--json` it prints one object on stdout. The output says `sent`, never `delivered`: Home Assistant reports success whether or not the push reaches a phone.

### Dry run

`--dry-run` builds the request and prints it without sending anything. It needs neither `base_url`, `service` nor the token, reads no credential and writes no log record, so it is the safe way to see what a message becomes. It applies to `send` only.

```console
$ ha-notice --dry-run send --title Disk --message "Almost full" --level warn --dedupe-key=abc123
{"title":"WARN: Disk","message":"Almost full","data":{"tag":"awkit-6ca13d52ca70c883e0f0bb10"}}
```

With `--json` the same request appears under `rendered`:

```console
$ echo '{"title":"Build","message":"Finished","level":"warn","link":"https://ci.example.org/run/1"}' | ha-notice --json --dry-run send --stdin-json
{"outcome":"dry_run","tool":"ha-notice","level":"warn","truncated":false,"bytes":135,"duration_ms":0,"http_status":null,"tag_set":false,"dedupe_key":null,"warnings":[],"rendered":{"title":"WARN: Build","message":"Finished","data":{"url":"https://ci.example.org/run/1","clickAction":"https://ci.example.org/run/1"}}}
```

### Levels and prefix

The level is advisory: ha-notice puts the `level_prefix` of the level in front of the title (`WARN:`, `ACTION:`, `ERROR:` by default, none for `info`) and otherwise treats all levels alike. The prefix does not authenticate the sender. Change the prefixes with `level_prefix` in the config.

### Links

`link` becomes the tap target of the notification. It must be a printable-ASCII `http` or `https` URL of at most 1024 characters, with no userinfo; percent-encode paths and give hosts as punycode. Anything else is refused with exit 20 (`link_invalid`, or `link_scheme` for another scheme). The rules are in the [link rule](docs/interface.md#notification).

Set `link_hosts` in the config to restrict the host. An entry matches itself and its subdomains, so do not list a shared hosting domain. A link to another host is refused with `link_invalid`:

```console
$ ha-notice --json --dry-run send --message hi --link https://evil.test/x
{"error":{"code":"refused","message":"the link is not valid","reason":"link_invalid","details":{"pointer":"/link"},"retryable":null,"retry_after_s":null,"unknown_outcome":null}}
```

With `link_hosts` unset, a producer can aim the tap target at any web address. Home Assistant does not show the URL in the push.

### Replacing a notification

`--dedupe-key=<key>` sets a notification tag: `awkit-` plus 24 hex characters of the SHA-256 of the key. Home Assistant replaces an earlier notification that has the same tag, whatever its level, so a retry does not show twice. Pass a hex digest of your key rather than a raw id, in the `=` form. A late first request can replace a newer notification with the same tag; a router that cares puts the level or a sequence number in its key.

### Truncation limits

Limits count Unicode code points. A title is cut at 256 characters (the cut ends with `…`) before the level prefix is added. A message is limited to `max_chars` (default 1000, range 100 to 2000) and to 2000 UTF-8 bytes, whichever is reached first; a cut message ends with `…[truncated]`. Input over 100000 characters in a field, or over 1 MiB in total, is refused with exit 20 (`invalid_payload`). The output field `truncated` tells you whether anything was cut. Details are in [Rendering](docs/interface.md#rendering).

## Validating the setup

`ha-notice validate` runs checks in order: `config` (every key valid, `base_url` and `service` set), `credential` (the token variable is set and well formed), then, only on request, `probe` and `test_message`. A failed check ends the run. It never prompts and never reads stdin.

```console
$ ha-notice validate
config: ok: the configuration is usable
credential: ok: the token is set and well formed
```

Plain `validate` makes no network call. With the token variable unset it reports the fault and exits 12:

```console
$ ha-notice validate
config: ok: the configuration is usable
credential: failed: credential_invalid: the token variable (HA_TOKEN) is missing or malformed
```

`--json` prints one report on stdout instead of the check lines. This is the output of a passing `validate --probe --json`:

```json
{"ok":true,"enabled":true,"probe":{"api_ok":true},"checks":[{"name":"config","ok":true,"message":"the configuration is usable"},{"name":"credential","ok":true,"message":"the token is set and well formed"},{"name":"probe","ok":true,"message":"GET /api/ answered with a JSON object"}]}
```

- `validate --probe` also makes one read-only call, `GET /api/`, to check the host and the token. It sends no notification. A 401 or 403 reports `auth_required`; a 404 or 405 means `base_url` or its path prefix is probably wrong; a certificate failure points at `ca_file`.
- `validate --test-message` sends a REAL notification (level `info`, title `ha-notice`, message `validate: test message`) and adds a `test_message` check. Look at your phone: delivery is not observable, so the check can only say that Home Assistant accepted the request. It is logged like a send. When it fails, the message does not name the code (it is in the log record unless `log` is false), and any non-zero exit means "look at the destination". It is for a human to run once by hand and is not for automation.
- `--dry-run` has no effect on `validate`: `validate --dry-run --test-message` still sends.
- With `enabled: false`, plain `validate` exits 0 and reports `enabled: false` (or exits 12 with a broken credential). `--probe` and `--test-message` make no call and exit 22, printing `{"outcome":"disabled"}` on stdout with `--json` and otherwise `disabled in config` on stderr.

| `validate` exit | Meaning |
|---|---|
| 0 | Every check passed (including `probe` or `test_message` when requested). |
| 2 | The `config` check failed, or the config could not be loaded (the `config_invalid` envelope). |
| 12 | The `credential`, `probe` or `test_message` check failed. |
| 22 | `--probe` or `--test-message` with `enabled: false`; no call was made. |

## Configuration

The config file is `.config/ha-notice/config.yaml` under your home directory, plus `config.d/*.yaml` beside it in lexical order (maps merge). Files are at most 64 KiB, unknown keys are refused, and an invalid config exits 2 `config_invalid` naming the key (an unknown key is reported as `?`, never by name). Precedence is flags, then config, then defaults; there are no environment overrides. The schema is [schemas/config.json](schemas/config.json) and every key is documented in the [Config](docs/interface.md#config) table.

This is [config.example.yaml](config.example.yaml), with every key at its default except the two required ones, which are commented out:

<!-- config.example.yaml -->

```yaml
# ha-notice example config: every key with its default, except the two required keys.
# Location: .config/ha-notice/config.yaml under your home directory (from the password database, no fallback: a failed lookup exits 2; HOME and
# XDG_CONFIG_HOME are not read), plus config.d/*.yaml beside it in lexical order; --config <path> reads another file (drop-ins are read next to it).
# Drop-ins: maps merge. Files are at most 64 KiB; unknown keys are refused.
# Precedence: flags, then config, then defaults. There are no environment overrides.
# Schema: schemas/config.json. Invalid config exits 2 (config_invalid), naming the key (`?` for an unknown key).
# Durations: a number of seconds, or a string such as "10s" or "1m" (no unit means seconds).

# false makes `send` print {"outcome": "disabled"} and exit 22 without reading input or the token.
enabled: true

# REQUIRED for send, no default: send exits 2 until both are set; a dry run needs neither.
# Home Assistant base URL: https://host[:port][/prefix]. No userinfo, query or fragment; one
# trailing slash run is removed. http:// only with allow_insecure_http: true.
# base_url: https://homeassistant.example:8123

# REQUIRED for send, no default. The notify service name, the part after "notify." (a mobile_app_ service
# for a phone). Lowercase letters, digits and underscores, at most 64 characters.
# service: mobile_app_your_phone

# Name of the environment variable holding a long-lived access token. Must match
# HA_[A-Z0-9_]{1,60} as a whole. The token itself never belongs in this file.
token_env: HA_TOKEN

# Allow an http:// base_url. The token then travels in cleartext. Warns on stderr on every send.
allow_insecure_http: false

# Extra CA bundle, an absolute path to a readable regular file of at most 4 MiB, for a private certificate authority or a self-signed server.
# Unset by default. There is no key that turns certificate checks off.
# ca_file: /path/to/ca-bundle.pem

# Restrict the host of `link` (list of 1 to 32 lowercase host names of at least two labels; an entry matches itself and
# its subdomains). Unset by default. With it unset a producer can aim the tap target at any web
# address; the push does not show the URL.
# link_hosts: [example.org]

# Title prefixes per level, one line of at most 16 characters each. Empty string: no prefix.
level_prefix:
  info: ""
  warn: "WARN:"
  action: "ACTION:"
  error: "ERROR:"

# data.group for every notification. Unset by default; [A-Za-z0-9_-]{1,64} as a whole.
# default_group: awkit

# Message limit in characters (100 to 2000); the message is also limited to 2000 UTF-8 bytes.
# Longer messages are cut and end with "…[truncated]".
max_chars: 1000

# The one deadline for a whole send (input, connect, request, retries): 1s to 120s.
timeout: 10s

# Limit for the connect phase: 1s to 30s; capped by the time left in the deadline.
connect_timeout: 3s

# false writes no log.jsonl in the state directory.
log: true
```

To send to several destinations, keep one config file per destination and pass `--config`.

## Logs and state

Every outcome that reaches step 3 (input reading) or later appends one record to `log.jsonl`, whether it was sent, refused (exit 20), failed or `outcome_unknown`, including an input timeout (`unavailable`). The file is in the state directory, `.local/state/ha-notice` under the same password-database home (created with mode 0700; `XDG_STATE_HOME` is not read). An exit 1 is logged only if the request may already have been sent (outcome `outcome_unknown`, code `internal`). It holds hashes, counts, the outcome and the exit code, never a title, message, link, host, service or credential. The log rotates at 1 MiB and keeps three older files. Not logged: exit 2, exit 22 (disabled), signals, dry runs, `validate` (except `--test-message`) and an exit 1 before the request started. `message_sha256` is a 64-bit unsalted hash, so a reader of the log file (mode 0600) can confirm a short message by hashing a guess. A state directory that cannot be used only prints `warning: log record skipped (state directory unusable)` and never changes the exit code. Set `log: false` to write nothing. See [Log](docs/interface.md#log).

## Exit codes

Decide by exit code; with `--json` the stdout document adds detail.

| Exit | Meaning |
|---|---|
| 0 | Accepted by Home Assistant (`sent`), or a dry run. |
| 1 | Internal error (code `internal`). With no envelope the outcome is unknown. |
| 2 | Usage or invalid configuration (codes `usage`, `config_invalid`). |
| 12 | Failed for a reportable reason; read `code`, `retryable` and `unknown_outcome` in the envelope. Codes: `host_rejected`, `auth_required`, `credential_invalid`, `rate_limited`, `upstream_error`, `network_error`, `outcome_unknown`, `wrong_host_response`, `unavailable`. |
| 20 | Refused before sending because of the payload (`code: refused`). Reasons: `invalid_payload`, `empty_message`, `command_keyword`, `link_invalid`, `link_scheme`. Nothing was sent. |
| 22 | Nothing sent because the tool is disabled in the config. A no-op, not an error; output `{"outcome":"disabled"}`. |
| 128+N | A signal arrived before the send started (129 SIGHUP, 130 SIGINT, 143 SIGTERM). Nothing was sent; no envelope, no log record. |

Exits 10, 11, 13 and 21 are never used.

### Error envelope

With `--json` every error prints one envelope on stdout (and one `<code>: <message>` line on stderr, `refused (<reason>): <message>` for exit 20):

```json
{"error":{"code":"credential_invalid","message":"the credential is missing or invalid","reason":null,"details":{"env":"HA_TOKEN"},"retryable":false,"retry_after_s":null,"unknown_outcome":false}}
```

Only `code` and `message` are always meaningful; the other keys are null when they do not apply. `message` is a fixed string and never contains input, a response body or the token. `retryable` means that sending the same notification again is safe. `unknown_outcome` means that the notification may already have been delivered. The full table is in [Exit codes](docs/interface.md#exit-codes), and the schema is [schemas/cli/error.json](schemas/cli/error.json).

## Calling from automation

Cron jobs, hooks and scripts call `ha-notice send --stdin-json --json --actor auto:<name>` with the payload on stdin, and decide by exit code: treat 22 as success, never retry 20 (after `link_invalid` or `link_scheme` you may retry once without `link`, putting the URL in the message; after `command_keyword` you may retry once with the text prefixed by its source and a colon), retry only exit 12 with `retryable` true (with your own backoff and a cap; when `unknown_outcome` is also true, only if you passed `--dedupe-key` and no newer notification with that key has been sent), treat an exit 1 without an envelope as outcome unknown, and wait at least `timeout` plus 10 s before killing the tool. The full rules for callers are in [Calling from automation](docs/interface.md#calling-from-automation). Automation must not call `validate --test-message`, which sends a real notification.

The practical guide is [docs/automation.md](docs/automation.md): the token env file, the cron line, a wrapper that handles every exit code, a retry loop, a health check and a hook that never blocks. In short, create the env file with mode 0600 (`umask 077` and `install -m 600` in a subshell keep the token out of other users' reach), and source it in the cron line with `set -a` so that the variable reaches the tool:

```sh
f=~/.config/ha-notice/env
(umask 077; mkdir -p ~/.config/ha-notice; [ -e "$f" ] || install -m 600 /dev/null "$f")
${EDITOR:-vi} "$f"
ls -l "$f"
```

```crontab
PATH=/home/me/.local/bin:/usr/bin:/bin
*/15 * * * * set -a; . "$HOME/.config/ha-notice/env"; set +a; /home/me/bin/check-disk
```

Put `HA_TOKEN='...'` in the env file (or alias another name to it). Never put the token in the crontab or on a command line, and call the tool with a kill timeout of at least `timeout` plus 10 s, for example `timeout 20 ha-notice ...` with the default `timeout` of 10 s. Cron mails any output, so wrap the call: treat exit 22 (disabled) as success with `rc=$?; [ "$rc" = 22 ] && rc=0` and print the error envelope only on a real failure. The cron line finds the config from the password-database home, so cron's own `HOME` does not matter to the tool.

## Signals and timing

`timeout` (default 10 s) is one deadline for the whole send: reading input, connecting, the request and retries. The tool ends within `timeout` plus 3 s. SIGINT, SIGTERM and SIGHUP before the send starts exit 128+N and send nothing; during the send they act like the deadline. SIGTERM is the preferred way for a caller to stop the tool. A 429 answer is retried up to twice (after 2 s and 4 s) and a connection failure once, all inside the deadline; these are the tool's own retries, and a caller's retry rule is under [Calling from automation](#calling-from-automation). See [Deadline](docs/interface.md#home-assistant-edge).

## Security notes

- The token is read only from the variable named by `token_env`, which must start with `HA_`. It is sent only as an `Authorization: Bearer` header, and never appears in argv, URLs, logs, output or errors.
- The connection uses `https` with certificate and host name checks and TLS 1.2 or newer. An `http://` `base_url` is refused unless `allow_insecure_http: true`; then the token travels in cleartext and every run that makes a request warns on stderr (`--quiet` does not hide it). There is no switch that turns certificate checks off.
- For a private certificate authority or a self-signed server, set `ca_file` to an absolute path of a PEM bundle of at most 4 MiB; it is added to the system trust, or used alone when the default trust is empty.
- Proxy variables and `SSL_CERT_FILE` are ignored, redirects are never followed, and the tool runs no subprocess.
- Untrusted text travels only on stdin or in a file, never in argv or the environment. Flag text is for humans.
- A message that is only a companion-app command word (for example `clear_notification`) is refused with `command_keyword`. Prefix the text with its source and a colon, or write a sentence.

## Residual risks

The complete list is [Residual risks](docs/interface.md#residual-risks). In short:

- No delivery confirmation: success is returned whether or not the push reaches the phone.
- The token is a long-lived credential valid for the whole Home Assistant API; use a dedicated user. Whoever can edit your config can send the token anywhere, since `base_url` and `--config` choose the destination; the config is trusted (same-user boundary), and the state directory is checked but the config is not.
- The environment is trusted: `PYTHONPATH`, `LD_PRELOAD` and `OPENSSL_CONF` run code in the tool with the token in reach, so a caller that can set the process environment is inside the trust boundary.
- Errors are opaque: several different mistakes return the same 400, so diagnose with `validate --test-message` and check `service`.
- `message_sha256` in the log is a 64-bit unsalted hash, so a reader of the log file can confirm a short message.
- The command-word rule is a guess at the apps' matching and is over-broad: a legitimate message that equals a keyword or starts `command_` or `kiosk_` is refused, so the caller prefixes the text with its source and a colon.
- The tool does not escape template syntax. A caller that sends untrusted text to a Home Assistant service that renders templates takes that risk.
- The message may be cut or dropped on the phone; the display limit is unknown, and the defaults of 1000 characters and 2000 bytes are conservative.
- With `allow_insecure_http` the token travels in cleartext, and a self-signed server is trusted only through `ca_file`; see [Security notes](#security-notes).
- Home Assistant was observed not to render templates in REST-supplied text; this is tested, not guaranteed.
- The Android app may render a small HTML subset in the message (unverified), so a producer may be able to style or mislabel text.
- With `link_hosts` unset, a producer can aim the tap target at any web address.
- Title and message may show on the lock screen: never send secrets.
- A producer who can guess a dedupe key can replace an unread notification with the same key.
- The `level` prefix does not authenticate the sender.

## Live tests

The maintainer's live suite (`pytest -m live -s`, never in CI) sends real notifications and needs a look at the phone; see [docs/live-tests.md](docs/live-tests.md).

## Documentation

- [docs/interface.md](docs/interface.md): normative interface
- [docs/automation.md](docs/automation.md): cron, scripts and hooks
- [docs/design.md](docs/design.md): decisions and internals
- [docs/plan.md](docs/plan.md): staged implementation plan
- [docs/live-tests.md](docs/live-tests.md): the live test suite
- [awkit architecture](https://github.com/agent-workflow-kit/awkit-docs/blob/main/architecture.md)
- [awkit design guide](https://github.com/agent-workflow-kit/awkit-docs/blob/main/design-guide.md)

## License

MIT, see [LICENSE](LICENSE).
