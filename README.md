# ha-notice

Sends one notification through a Home Assistant `notify` service over the REST API, in practice a push to your phone.

## Status

Designed (interface 0.1.0-design); not yet implemented. The normative specification is [docs/interface.md](docs/interface.md); decisions are in [docs/design.md](docs/design.md).

## Layer

L1 (primitive). Works fully standalone; it does not need the `awkit` harness.

## What it does

- Sends a notification (`title`, `message`, `level`, `link`) to the `notify` service named in your config, with the access token read from the environment variable named by `token_env`.
- Sanitizes text, adds a per-level title prefix (`WARN:`, `ACTION:`, `ERROR:` by default), cuts long titles and messages and builds the request from an allowlist only ([Rendering](docs/interface.md#rendering)).
- Derives a notification tag from `--dedupe-key`, so a retry replaces the earlier notification instead of showing twice.
- Is stateless: it keeps no database, only a log of what it sent or refused (never the text); dry runs, usage errors and disabled runs are not logged. When to send, what to send and how often are your caller's decisions.

## Quick start

After the [Set up Home Assistant](#set-up-home-assistant) steps (you need `base_url` and `service`):

```sh
export HA_TOKEN=...   # a long-lived access token, see below
ha-notice validate --probe     # offline checks plus one read-only call; never sends
echo '{"title": "Build", "message": "Finished", "level": "info"}' | ha-notice send --stdin-json
ha-notice send --title "Disk" --message "Almost full" --level warn --link https://example.com/dashboard
ha-notice send --message "Preview only" --dry-run --json
```

## Commands

| Command | Purpose |
|---|---|
| `ha-notice send [--stdin-json \| --file <path>\|-] [--title <t>] [--message <m>] [--level <l>] [--link <url>] [--dedupe-key <k>] [--decision-id <id>]` | Send one notification. Text comes from stdin JSON, a file or flags; flags are for humans. |
| `ha-notice validate [--probe] [--test-message]` | Check the config and the token variable; never prompts; `--probe` also checks the host and the token with one read-only call, `GET /api/` (output gains `probe: {api_ok}`); `--test-message` sends one marked test notification and adds a `test_message` check (look at your phone; automation must not call it). Plain `validate` ignores `enabled` except to report it, so a disabled tool still reports its faults; `--probe` and `--test-message` on a disabled tool make no call and exit 22. Exit 0 when every check passes, else the exit code of the failing check. |

Global flags: `--json`, `--config`, `--dry-run`, `--actor`, `--verbose`, `--quiet`, `--version` ([Global flags](docs/interface.md#global-flags)).

## Set up Home Assistant

1. Create a long-lived access token: in Home Assistant open your profile page (your user name at the bottom of the sidebar), scroll to Long-lived access tokens and create one. A dedicated user for notifications limits what a leaked token can do.
2. Put the token in an environment variable whose name you set as `token_env` in the config (default `HA_TOKEN`). For cron, keep it in a file that only you can read and source it in the cron line:

   ```sh
   ( umask 077; mkdir -p ~/.config/ha-notice; echo 'export HA_TOKEN=...' >> ~/.config/ha-notice/env )
   # crontab (absolute binary path, from `command -v ha-notice`; the schedule is a placeholder):
   # */15 * * * * set -a; . ~/.config/ha-notice/env; set +a; "$HOME/.local/bin/ha-notice" send --stdin-json --json --actor auto:cron < msg.json
   ```

   The `>>` never truncates an existing file, so a second run adds a second line and the last one wins. Cron runs the tool with `--config <path>` when your config is not in the default place. The variable name must start with `HA_` (`token_env` is restricted to that); a token kept under another name is aliased to `HA_TOKEN` in this env file.

3. Find the service name: in Home Assistant, Developer tools, Actions (or Services), search for `notify.`. Your phone is a service named `mobile_app_<device>`; the config key `service` is the part after `notify.`.
4. Copy [config.example.yaml](config.example.yaml) to `~/.config/ha-notice/config.yaml` and set `base_url` and `service` (without them a send exits 2).
5. Run `ha-notice validate --probe`, and `ha-notice validate --test-message` once by hand to see a test notification on your phone.

## Safety

- A message that is only a companion-app command word is refused, `link` must be a printable-ASCII `http` or `https` URL (and, with `link_hosts` set, on an allowed host), and the request carries no caller-supplied `data` ([Command messages](docs/interface.md#command-messages), [Rendering](docs/interface.md#rendering)).
- Home Assistant reports success whether or not the push reaches a phone, so output says `sent`, never `delivered` ([Residual risks](docs/interface.md#residual-risks)).

## Exit codes

0 sent or dry run, 1 internal error, 2 usage or invalid config, 12 failed (with a `code`, including `credential_invalid` for a missing or malformed token; read `retryable` and `unknown_outcome`), 20 refused (`code: refused` with a `reason` such as `invalid_payload` or `empty_message`; only for payload problems), 22 nothing sent because the tool is disabled (a no-op, not an error). See [Exit codes](docs/interface.md#exit-codes).

## Config and environment

- Config: `.config/ha-notice/config.yaml` under your home directory (taken from the password database; `HOME` and `XDG_CONFIG_HOME` are not read; `--config <path>` selects another file) plus `config.d/*.yaml` beside it; every key is documented in [config.example.yaml](config.example.yaml) and [Config](docs/interface.md#config).
- Environment: only the variable named by `token_env` (the token) is read; the state directory is `.local/state/ha-notice` under the same home directory; there are no `HA_NOTICE_*` overrides ([Environment variables](docs/interface.md#environment-variables)).
- Hooks: none.

## Limits

- Proxy variables and `SSL_CERT_FILE` are ignored; a private CA goes in `ca_file`, and there is no switch that turns certificate checks off.
- With `link_hosts` unset a producer can aim the tap target at any web address; the push does not show the URL.
- A retry after an unknown outcome is safe only while no newer notification with the same key has been sent (a retry replaces the earlier notification).
- The Android app may render a small HTML subset in the message (unverified); until checked, a producer may be able to style or mislabel text.
- Calling from a script: see [Calling from automation](docs/interface.md#calling-from-automation).

## Dependencies

The Python standard library, Pydantic for config validation and PyYAML (with a strict loader) for the config file; ha-notice calls no other tool.

## Requirements and install

Python 3.12 or newer and [uv](https://docs.astral.sh/uv/) to install it.

```sh
uv tool install git+https://github.com/agent-workflow-kit/ha-notice
```

## Documentation

- [docs/interface.md](docs/interface.md): normative interface
- [docs/design.md](docs/design.md): decisions and internals
- [docs/plan.md](docs/plan.md): staged implementation plan
- [awkit architecture](../awkit-docs/architecture.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/architecture.md))
- [awkit design guide](../awkit-docs/design-guide.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/design-guide.md))

## License

MIT — see LICENSE.
