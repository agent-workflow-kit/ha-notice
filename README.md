# ha-notice

Sends one notification through a Home Assistant `notify` service over the REST API, in practice a push to your phone.

## Status

Designed (interface 0.1.0-design); not yet implemented. The normative specification is [docs/interface.md](docs/interface.md); decisions are in [docs/design.md](docs/design.md).

## Layer

L1 (primitive). Works fully standalone; it does not need the `awkit` harness.

## What it does

- Sends a notification (`title`, `message`, `level`, `link`) to the `notify` service named in your config, with the access token read from the environment variable named by `token_env`.
- Sanitizes text, adds a per-level title prefix (`WARN:`, `ACTION:`, `ERROR:` by default), cuts long messages and builds the request from an allowlist only ([Rendering](docs/interface.md#rendering)).
- Can derive a notification tag from `--dedupe-key`, so a retry replaces the earlier notification instead of showing twice.
- Is stateless: it keeps no database, only a log of what it sent (never the text). When to send, what to send and how often are your caller's decisions.

## Quick start

```sh
export HA_TOKEN=...   # a long-lived access token, see below
ha-notice validate --probe
echo '{"title": "Build", "message": "Finished", "level": "info"}' | ha-notice send --stdin-json
ha-notice send --title "Disk" --message "Almost full" --level warn --link https://example.com/dashboard
ha-notice send --message "Preview only" --dry-run --json
```

## Commands

| Command | Purpose |
|---|---|
| `ha-notice send [--stdin-json \| --file <path>\|-] [--title <t>] [--message <m>] [--level <l>] [--link <url>] [--dedupe-key <k>]` | Send one notification. Text comes from stdin JSON, a file or flags; flags are for humans. |
| `ha-notice validate [--probe] [--test-message]` | Check the config and the token variable; `--probe` also checks the host and the service with two read-only calls; `--test-message` then sends one marked test after confirmation. |

Global flags: `--json`, `--config`, `--dry-run`, `--yes`, `--actor`, `--verbose`, `--quiet`, `--version` ([Global flags](docs/interface.md#global-flags)).

## Set up Home Assistant

1. Create a long-lived access token: in Home Assistant open your profile page (your user name at the bottom of the sidebar), scroll to Long-lived access tokens and create one. A dedicated user for notifications limits what a leaked token can do.
2. Put the token in an environment variable whose name you set as `token_env` in the config (default `HA_TOKEN`). For cron, keep it in a file that only you can read and source it in the cron line:

   ```sh
   install -m 600 /dev/null ~/.config/ha-notice/env
   echo 'export HA_TOKEN=...' >> ~/.config/ha-notice/env
   # crontab: * * * * * . ~/.config/ha-notice/env && ha-notice send --stdin-json < msg.json
   ```

3. Find the service name: in Home Assistant, Developer tools, Actions (or Services), search for `notify.`. Your phone is a service named `mobile_app_<device>`; the config key `service` is the part after `notify.`.
4. Copy [config.example.yaml](config.example.yaml) to `~/.config/ha-notice/config.yaml`, set `base_url` and `service`, and run `ha-notice validate --probe`.

## Safety

- A message that is a companion-app command keyword is refused, `link` must be `http` or `https`, and the request carries no caller-supplied `data` ([Command messages](docs/interface.md#command-messages), [Rendering](docs/interface.md#rendering)).
- Home Assistant reports success whether or not the push reaches a phone, so output says `sent`, never `delivered` ([Residual risks](docs/interface.md#residual-risks)).

## Exit codes

0 sent or dry run, 1 internal error, 2 usage or invalid config, 12 failed (with a `code`), 20 refused with a `reason`, 22 nothing sent because the tool is disabled (a no-op, not an error). See [Exit codes](docs/interface.md#exit-codes).

## Config and environment

- Config: `~/.config/ha-notice/config.yaml` plus `config.d/*.yaml`; every key is documented in [config.example.yaml](config.example.yaml) and [Config](docs/interface.md#config).
- Environment: `HA_NOTICE_<KEY>` for scalar config keys, and the variable named by `token_env` for the token ([Environment variables](docs/interface.md#environment-variables)).
- Hooks: none.

## Dependencies

None beyond the Python standard library and Pydantic for config validation; ha-notice calls no other tool.

## Install

```sh
uv tool install git+https://github.com/agent-workflow-kit/ha-notice
```

## Documentation

- [docs/interface.md](docs/interface.md): normative interface
- [docs/design.md](docs/design.md): decisions and internals
- [awkit architecture](../awkit-docs/architecture.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/architecture.md))
- [awkit design guide](../awkit-docs/design-guide.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/design-guide.md))

## License

MIT — see LICENSE.
