# ha-notice

Send a notification through the Home Assistant REST notify service.

## Status

Pre-design: interface not yet specified; see [docs/design.md](docs/design.md).

## Layer

L1 (primitive). Works fully standalone.

## What it does

Delivers a notification through the Home Assistant REST notify service (base URL and service name from config; token from the env var named by `token_env`). Takes `send --stdin-json` (a JSON object with `title`, `message`, `level`, `link`) or, for trusted human use, `send --title ... --message ...`. Levels are ordered `info < warn < action < error`. Escapes platform markup in title and message (no mentions, no link injection); links are only added via `link`/`--link`. Routing, quiet hours and dedup are notice-route's job; this tool only delivers.

## Indicative commands

Indicative, finalized in [docs/interface.md](docs/interface.md):

```text
ha-notice send --stdin-json            # JSON object with title, message, level, link
ha-notice send --title ... --message ... [--level info|warn|action|error] [--link URL]   # trusted human use
```

## Dependencies

- curl/HTTP (Home Assistant REST API): binding: TBD (A/B/C), decided in this tool's design session

## Install

```text
uv tool install git+https://github.com/agent-workflow-kit/ha-notice
```

## Documentation

- [awkit architecture](../awkit-docs/architecture.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/architecture.md))
- [awkit design guide](../awkit-docs/design-guide.md) ([published](https://github.com/agent-workflow-kit/awkit-docs/blob/main/design-guide.md))

## License

MIT — see LICENSE.
