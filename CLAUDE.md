# CLAUDE.md: ha-notice

ha-notice is an awkit L1 primitive: send one notification through the Home Assistant REST notify service. It must work fully standalone (no harness, bus, shared library or shared contracts package). Status: design done, 0.1.0-design.

**Naming.** Tools have no shared prefix; see design guide §1 naming rules.

## Read first

1. `../awkit-docs/architecture.md`: this tool's §5.1 entry and its §20 entry (constraints and open topics), plus the cross-cutting sections listed in `docs/design.md`.
2. `../awkit-docs/design-guide.md`: the conventions every awkit tool follows.
3. `docs/interface.md`: the single normative source for this tool's rules; it wins over every other document.
4. `docs/design.md`: decisions, modules and test strategy; `docs/plan.md`: the staged plan.

## Rules

- Open source: never add confidential information (company names, hostnames, ticket project keys, repo or org names, people's names, private skills). Organization specifics belong in the user's config.
- Never import sibling repos. Read their docs and schemas by path only; copying a sibling's schema files into `tests/` pinned to a version is allowed.
- No upward awareness: this tool never knows about, or behaves differently for, the tools that call it.
- Interface first: interface changes update `docs/interface.md`, `schemas/` and `../awkit-docs/interface-registry.md` together.
- Semver. A breaking interface change is, before 1.0, a `feat` commit whose title names the break (never `!` before 1.0), and from 1.0 on a `!` commit; the title becomes the changelog line (details go in the PR body). Either way, update `awkit-docs/interface-registry.md`. Never hand-edit CHANGELOG.md or the version.
- Run `make verify` before every commit.
- All subprocess and HTTP calls go through `src/ha_notice/gateway.py`.
- Untrusted text travels only in files or stdin, never argv or env.
- The token is read only from the variable named by `token_env` (it must start with `HA_`) and never appears in argv, URLs, logs, output or errors. There are no `HA_NOTICE_*` environment overrides. The config and state directory are found from the password-database home; `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are not read. A failed home lookup is exit 2 `config_invalid` (key `home`); there is no fallback.
- HTTP uses `http.client` with its own TLS context: no proxies, no redirects, no `urllib`, `SSL_CERT_FILE` ignored.
- Never run destructive git commands (reset, checkout --, clean, restore, stash drop, force-push). Never kill processes by pattern; only signal an exact PID this tool started.
- Minimize dependencies; justify each one in `docs/design.md`.

## Workflow

1. The design is done (interface 0.1.0-design). Implement the GitHub issues in plan order, test-first; `docs/interface.md` wins over any other document.
2. There is no audit file and there are no hooks; do not add either without an interface change.

## Repository workflow

- Work in a git worktree on a branch named `<type>/<short-slug>`, never in the main checkout (design guide section 17).
- PR titles are Conventional Commit headers; they become the squash commit, the version bump and the changelog line (architecture section 18.3). Do not use `!` before 1.0 (a breaking change before then is a `feat` whose title names the break).
- Never use `--no-verify`. Check PR titles, bodies and comments with `guard text` where the private-content guard is installed (architecture section 18.7).
- Never merge a PR without the maintainer's explicit instruction for that PR; merges go through `awkit-ci`'s `scripts/pr-merge` (architecture section 18.6).
- Never hand-edit `CHANGELOG.md` or the version in `pyproject.toml`; the release job owns them.
