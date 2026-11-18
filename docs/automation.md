# Calling ha-notice from cron, scripts and hooks

This guide is the practical side of [Calling from automation](interface.md#calling-from-automation), which is normative. It shows a token env file, a cron line, a wrapper that handles exit codes, a retry loop and a hook that never blocks. The shell examples are bash unless a block says `sh`, they are syntax-checked by the test suite, and the wrappers are run against stub and real binaries there.

Names in angle brackets such as `<name>` are placeholders; the examples use `/home/me` for a home directory and `homeassistant.example` for a host.

## The short version

- Keep the token in a mode-0600 env file that the cron line sources, never in argv, in the crontab or in the config.
- Call `ha-notice send --stdin-json --json --actor auto:<name>` with the payload on stdin or in a file.
- Kill the tool no earlier than `timeout` plus 10 s (20 s with the default `timeout` of 10 s).
- Treat exit 22 (disabled) as success, never retry exit 20, retry exit 12 only when its envelope says `retryable` is true.
- Never call `validate --test-message` from automation: it sends a real notification.

## The token env file

The tool reads the token only from the environment variable named by `token_env` (default `HA_TOKEN`; the name must match `HA_[A-Z0-9_]{1,60}`). There are no `HA_NOTICE_*` overrides, and the tool never reads a secret file or a shell startup file itself, so under cron the variable must already be in the process environment. A mode-0600 env file that the cron line sources does that.

Create the file empty, with the right mode from the first byte, then put the token in with an editor so it never appears in shell history, argv or a terminal log:

<!-- test:envsetup -->

```sh
f=~/.config/ha-notice/env
(umask 077; mkdir -p ~/.config/ha-notice; [ -e "$f" ] || install -m 600 /dev/null "$f")
${EDITOR:-vi} "$f"
ls -l "$f"
```

The `umask 077` is scoped to the subshell, and an existing file is never truncated, so running the commands again keeps the token. The listing should start with `-rw-------`. The file is shell syntax, so single-quote the value; a long-lived token is printable ASCII without quotes. If you keep the token under another name, alias it to the name the config expects in the same file and unset the original, so that `set -a` exports only one copy of the token:

<!-- test:envalias -->

```sh
HOME_ASSISTANT_TOKEN='paste-the-long-lived-token-here'
HA_TOKEN=$HOME_ASSISTANT_TOKEN
unset HOME_ASSISTANT_TOKEN
```

Alternatively set `token_env: HA_HOME_ASSISTANT_TOKEN` in the config and name the variable that way in the file; the name must still start with `HA_`. Cron's `sh` only needs `set -a` (see below) for the variables to reach the tool. The file is executed as shell by whoever sources it, so it must be owned by you and writable by nobody else.

Why not put the token on the command line or in the crontab: argv is readable by every local user through `ps` and `/proc/<pid>/cmdline`, and crontab text is readable through `crontab -l`, backups, the cron log (which records each command line) and cron mail. The tool is built the same way: the token never appears in its argv, output, logs or errors. A missing or malformed token is exit 12 `credential_invalid`, and `validate` reports it without any network call.

## The cron line

Cron starts jobs with a minimal environment, so spell out what the job needs. The crontab does not expand variables in assignments, so give `PATH` as a literal path (`uv tool install` puts the program in `~/.local/bin`). Cron runs the command with `/bin/sh`, so the line must be POSIX shell:

<!-- test:cron -->

```crontab
PATH=/home/me/.local/bin:/usr/bin:/bin
*/15 * * * * set -a; . "$HOME/.config/ha-notice/env"; set +a; /home/me/bin/check-disk
```

- `set -a` exports every variable the file defines, so the tool sees `HA_TOKEN`. `set +a` stops exporting after the file.
- If the env file is missing, the shell's `.` fails and a non-interactive `sh` stops before it runs the job. That is the safe behaviour: nothing runs without its token and cron mails the error.
- `HOME` in the crontab line is whatever cron sets; the tool itself does not read it. It finds the config and the log directory from the account's home in the password database, so cron's `HOME` is irrelevant to where the config is read from. Use `--config <path>` for any other file.
- In a crontab line an unescaped `%` ends the command and starts its standard input. Put anything with a `%` (a `date +%F`, say) in a script, or write `\%`.
- Cron mails whatever a job prints, so a job should print nothing on success. The wrapper below does.

A job script is ordinary shell. Save the wrapper from the exit-code section below as `notify-ha` in `~/.local/bin`, which is on the crontab `PATH` above, and this one as `/home/me/bin/check-disk`. It sends a warning when the root filesystem is nearly full, with a fixed payload in a here-document (a file, not a pipe) and a dedupe key so that a repeat replaces the earlier notification:

```bash
#!/bin/bash
used=$(df --output=pcent / | tail -n 1 | tr -dc 0-9)
if [ "$used" -ge 90 ]; then
  key=$(printf '%s' disk-root | sha256sum | cut -d' ' -f1)
  notify-ha disk --dedupe-key="$key" <<'EOF'
{"title":"Disk","message":"The root filesystem is almost full","level":"warn"}
EOF
fi
```

## The canonical call

`ha-notice send --stdin-json --json --actor auto:<name> [--dedupe-key=<hex>]`, with the payload on stdin.

- Leave an absent field out; never send `null`. A message is required and non-empty.
- Pass the dedupe key in the `=` form and as a hex digest of your own key, not a raw id (`printf '%s' "$id" | sha256sum | cut -d' ' -f1`).
- `--file <path>` reads the same JSON from a file, and `--file -` is stdin.
- Untrusted text (a log line, a branch name, a commit message) goes only in the payload on stdin or in a file, never in argv or in an environment variable. The `--title` and `--message` flags are for humans typing.
- The caller prevents refusals: keep fields under 100000 characters, give a non-empty message, use one of `info`, `warn`, `action`, `error`, and give a link as an `http` or `https` address in printable ASCII.
- A dry run is the safe way to see what a payload becomes. It needs no token and no destination, sends nothing and writes no log record:

```console
$ echo '{"title":"Build","message":"ok","level":"warn"}' | ha-notice send --stdin-json --json --actor auto:demo --dry-run
{"outcome":"dry_run","tool":"ha-notice","level":"warn","truncated":false,"bytes":38,"duration_ms":0,"http_status":null,"tag_set":false,"dedupe_key":null,"warnings":[],"rendered":{"title":"WARN: Build","message":"ok"}}
```

## Kill timeout and the stdin write

`timeout` in the config is one deadline for the whole send; it defaults to 10 s and may be 1 s to 120 s. The tool ends within `timeout` plus 3 s, so a caller that kills it must wait at least `timeout` plus 10 s: 20 s for the default, 130 s for the maximum. A caller that kills the tool earlier gets no envelope and has to treat the outcome as unknown.

- With coreutils: `timeout 20 ha-notice send ...`. When `timeout` fires it exits 124, which the wrapper below reports as an unknown outcome. It sends SIGTERM, which the tool treats as the deadline during the send; do not use `-s KILL`.
- Raise the number whenever you raise `timeout` in the config: it is `timeout` plus 10.
- The tool may exit without reading all of stdin (a refused config, a disabled tool). A caller ignores EPIPE and SIGPIPE on the stdin write and decides by the exit code alone.
- In shell the simplest way is not to pipe at all: use a here-document, `<<<` or `< file`, as in the examples. If you do pipe, bash sets the pipeline status from the last command, and under `set -o pipefail` a writer killed by SIGPIPE shows as 141 beside the tool's own status in `PIPESTATUS`, so read `${PIPESTATUS[-1]}` there.
- In Python, `subprocess.run(..., input=data)` already ignores a broken pipe; with a hand-written writer catch `BrokenPipeError`.

## Exit codes: a wrapper

Exit 22 means the tool is disabled in the config and nothing was sent; for a caller that is a successful no-op, so a shell caller writes `rc=$?; [ "$rc" = 22 ] && rc=0`. This wrapper does that, adds the kill timeout, prints nothing on success and, on any failure, prints the envelope once on stderr (which cron mails) after the tool's own one-line `<code>: <message>` error on stderr:

<!-- test:wrapper -->

```bash
#!/bin/bash
# notify-ha NAME [ha-notice flags]: JSON payload on stdin; the environment holds the token.
# Exits 0 when sent or disabled, otherwise with the tool's exit code (124: the kill timeout fired).
name=${1:?usage: notify-ha NAME [flags]}
shift
out=$(timeout 20 ha-notice send --stdin-json --json --actor "auto:$name" "$@")
rc=$?
[ "$rc" = 22 ] && rc=0
if [ "$rc" != 0 ]; then
  printf 'ha-notice failed (exit %s): %s\n' "$rc" "$out" >&2
fi
exit "$rc"
```

- The wrapper is silent only while the tool is: with `allow_insecure_http` set, the tool prints its `insecure_http` warning on stderr on every request, even with `--quiet`, so the job is not silent and cron mails it.
- Do not add `set -e` before the `ha-notice` line: the script must read `$?` itself. If you source this logic into a script that has `set -e`, write `rc=0; out=$(...) || rc=$?` instead.
- The line `[ "$rc" = 22 ] && rc=0` is a plain `&&` list, so it is safe even when `rc` is not 22 (the list's status is not used).
- Exit 124 and an exit 1 without an envelope are unknown outcomes: the notification may have been delivered.
- The wrapper does not retry. A cron job that runs every few minutes is its own retry; when the message must get through, use the loop in the next section.

What each exit means for the caller (the full table is in the [interface](interface.md#calling-from-automation)):

| Exit | Meaning | Caller action |
|---|---|---|
| 0 | Sent, or a dry run. | Nothing. |
| 22 | Disabled in the config; nothing sent. | Treat as success. |
| 20 | The payload was refused; nothing sent. | Do not retry the same payload; fix it and surface once. After `link_invalid` or `link_scheme` you may retry once without `link` (no pointer, or pointer `/link`) or without the action named by the pointer `/actions/<i>/uri`, putting the URL in the message. After `command_keyword` you may retry once with the text prefixed by its source and a colon (a message with a second word is never a command). |
| 12 | Failed. Read `retryable` and `unknown_outcome`. | See below. |
| 2 | Usage or config fault. | Never retry; a person fixes the deployment. |
| 1 | Internal error. With no envelope the outcome is unknown. | Never blind-retry. |
| 128+N | A signal arrived before the send started; nothing was sent. | The sender of the signal knows; no envelope. |

For exit 12 the envelope on stdout (with `--json`) decides:

- `retryable` true and `unknown_outcome` false: nothing was sent and sending again is safe (`rate_limited`, `network_error`, `unavailable`). The tool has already retried a 429 after 2 s and 4 s and a connection failure once after 2 s inside its deadline, so back off in the caller for longer than that and cap the attempts.
- `retryable` false and `unknown_outcome` false: nothing was sent and it will fail again until a person changes the config or the credential (`auth_required`, `credential_invalid`, `host_rejected`). Do not retry; surface it once.
- `unknown_outcome` true: the notification may already be on the phone. Never retry blindly, because that can show it twice. A send with a dedupe key makes `outcome_unknown` and `upstream_error` retryable (`retryable` true), because the retry replaces the earlier notification; that holds only while no newer notification with the same key has been sent. Without a key `retryable` is false and the caller records the outcome as possibly sent.
- `wrong_host_response` after a 2xx or a non-HTTP answer is possibly delivered and not retryable: `base_url` is probably not the notify API.

## Retrying with a cap

This script retries an exit 12 only when the envelope says `retryable` is true, backs off 30 s and 60 s, and stops after three attempts. It reads the envelope with `jq`, which is optional elsewhere in this guide but needed here; without `jq` the check fails and the script does not retry, which is the safe direction. The payload is a file, so each attempt sends the same bytes:

<!-- test:retry -->

```bash
#!/bin/bash
# notify-ha-retry NAME PAYLOAD_FILE [DEDUPE_HEX]
name=${1:?usage: notify-ha-retry NAME PAYLOAD_FILE [DEDUPE_HEX]}
file=${2:?payload file}
args=(--file "$file" --json --actor "auto:$name")
[ -n "${3:-}" ] && args+=("--dedupe-key=$3")
attempt=0
while :; do
  attempt=$((attempt + 1))
  out=$(timeout 20 ha-notice send "${args[@]}")
  rc=$?
  case $rc in
    0 | 22) exit 0 ;;
    12) ;;
    *) printf 'ha-notice failed (exit %s): %s\n' "$rc" "$out" >&2; exit "$rc" ;;
  esac
  if [ "$attempt" -ge 3 ] || ! printf '%s' "$out" | jq -e '.error.retryable == true' > /dev/null; then
    printf 'ha-notice failed (exit 12, attempt %s): %s\n' "$attempt" "$out" >&2
    exit 12
  fi
  sleep $((attempt * 30))
done
```

Keep the key stable for the same event and put a sequence number or the level in it when a later notification must not be replaced by a late retry of an earlier one.

## Logs and machine-readable output

- `--json` prints one document on stdout: the result on success, the error envelope on failure, and a failure also prints one `<code>: <message>` line on stderr. Without it, a success prints `sent (<level>, <duration_ms> ms)` on stderr and a failure prints that one line. `--quiet` drops the informational stderr lines, but never the `insecure_http` warning.
- The tool never prints a title, message, link, response body or the token, so its output is safe to put in a log. Put the envelope in your own log with the time and the job name.
- The tool's own log is `log.jsonl` in `.local/state/ha-notice` under the account's home: hashes, counts, the outcome and the exit code. It records outcomes from the point where input is read; exit 2, exit 22, signals and dry runs are not logged.
- `jq` is optional. To read one field of the envelope: `printf '%s' "$out" | jq -r '.error.code'`. Shell-only callers decide by the exit code, which carries most of the meaning, and print the envelope unparsed.

## A health check

A doctor job runs `validate`, which never prompts and never reads stdin:

<!-- test:health -->

```sh
ha-notice validate --probe --json > /dev/null; rc=$?
[ "$rc" = 22 ] && rc=0
[ "$rc" = 0 ] || echo "ha-notice health check failed (exit $rc)" >&2
```

- Plain `validate` checks the config and that the token is set and well formed, with no network call: exit 0 when both pass, 2 for a config fault, 12 for a missing or malformed token.
- `validate --probe` also makes one read-only `GET /api/` that sends no notification. It exits 12 when the host, the path prefix or the token is wrong, and the failed check says which.
- With `enabled: false`, plain `validate` exits 0 and reports `enabled: false`; `--probe` exits 22 without a call. A health check treats 22 as success, and a failed `credential` check of a disabled tool as information.
- `validate --test-message` sends a REAL notification to the phone and is logged like a send. It is for a person to run once by hand and is not for cron or any other automation. `--dry-run` has no effect on `validate`, so `validate --dry-run --test-message` still sends.

Read the checks with `jq` if you have it (optional):

```sh
ha-notice validate --json | jq -r '.checks[] | select(.ok | not) | "\(.name): \(.message)"'
```

## A hook that never blocks

A hook is called by another program (an editor, a build tool, an agent runner), and a notification must never slow it down or fail it. The rules:

- Detach the send: run it in the background, with standard input, output and error all redirected. A caller that captures the hook's output waits for every holder of that pipe, so a background child that keeps it open blocks the caller.
- Start it with `setsid` (Linux; absent on macOS) rather than `nohup`: the tool installs its own SIGHUP handler even when the caller ignored the signal, so `nohup` does not protect a send from a hangup, and a hangup before the send starts is exit 129 with nothing sent.
- Keep the kill timeout (`timeout 20`) so a stuck send is bounded, and always exit 0 from the hook.
- Put the payload in a file that you create with mode 0600 and remove afterwards; do not build JSON from untrusted text in a shell string. Write the text to a file and wrap it with `jq -Rs` (optional; any JSON encoder works), so the text never touches argv.

<!-- test:hook -->

```bash
#!/bin/bash
# hook-notify TEXT_FILE: send the file's text as a warning, in the background; never block, never fail.
text=${1:?usage: hook-notify TEXT_FILE}
log=$HOME/.cache/ha-notice-hook.log
payload=$(mktemp) || exit 0
mkdir -p "$HOME/.cache" || { rm -f "$payload"; exit 0; }
jq -Rs '{title: "Build", message: ., level: "warn"}' < "$text" > "$payload" || { rm -f "$payload"; exit 0; }
setsid bash -c 'trap "rm -f \"\$1\"" EXIT; exec >> "$2" 2>&1; timeout 20 ha-notice send --file "$1" --json --actor auto:hook' hook "$payload" "$log" \
  < /dev/null > /dev/null 2>&1 &
exit 0
```

- `mktemp` creates the file with mode 0600. The child opens the log itself and removes the payload in an `EXIT` trap, so a log that cannot be opened still leaves no payload behind. The log file holds only the tool's stdout and stderr, which never contain message text.
- The token comes from the environment of the process that runs the hook. A hook started by a desktop or a service manager does not have your shell's variables: source the env file in the hook (`set -a; . "$HOME/.config/ha-notice/env"; set +a`) before the `setsid` line.
- A hook must not call the tool again for a failure of the tool itself: that can loop. The tool has no hooks of its own for this reason.
- For a message that is a fixed sentence, skip `jq` and the temp file: `printf '%s\n' '{"message":"nightly backup failed","level":"error"}' > "$payload"`.

## How the examples are tested

The test suite syntax-checks every shell block in this guide (`bash -n` for a `bash` block, `sh -n` for an `sh` block). It runs the wrapper against a stub `ha-notice` that returns exits 0, 1, 2, 12, 20, 22 and 124, and against the real binary with `--dry-run` (exit 0), a config with `enabled: false` (the tool exits 22, the wrapper 0), a bad flag (2) and a missing token (12). It runs the retry script against stubs for a retryable failure, a permanent one, an unknown outcome and the cap, it runs the cron line against a stub job to check that the alias reaches the job and no second copy of the token does, and it runs the env-file commands twice, the health check and the hook against stubs.
