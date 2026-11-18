# Live tests

The live suite in `tests/live/` sends real, marked notifications to the maintainer's own Home Assistant and needs a person to look at the phone. It settles the items of the live-verification checklist (issue #36, [design.md](design.md#live-verification)) and two rows of the design's spike table (`spike-success`, `spike-tag`) that have no checkbox on #36. It never runs in CI or in `make verify`: the `live` marker is excluded by default (`addopts = "-m 'not live'"` in `pyproject.toml`), every test under `tests/live/` gets the marker automatically, and `tests/test_live_harness.py` checks that no live test is collected without `-m live`.

## Safety

These tests send real notifications to a real phone. Run them only against your own instance and your own service.

The opt-in V10 test sends companion-app command words as whole messages, which the tool itself refuses to send. The word list is a sample (`FAMILY_WORDS` in `tests/live/test_live_commands.py`), not everything the companion apps accept: `tts`, `clear_notification`, `clear_badge`, `remove_channel`, `request_location_update`, `update_complications`, `update_widgets`, `command_screen_on` and `kiosk_mode`. Their effects vary by app version and platform and are unverified here. Known or possible effects: `tts` may speak the text aloud, `clear_notification` may clear notifications, `command_screen_on` may wake the screen, and `request_location_update` may make the phone report its location to Home Assistant. The test prints each word with its possible effect in a banner and then counts down (`LIVE_HA_COUNTDOWN` seconds, default 10; Ctrl-C aborts) before the first word.

The command test needs two things. It must be selected explicitly with `-m live_commands` (it skips under `-m live` and under any other expression, so `-m "live and not live_commands"` is not needed), and `LIVE_HA_ALLOW_COMMANDS=1` must be set. Set the opt-in inline for that one command and never export it, so a later routine `-m live` run cannot send a word:

```sh
LIVE_HA_ALLOW_COMMANDS=1 uv run pytest -m live_commands -s -rs
```

The guarded raw helpers are the intended senders and the only way the suite sends outside the tool: `raw_post_notify` refuses a command word (raw or after the tool's sanitizing, in the message or the title), any body key other than `title`, `message` and `data`, and any `data` key other than `tag`, `url` and `clickAction`. The generic raw client is private and refuses any POST to a notify service. Only `send_command_word` can send a command word, and only with the opt-in. The guard protects against accidents; it is not a defence against code that is written to bypass it.

The token is read from the environment only, in the variable named by `LIVE_HA_TOKEN_ENV` (the tool requires the name to match `HA_[A-Z0-9_]{1,60}`). It is never written to a file, passed in argv or printed; the harness keeps it out of failure output (also under `pytest -l`) and fails a test whose tool run printed it. The generated config files hold no token. Tests that use a wrong or unreachable address use a dummy token, so the real token goes to your Home Assistant only. The `LIVE_HA_*` variables belong to the test harness; the tool never reads them.

The tool finds its home from the password database, not from `$HOME`, so a private `HOME` protects nothing; the generated configs set `log: false`, which is what keeps the live runs out of your real state directory (the harness's own inner runs set `HOME` only as a convenience).

The wrong-token test makes several failed authentications in one run (two raw requests, a probe and a send). With `ip_ban_enabled` on your instance this can trigger login-failure notifications or a ban of the runner's IP address; run it from an address you can afford to have banned, or skip it with `-k "not wrong_token"`.

## Run

```sh
read -rs HA_LIVE_TOKEN && export HA_LIVE_TOKEN          # paste a long-lived access token
export LIVE_HA_BASE_URL=https://homeassistant.example:8123
export LIVE_HA_SERVICE=mobile_app_your_phone            # the part after "notify."
export LIVE_HA_TOKEN_ENV=HA_LIVE_TOKEN                  # names the variable that holds the token
uv run pytest -m live -s -rs
```

`-s` is required: the instructions for the person are printed, and a configured live test skips without it. `-rs` lists the skipped tests with their reasons. When no `LIVE_HA_*` variable is set at all, every live test skips with the message `live suite not configured: set ...`. When any is set and the configuration is partly set or invalid (a missing required variable, a token variable that is empty, a name that does not start with `HA_`, a bad pause, countdown or timeout), the live tests fail with the reason, which names variables and never values.

Optional variables:

| Variable | Effect |
|---|---|
| `LIVE_HA_CA_FILE` | Absolute path to a CA bundle or the self-signed certificate; added to every config and enables the self-signed test. |
| `LIVE_HA_ALLOW_INSECURE_HTTP` | `1` allows an `http://` base URL (the token then travels in cleartext). |
| `LIVE_HA_PREFIX_BASE_URL` | A full URL with a path prefix (a reverse proxy); enables the path-prefix test. |
| `LIVE_HA_OTHER_SERVICE` | Another notify service name (for example a persistent notification); enables the other-services test. |
| `LIVE_HA_BLACKHOLE_URL` | Address for the unreachable-host test; default `https://192.0.2.1:8123` (a documentation-only range). Pick one that is dropped, not refused, on your network. It must differ from the base and prefix URLs. |
| `LIVE_HA_TIMEOUT` | The tool's `timeout` for the live configs, in the interface duration grammar (`10`, `1.5s`, `1m`), 1 s to 120 s; default `10s`. |
| `LIVE_HA_PAUSE` | Seconds between notifications, default `5`. |
| `LIVE_HA_COUNTDOWN` | Seconds between the command-word banner and the first word, 0 to 60; default 10. |
| `LIVE_HA_ALLOW_COMMANDS` | `1` enables the V10 command-word test, which also needs `-m live_commands`. Set it inline for one run, never export it. Read the safety section first. |

To run one item, select it by name: `uv run pytest -m live -s -k link_tap`. The command-word test is never part of a `-m live` run; it is run with `LIVE_HA_ALLOW_COMMANDS=1 uv run pytest -m live_commands -s`.

## What each test prints and settles

Every test prints a header with its name, the checklist item it settles and a run id, then `WHAT YOU SHOULD SEE ON THE PHONE` as a numbered list, then `RECORD ON ISSUE #36` with what to write down. Titles and messages carry `ha-notice live test <run id>` so you can find them. A test that sends nothing says so.

| Test | Settles | You look at |
|---|---|---|
| `test_plain_send`, `test_validate_test_message` | spike-success | Two plain notifications, then the fixed-text test message; the raw reply line records the real 200 body. |
| `test_tag_replacement` | spike-tag | One notification showing `SECOND send`, not two. |
| `test_link_tap` | V9 | Three notifications: the tool's (both `url` and `clickAction`), then two raw ones carrying only `data.url` and only `data.clickAction`; tap each on each platform. |
| `test_long_message_through_the_tool`, `test_long_message_raw_api` | V8 | Notifications of 1000, 2000 (cut by the tool), 1000, 10000 and 100000 characters (raw). The run marker is in the title and the message is the counting text alone, so the last visible number is the display limit. The raw test only records on the phone side; its one assertion is the 200 reply. |
| `test_android_markup_look` | V20 | `<b>x</b>` and `<a href=...>y</a>` rendered or literal. |
| `test_probe_body_shape` | V7 | Nothing; records status, content type and body of `GET /api/`. |
| `test_wrong_token_is_401` | wrong-token | Nothing; records status and body of a wrong token (401 or 403) and asserts the tool reports `auth_required` for the probe and the send (`credential_invalid` is only for a missing or malformed token variable). |
| `test_unreachable_host_timeout` | unreachable-host | Nothing; asserts `network_error` with `details.timeout` true within `timeout` plus 3 s. Skips only when the connection is refused at once (under 1 s, not a timeout); a host that answers fails the test. |
| `test_self_signed_through_ca_file` | self-signed | Nothing; the probe passes with `ca_file` and must fail certificate verification without it. Skips (with the reason) if system trust already verifies the certificate. |
| `test_default_ca_paths` | V18 | Nothing; prints the default CA paths and whether each exists and loads, then asserts the system-trust probe: for an https instance with `LIVE_HA_CA_FILE` (self-signed) a pass means system trust rejects the chain, without it a pass means system trust verifies the chain; a failure means this machine's default trust does not match the instance. An http instance skips after printing the paths. |
| `test_path_prefix` | path-prefix | One notification sent through the prefix. |
| `test_other_notify_service` | other-services | Whether the other service accepted and showed the body (record-only: it asserts only that the tool answered with exit 0 or 12). |
| `test_command_word_families` | V10 | Opt-in, `-m live_commands` only. One notification per command word; does the phone act or show text. |

## Record the results

Copy the lines under `RECORD ON ISSUE #36` and what you saw into a comment on issue #36, one comment per run, naming the platform and app versions. For V9 record each of the three variants per platform. `spike-success` and `spike-tag` are rows of the design's spike table, not checkboxes on #36: record them as a result on #36 and update the spike table in the design if they differ. Tick a checklist item only when the interface or code matches the result. A result that differs from the default needs a follow-up issue or an interface change, and a difference from the fake Home Assistant needs a fix in `tests/fake_ha.py`.

## Not covered here

The suite does not exercise signals, `flock` and log rotation on other filesystems, a real 429, 3xx or 1xx answer, or a stalled host that accepts and never answers; those need a host or an operating system that cannot be scripted from here and stay on issue #36 for a manual check. The #25 check that a run exits within `timeout` plus 3 s including the log step also stays manual, because the live configs set `log: false`.

## Testing the suite itself

`tests/test_live_harness.py` runs in `make verify`. Besides the checks that the tests are tagged and never collected by default, it runs the live tests in an inner pytest process against the fake Home Assistant on loopback (with a loopback address that never completes a connection as the blackhole), so the harness and the guarded raw senders are tested without any real host. It also checks that mutated hosts (a healthy host as the blackhole, a wrong token answered 500, a probe that is not `auth_required`) make the inner run fail, and that a failing run with `pytest -l --showlocals` never prints the token.
