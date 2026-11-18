# Live tests

The live suite in `tests/live/` sends real, marked notifications to the maintainer's own Home Assistant and needs a person to look at the phone. It settles the items of the live-verification checklist (issue #36, [design.md](design.md#live-verification)). It never runs in CI or in `make verify`: the `live` marker is excluded by default (`addopts = "-m 'not live'"` in `pyproject.toml`), every test under `tests/live/` gets the marker automatically, and `tests/test_live_harness.py` checks that no live test is collected without `-m live`.

## Safety

These tests send real notifications to a real phone. Run them only against your own instance and your own service.

The opt-in V10 test sends companion-app command words (`tts`, `clear_notification`, `request_location_update`, `command_screen_on` and others) as whole messages, which the tool itself refuses to send. A phone may act on them: clear its notifications, speak, wake the screen, report its location. It is skipped even under `-m live` unless `LIVE_HA_ALLOW_COMMANDS=1` is set, it prints the word list in a banner before sending, and its raw sender is the only code that can send a command word.

The token is read from the environment only, in the variable named by `LIVE_HA_TOKEN_ENV` (the tool requires the name to match `HA_[A-Z0-9_]{1,60}`). It is never written to a file, passed in argv or printed. The generated config files hold no token. Tests that use a wrong or unreachable address use a dummy token, so the real token goes to your Home Assistant only. The `LIVE_HA_*` variables belong to the test harness; the tool never reads them.

## Run

```sh
read -rs HA_LIVE_TOKEN && export HA_LIVE_TOKEN          # paste a long-lived access token
export LIVE_HA_BASE_URL=https://homeassistant.example:8123
export LIVE_HA_SERVICE=mobile_app_your_phone            # the part after "notify."
export LIVE_HA_TOKEN_ENV=HA_LIVE_TOKEN                  # names the variable that holds the token
uv run pytest -m live -s -rs
```

`-s` is required: the instructions for the person are printed, and a configured live test skips without it. `-rs` lists the skipped tests with their reasons. Without the three required variables every live test skips with the message `live suite not configured: set ...`.

Optional variables:

| Variable | Effect |
|---|---|
| `LIVE_HA_CA_FILE` | Absolute path to a CA bundle or the self-signed certificate; added to every config and enables the self-signed test. |
| `LIVE_HA_ALLOW_INSECURE_HTTP` | `1` allows an `http://` base URL (the token then travels in cleartext). |
| `LIVE_HA_PREFIX_BASE_URL` | A full URL with a path prefix (a reverse proxy); enables the path-prefix test. |
| `LIVE_HA_OTHER_SERVICE` | Another notify service name (for example a persistent notification); enables the other-services test. |
| `LIVE_HA_BLACKHOLE_URL` | Address for the unreachable-host test; default `https://192.0.2.1:8123` (a documentation-only range). Pick one that is dropped, not refused, on your network. |
| `LIVE_HA_TIMEOUT` | The tool's `timeout` for the live configs; default `10s`. |
| `LIVE_HA_PAUSE` | Seconds between notifications, default `5`. |
| `LIVE_HA_ALLOW_COMMANDS` | `1` enables the V10 command-word test. Read the safety section first. |

To run one item, select it by name: `uv run pytest -m live -s -k link_tap`. The command-word test is run the same way with the opt-in: `LIVE_HA_ALLOW_COMMANDS=1 uv run pytest -m live -s -k command_word`.

## What each test prints and settles

Every test prints a header with its name, the checklist item it settles and a run id, then `WHAT YOU SHOULD SEE ON THE PHONE` as a numbered list, then `RECORD ON ISSUE #36` with what to write down. Titles and messages carry `ha-notice live test <run id>` so you can find them. A test that sends nothing says so.

| Test | Settles | You look at |
|---|---|---|
| `test_plain_send`, `test_validate_test_message` | spike-success | Two plain notifications, then the fixed-text test message; the raw reply line records the real 200 body. |
| `test_tag_replacement` | spike-tag | One notification showing `SECOND send`, not two. |
| `test_link_tap` | V9 | Tap the notification on each platform; does the link open. |
| `test_long_message_through_the_tool`, `test_long_message_raw_api` | V8 | Notifications of 1000, 2000 (cut by the tool), 1000, 10000 and 100000 characters (raw); the text counts up so the last visible number is the display limit. |
| `test_android_markup_look` | V20 | `<b>x</b>` and `<a href=...>y</a>` rendered or literal. |
| `test_probe_body_shape` | V7 | Nothing; records status, content type and body of `GET /api/`. |
| `test_wrong_token_is_401` | wrong-token | Nothing; records status and body of a wrong token (401 or 403) and the tool's two error codes. |
| `test_unreachable_host_timeout` | unreachable-host | Nothing; records the elapsed time against `timeout` plus 3 s. Skips when the connection is refused at once. |
| `test_self_signed_through_ca_file` | self-signed | Nothing; probe with and without `ca_file`. |
| `test_default_ca_paths` | V18 | Nothing; prints the default CA paths and whether system trust verifies the chain. |
| `test_path_prefix` | path-prefix | One notification sent through the prefix. |
| `test_other_notify_service` | other-services | Whether the other service accepted and showed the body. |
| `test_command_word_families` | V10 | Opt-in. One notification per command word; does the phone act or show text. |

## Record the results

Copy the lines under `RECORD ON ISSUE #36` and what you saw into a comment on issue #36, one comment per run, naming the platform and app versions. Tick a checklist item only when the interface or code matches the result. A result that differs from the default needs a follow-up issue or an interface change, and a difference from the fake Home Assistant needs a fix in `tests/fake_ha.py`.

## Not covered here

The suite does not exercise signals, `flock` and log rotation on other filesystems, a real 429, 3xx or 1xx answer, or a stalled host that accepts and never answers; those need a host or an operating system that cannot be scripted from here and stay on issue #36 for a manual check.

## Testing the suite itself

`tests/test_live_harness.py` runs in `make verify`. Besides the checks that the tests are tagged and never collected by default, it runs the live tests in an inner pytest process against the fake Home Assistant on loopback, so the harness and the guarded raw senders are tested without any real host.
