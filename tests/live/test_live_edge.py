"""Live checks of the Home Assistant edge (issue #31): probe, auth, timeouts, TLS, prefix."""

from __future__ import annotations

import json
import ssl
from pathlib import Path

import pytest

from ha_notice.gateway import RealGateway
from tests.live.checklist import settles
from tests.live.support import (
    LiveConfig,
    banner,
    marker,
    out,
    raw_get,
    raw_post_notify,
    record,
    see,
    send,
    trust_location_state,
    validate,
    write_config,
)

# The probe check message for a certificate or trust failure (network_error with details.tls
# true; the probe prints the code and the fixed hint, not the details).
TLS_FAILURE = "network_error; check ca_file"
DUMMY_TOKEN = "ha-notice-live-dummy-token-not-a-credential"


@settles("V7")
def test_probe_body_shape(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """``validate --probe`` against the real instance, plus the raw ``GET /api/`` body shape."""
    banner("validate --probe", ("V7",), run_id)
    config = write_config(workdir, live)
    run = validate(config, live, "--probe")
    out(f"tool result: {run.describe()}")
    envelope = run.envelope or {}
    assert run.code == 0 and envelope.get("probe") == {"api_ok": True}, run.describe()
    raw = raw_get(live, "/api/")
    out(f"raw GET /api/: {raw.describe(live.token)}")
    shape = "not JSON"
    try:
        value = json.loads(raw.body)
        shape = type(value).__name__ + (
            f" with keys {sorted(value)}" if isinstance(value, dict) else ""
        )
    except ValueError:
        pass
    out(f"parsed body: {shape}")
    assert raw.status == 200
    see("Nothing: the probe sends no notification.")
    record("the raw GET /api/ line above (status, content type, body) and the parsed shape")


@settles("wrong-token")
def test_wrong_token_is_401(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """A deliberately wrong token: status and body from the host, and the tool's verdict.

    Records the host's reply and asserts the tool reports ``auth_required`` for both the probe
    and the send. Several failed authentications are made in one run.
    """
    banner("wrong token", ("wrong-token",), run_id)
    config = write_config(workdir, live)
    get_reply = raw_get(live, "/api/", token=DUMMY_TOKEN)
    out(f"raw GET /api/ with a wrong token: {get_reply.describe(DUMMY_TOKEN)}")
    raw_post = raw_post_notify(live, {"message": marker(run_id, "wrong token")}, token=DUMMY_TOKEN)
    out(f"raw POST notify with a wrong token: {raw_post.describe(DUMMY_TOKEN)}")
    probe = validate(config, live, "--probe", token=DUMMY_TOKEN)
    out(f"tool probe with a wrong token: {probe.describe()}")
    sent = send(config, live, {"message": marker(run_id, "wrong token")}, token=DUMMY_TOKEN)
    out(f"tool send with a wrong token: {sent.describe()}")
    assert get_reply.status in (401, 403) and raw_post.status in (401, 403)
    # a rejected (not missing or malformed) token is auth_required; credential_invalid is for a
    # token variable that is empty or malformed, which is not this case
    failed = probe.failed_check()
    assert probe.code == 12 and failed is not None, probe.describe()
    assert failed[0] == "probe" and failed[1].startswith("auth_required"), probe.describe()
    assert sent.code == 12 and sent.error().get("code") == "auth_required", sent.describe()
    see("Nothing: a wrong token must deliver no notification. If one appears, report it.")
    record(
        "status and body of the wrong-token GET and POST above (401 or 403, body text), and "
        "the two tool error codes (auth_required with details.http_status; credential_invalid is "
        "only for a missing or malformed token variable)"
    )


@settles("unreachable-host")
def test_unreachable_host_timeout(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """A blackholed address: ``network_error`` with ``details.timeout`` true within timeout + 3 s.

    Skips only when the connection is refused at once (under 1 s, not a timeout); any other
    outcome, such as a host that answers, fails. A dummy token is used so the real token goes to
    no other address.
    """
    banner("unreachable host", ("unreachable-host",), run_id)
    config = write_config(
        workdir, live, base_url=live.blackhole_url, use_ca_file=False, name="blackhole.yaml"
    )
    run = send(config, live, {"message": marker(run_id, "unreachable")}, token=DUMMY_TOKEN)
    out(f"tool result after {run.elapsed:.1f} s (timeout {live.timeout}): {run.describe()}")
    details = run.error().get("details")
    timed_out = isinstance(details, dict) and details.get("timeout") is True
    if run.elapsed < 1.0 and not timed_out and run.error().get("code") == "network_error":
        pytest.skip(
            "the environment refused the connection at once (no route or egress rule): "
            "no blackhole behaviour to time; try another LIVE_HA_BLACKHOLE_URL"
        )
    assert run.code == 12 and run.error().get("code") == "network_error", run.describe()
    assert timed_out, f"the failure is not a timeout: {run.describe()}"
    limit = live.timeout_seconds + 3.0
    assert run.elapsed <= limit, f"took {run.elapsed:.1f} s, more than timeout + 3 s"
    see("Nothing: nothing is delivered.")
    record(
        "elapsed seconds and the error code above (design: bounded by timeout and connect_timeout)"
    )


@settles("self-signed")
def test_self_signed_through_ca_file(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """Needs LIVE_HA_CA_FILE: the probe passes with ``ca_file`` and fails certificate
    verification (``network_error``, the ``check ca_file`` hint) without it; if system trust already
    verifies the certificate the test skips, since there is nothing self-signed to show."""
    banner("self-signed certificate", ("self-signed",), run_id)
    if not live.ca_file or not live.base_url.startswith("https://"):
        pytest.skip("not configured: needs an https LIVE_HA_BASE_URL and LIVE_HA_CA_FILE")
    with_ca = validate(write_config(workdir, live), live, "--probe")
    out(f"probe with ca_file: {with_ca.describe()}")
    assert with_ca.code == 0, with_ca.describe()
    bare = write_config(workdir, live, use_ca_file=False, name="no-ca.yaml")
    without = validate(bare, live, "--probe")
    out(f"probe without ca_file: {without.describe()}")
    if without.code == 0:
        pytest.skip(
            "system trust already verifies this certificate: nothing to show without ca_file"
        )
    assert without.code == 12 and without.failed_check() == ("probe", TLS_FAILURE), (
        without.describe()
    )
    see("Nothing: the probe sends no notification.")
    record(
        "the certificate shape (RSA or EC, SAN IP or DNS, CA:TRUE or not) and both results above"
    )


@settles("V18")
def test_default_ca_paths(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """What this Python and the tool consider default trust, and whether the chain verifies.

    Prints whether each default CA location exists and loads. For an https instance the outcome
    is the system-trust probe: with ``LIVE_HA_CA_FILE`` set (a self-signed instance) it passes
    when system trust rejects the chain (``tls`` true), otherwise it passes when system trust
    verifies it. A failure means the default trust of this machine does not match the instance.
    An http instance skips after printing the locations.
    """
    banner("default CA paths", ("V18",), run_id)
    paths = ssl.get_default_verify_paths()
    candidates = RealGateway().ca_candidates()
    out(f"ssl.get_default_verify_paths(): cafile={paths.cafile!r} capath={paths.capath!r}")
    out(f"  openssl_cafile={paths.openssl_cafile!r} openssl_capath={paths.openssl_capath!r}")
    out(
        f"gateway.ca_candidates(): cafile {candidates.cafile!r}: "
        f"{trust_location_state(candidates.cafile, directory=False)}"
    )
    out(
        f"  capath {candidates.capath!r}: {trust_location_state(candidates.capath, directory=True)}"
    )
    for fallback in candidates.fallback_files:
        out(f"  fallback {fallback!r}: {trust_location_state(fallback, directory=False)}")
    if not live.base_url.startswith("https://"):
        see("Nothing: no notification is sent.")
        record("the CA location lines above for this OS and Python")
        pytest.skip("http LIVE_HA_BASE_URL: no TLS chain to verify; the location lines are printed")
    bare = write_config(workdir, live, use_ca_file=False, name="system-trust.yaml")
    run = validate(bare, live, "--probe")
    out(f"probe with system trust only: {run.describe()}")
    if live.ca_file:  # a self-signed instance: system trust must NOT verify it
        assert run.code == 12 and run.failed_check() == ("probe", TLS_FAILURE), run.describe()
    else:  # a publicly trusted chain: system trust must verify it
        assert run.code == 0, run.describe()
    see("Nothing: no notification is sent.")
    record("the lines above for this OS and Python, and whether system trust verifies HA's chain")


@settles("path-prefix")
def test_path_prefix(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """Needs LIVE_HA_PREFIX_BASE_URL: a reverse proxy that serves Home Assistant under a prefix."""
    banner("path prefix", ("path-prefix",), run_id)
    if not live.prefix_base_url:
        pytest.skip("not configured: set LIVE_HA_PREFIX_BASE_URL to a URL with a path prefix")
    config = write_config(workdir, live, base_url=live.prefix_base_url, name="prefix.yaml")
    probe = validate(config, live, "--probe")
    out(f"probe through the prefix: {probe.describe()}")
    assert probe.code == 0, probe.describe()
    title = marker(run_id, "prefix")
    run = send(config, live, {"title": title, "message": "sent through a path prefix"})
    out(f"send through the prefix: {run.describe()}")
    assert run.code == 0, run.describe()
    see(f"One notification titled '{title}', text 'sent through a path prefix'.")
    record("probe and send results through the prefix (a prefix-stripping proxy is assumed)")


@settles("other-services")
def test_other_notify_service(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """Needs LIVE_HA_OTHER_SERVICE: does a non-companion notify service accept the same body?"""
    banner("other notify service", ("other-services",), run_id)
    if not live.other_service:
        pytest.skip("not configured: set LIVE_HA_OTHER_SERVICE (e.g. a persistent notification)")
    config = write_config(workdir, live, service=live.other_service, name="other.yaml")
    title = marker(run_id, "other service")
    run = send(config, live, {"title": title, "message": "same body, another service"})
    out(f"send to the other service: {run.describe()}")
    assert run.envelope is not None and run.code in (0, 12), run.describe()
    see(
        f"Where that service shows notifications (for a persistent notification: the bell in "
        f"the Home Assistant sidebar): one titled '{title}' with the text "
        "'same body, another service', or nothing.",
    )
    record("accepted or rejected (the result line above) and whether it displayed")
