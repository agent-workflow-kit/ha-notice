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
    raw_request,
    record,
    see,
    send,
    validate,
    write_config,
)

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
    raw = raw_request(live, "GET", "/api/")
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
    """A deliberately wrong token: status and body from the host, and the tool's verdict."""
    banner("wrong token", ("wrong-token",), run_id)
    config = write_config(workdir, live)
    raw_get = raw_request(live, "GET", "/api/", token=DUMMY_TOKEN)
    out(f"raw GET /api/ with a wrong token: {raw_get.describe(DUMMY_TOKEN)}")
    notify = f"/api/services/notify/{live.service}"
    raw_post = raw_request(
        live, "POST", notify, body={"message": marker(run_id, "wrong token")}, token=DUMMY_TOKEN
    )
    out(f"raw POST notify with a wrong token: {raw_post.describe(DUMMY_TOKEN)}")
    probe = validate(config, live, "--probe", token=DUMMY_TOKEN)
    out(f"tool probe with a wrong token: {probe.describe()}")
    sent = send(config, live, {"message": marker(run_id, "wrong token")}, token=DUMMY_TOKEN)
    out(f"tool send with a wrong token: {sent.describe()}")
    assert raw_get.status in (401, 403) and raw_post.status in (401, 403)
    assert probe.code == 12 and sent.code == 12
    see("Nothing: a wrong token must deliver no notification. If one appears, report it.")
    record(
        "status and body of the wrong-token GET and POST above (401 or 403, body text), and "
        "the two tool error codes (design default: any 401 is credential_invalid for send)"
    )


@settles("unreachable-host")
def test_unreachable_host_timeout(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """A blackholed address: the run must end within the deadline plus 3 s.

    A dummy token is used so the real token goes to no other address.
    """
    banner("unreachable host", ("unreachable-host",), run_id)
    config = write_config(
        workdir, live, base_url=live.blackhole_url, use_ca_file=False, name="blackhole.yaml"
    )
    run = send(config, live, {"message": marker(run_id, "unreachable")}, token=DUMMY_TOKEN)
    out(f"tool result after {run.elapsed:.1f} s (timeout {live.timeout}): {run.describe()}")
    details = run.error().get("details")
    refused_at_once = (
        run.code == 12
        and run.error().get("code") == "network_error"
        and isinstance(details, dict)
        and details.get("timeout") is False
    )
    if refused_at_once:
        pytest.skip(
            "the environment refused the connection at once (no route or egress rule): "
            "no blackhole behaviour to time; try another LIVE_HA_BLACKHOLE_URL"
        )
    limit = float(live.timeout.rstrip("s")) + 3.0
    assert run.code == 12, run.describe()
    assert run.elapsed <= limit, f"took {run.elapsed:.1f} s, more than timeout + 3 s"
    see("Nothing: nothing is delivered.")
    record(
        "elapsed seconds and the error code above (design: bounded by timeout and connect_timeout)"
    )


@settles("self-signed")
def test_self_signed_through_ca_file(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """Needs LIVE_HA_CA_FILE: the real self-signed certificate works only through ``ca_file``."""
    banner("self-signed certificate", ("self-signed",), run_id)
    if not live.ca_file or not live.base_url.startswith("https://"):
        pytest.skip("not configured: needs an https LIVE_HA_BASE_URL and LIVE_HA_CA_FILE")
    with_ca = validate(write_config(workdir, live), live, "--probe")
    out(f"probe with ca_file: {with_ca.describe()}")
    assert with_ca.code == 0, with_ca.describe()
    bare = write_config(workdir, live, use_ca_file=False, name="no-ca.yaml")
    without = validate(bare, live, "--probe")
    out(f"probe without ca_file (informational): {without.describe()}")
    see("Nothing: the probe sends no notification.")
    record(
        "the certificate shape (RSA or EC, SAN IP or DNS, CA:TRUE or not) and both results above"
    )


@settles("V18")
def test_default_ca_paths(live: LiveConfig, run_id: str, workdir: Path) -> None:
    """What this Python and the tool consider default trust, and whether the chain verifies."""
    banner("default CA paths", ("V18",), run_id)
    paths = ssl.get_default_verify_paths()
    candidates = RealGateway().ca_candidates()
    out(f"ssl.get_default_verify_paths(): cafile={paths.cafile!r} capath={paths.capath!r}")
    out(f"  openssl_cafile={paths.openssl_cafile!r} openssl_capath={paths.openssl_capath!r}")
    out(f"gateway.ca_candidates(): {candidates}")
    assert candidates.fallback_files, "the fixed fallback list is empty"
    if live.base_url.startswith("https://"):
        bare = write_config(workdir, live, use_ca_file=False, name="system-trust.yaml")
        run = validate(bare, live, "--probe")
        out(f"probe with system trust only: {run.describe()}")
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
