# -*- coding: utf-8 -*-
"""F2: search semantics, heartbeat (v1 + legacy), expiry with injected clock."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory.timeutil import to_rfc3339
from tests.conftest import http_get, http_post, make_agent, register_agent


def _register_with(running, name, **agent_fields):
    agent = make_agent(name)
    manifest = agent.manifest(**agent_fields)
    _, resp = http_post(
        f"{running.url}/v1/register",
        {"manifest": manifest, "public_key_b64": agent.public_key_b64,
         "manifest_signature": agent.sign_manifest(manifest)},
    )
    http_post(
        f"{running.url}/v1/register/complete",
        {"challenge_id": resp["challenge_id"], "fingerprint": agent.fingerprint,
         "endpoint_proof": agent.sign_nonce(resp["nonce"]),
         "public_key_b64": agent.public_key_b64},
    )
    return agent


def test_search_multiword_q_is_and(running):
    _register_with(
        running, "Euraka",
        agent={"speciality": "citas-peluqueria", "description": "peluqueria en Vitoria"},
    )
    # Both words present -> match.
    _, both = http_get(f"{running.url}/v1/search?q=peluqueria%20vitoria")
    assert both["total"] == 1
    # One word absent -> no match (AND semantics).
    _, missing = http_get(f"{running.url}/v1/search?q=peluqueria%20madrid")
    assert missing["total"] == 0


def test_search_geo_radius_include_exclude(running):
    # Vitoria-Gasteiz in integer micro-degrees.
    _register_with(
        running, "Local",
        agent={"geo": {"lat_microdeg": 42846700, "lon_microdeg": -2671600}},
    )
    _, near = http_get(f"{running.url}/v1/search?geo=42.85,-2.67,25")
    assert near["total"] == 1
    _, far = http_get(f"{running.url}/v1/search?geo=40.4168,-3.7038,25")
    assert far["total"] == 0


def test_search_excludes_agents_without_geo_when_geo_filter(running):
    _register_with(running, "NoGeo")  # no geo in manifest
    _, resp = http_get(f"{running.url}/v1/search?geo=42.85,-2.67,25")
    assert resp["total"] == 0


def test_search_pagination_and_total(running):
    for i in range(5):
        _register_with(running, f"Agent{i}")
    _, page = http_get(f"{running.url}/v1/search?limit=2&offset=0")
    assert page["total"] == 5
    assert len(page["results"]) == 2
    assert page["limit"] == 2
    _, page2 = http_get(f"{running.url}/v1/search?limit=2&offset=4")
    assert len(page2["results"]) == 1


def test_search_limit_clamped_to_100(running):
    _register_with(running, "One")
    _, resp = http_get(f"{running.url}/v1/search?limit=9999")
    assert resp["limit"] == 100


def test_empty_results_shape(running):
    _, resp = http_get(f"{running.url}/v1/search?capability=nothing")
    assert resp == {
        "results": [],
        "total": 0,
        "limit": 20,
        "offset": 0,
        "directory_fingerprint": resp["directory_fingerprint"],
    }


def test_heartbeat_v1_renews_ttl(running):
    agent = make_agent()
    register_agent(running.url, agent)
    running.clock.advance(running.config.ttl_seconds - 100)  # still alive
    ts = to_rfc3339(running.clock())
    sig = agent.sign_nonce(f"heartbeat:{agent.fingerprint}:{ts}")
    status, resp = http_post(
        f"{running.url}/v1/heartbeat",
        {"fingerprint": agent.fingerprint, "timestamp": ts, "signature": sig},
    )
    assert status == 200 and resp["status"] == "ok"
    # After renewal, advancing another (ttl - 100) still finds it alive.
    running.clock.advance(running.config.ttl_seconds - 100)
    s2, _ = http_get(f"{running.url}/v1/agents/{agent.fingerprint}")
    assert s2 == 200


def test_heartbeat_stale_timestamp_rejected(running):
    agent = make_agent()
    register_agent(running.url, agent)
    ts = to_rfc3339(running.clock() - 10_000)  # far outside ±300 s
    sig = agent.sign_nonce(f"heartbeat:{agent.fingerprint}:{ts}")
    status, resp = http_post(
        f"{running.url}/v1/heartbeat",
        {"fingerprint": agent.fingerprint, "timestamp": ts, "signature": sig},
    )
    assert status == 400
    assert resp["error"]["code"] == "STALE_TIMESTAMP"


def test_heartbeat_unknown_never_confirms(running):
    ts = to_rfc3339(running.clock())
    status, resp = http_post(
        f"{running.url}/v1/heartbeat",
        {"fingerprint": "HF-deadbeefdeadbeef", "timestamp": ts, "signature": "AAAA"},
    )
    assert status == 404
    assert resp["error"]["code"] == "UNKNOWN_OR_EXPIRED"


def test_legacy_unsigned_heartbeat(running):
    agent = make_agent()
    register_agent(running.url, agent)
    status, resp = http_post(f"{running.url}/heartbeat", {"fingerprint": agent.fingerprint})
    assert status == 200 and resp["status"] == "ok"


def test_expiry_pruned_on_read_with_injected_clock(running):
    agent = make_agent()
    register_agent(running.url, agent)
    assert running.server.service.store.count_live() == 1
    running.clock.advance(running.config.ttl_seconds + 5)
    # Lazy prune on read.
    status, _ = http_get(f"{running.url}/v1/agents/{agent.fingerprint}")
    assert status == 404
    assert running.server.service.store.count_live() == 0


def test_expiry_pruned_on_startup(make_server):
    running = make_server()
    agent = make_agent()
    register_agent(running.url, agent)
    db_path = running.config.db_path
    running.clock.advance(running.config.ttl_seconds + 5)
    # Restart a fresh server on the same DB (same shared clock, now advanced).
    restarted = make_server(db_path=db_path)
    assert restarted.server.service.store.count_live() == 0
