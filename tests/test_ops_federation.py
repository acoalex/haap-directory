# -*- coding: utf-8 -*-
"""F6: /metrics, rate-limit flood (429 + Retry-After), mirror federation."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory import mirror
from tests.conftest import http_get, make_agent, register_agent


def _submit_body(agent):
    manifest = agent.manifest()
    return {
        "manifest": manifest,
        "public_key_b64": agent.public_key_b64,
        "manifest_signature": agent.sign_manifest(manifest),
    }


def _raw_post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


def test_metrics_endpoint(running):
    register_agent(running.url, make_agent("A"))
    with urllib.request.urlopen(f"{running.url}/metrics", timeout=5) as r:
        text = r.read().decode()
    assert "haapd_agents_listed 1" in text
    assert "haapd_audit_seq" in text
    assert "haapd_ops_total" in text


def test_register_rate_limit_returns_429_with_retry_after(make_server):
    running = make_server(rate_register_per_hour=2)
    codes = []
    for i in range(3):
        status, headers = _raw_post(f"{running.url}/v1/register", _submit_body(make_agent(f"A{i}")))
        codes.append((status, headers))
    assert codes[0][0] == 202
    assert codes[1][0] == 202
    assert codes[2][0] == 429
    assert "Retry-After" in codes[2][1]


def test_rejection_counted_in_metrics(make_server):
    running = make_server(rate_register_per_hour=1)
    _raw_post(f"{running.url}/v1/register", _submit_body(make_agent("A")))
    _raw_post(f"{running.url}/v1/register", _submit_body(make_agent("B")))  # 429
    with urllib.request.urlopen(f"{running.url}/metrics", timeout=5) as r:
        text = r.read().decode()
    assert 'haapd_rejections_total{code="RATE_LIMITED"}' in text


def test_mirror_reproduces_head(running):
    for i in range(3):
        register_agent(running.url, make_agent(f"A{i}"))
    result = mirror.ingest_chain(running.url)
    assert result["verified"] is True
    assert result["matches_served_head"] is True
    _, head = http_get(f"{running.url}/v1/audit/head")
    assert result["seq"] == head["seq"]
    assert result["entry_hash"] == head["entry_hash"]
