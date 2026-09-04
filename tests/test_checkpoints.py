# -*- coding: utf-8 -*-
"""F5: L5 signed checkpoints, verify endpoint, agent audit, response signing."""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory.canonical import canonical_json
from haap_directory.crypto import b64d
from tests.conftest import http_get, make_agent, register_agent


def _get_full(url: str) -> tuple[int, dict, dict]:
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, json.loads(r.read() or b"{}"), dict(r.headers)


def test_head_is_signed_by_directory_key(running):
    register_agent(running.url, make_agent("A"))
    kp = running.server.service.keypair
    status, body, headers = _get_full(f"{running.url}/v1/audit/head")
    assert status == 200
    payload = {"seq": body["seq"], "entry_hash": body["entry_hash"], "ts": body["ts"]}
    assert kp.verify(canonical_json(payload), b64d(body["checkpoint_signature"]))
    # And the whole audit response carries a directory signature header.
    assert kp.verify(canonical_json(body), b64d(headers["X-HAAP-Directory-Signature"]))
    assert headers["X-HAAP-Directory-Fingerprint"] == running.server.service.directory_fingerprint


def test_create_and_list_checkpoints(running):
    register_agent(running.url, make_agent("A"))
    cp = running.server.service.audit.create_checkpoint()
    assert cp["seq"] >= 0
    _, body = http_get(f"{running.url}/v1/audit/checkpoints")
    seqs = [c["seq"] for c in body["checkpoints"]]
    assert cp["seq"] in seqs
    # The stored checkpoint signature verifies against the directory key.
    kp = running.server.service.keypair
    stored = [c for c in body["checkpoints"] if c["seq"] == cp["seq"]][0]
    payload = {"seq": stored["seq"], "entry_hash": stored["entry_hash"], "ts": stored["ts"]}
    assert kp.verify(canonical_json(payload), b64d(stored["signature_b64"]))


def test_maybe_checkpoint_respects_cadence(running):
    audit = running.server.service.audit
    first = audit.maybe_checkpoint(force=True)
    assert first is not None
    # Immediately after, cadence not elapsed -> no new checkpoint.
    assert audit.maybe_checkpoint() is None
    running.clock.advance(running.config.checkpoint_interval_s + 1)
    assert audit.maybe_checkpoint() is not None


def test_verify_endpoint(running):
    for i in range(3):
        register_agent(running.url, make_agent(f"A{i}"))
    _, head = http_get(f"{running.url}/v1/audit/head")
    _, body = http_get(f"{running.url}/v1/audit/verify?seq={head['seq']}")
    assert body["valid"] is True
    assert body["computed_head"] == head["entry_hash"]


def test_agent_audit_is_redacted(running):
    agent = make_agent("A")
    register_agent(running.url, agent)
    _, body = http_get(f"{running.url}/v1/agents/{agent.fingerprint}/audit")
    assert body["fingerprint"] == agent.fingerprint
    assert len(body["entries"]) >= 1
    for e in body["entries"]:
        assert e["fingerprint"] == agent.fingerprint
        assert "detail_hash" in e
        assert "detail" not in e  # never the body, only the hash


def test_shutdown_writes_final_checkpoint(make_server):
    running = make_server()
    register_agent(running.url, make_agent("A"))
    running.server.stop()
    # Reopen the same DB and confirm a checkpoint was persisted on shutdown.
    from haap_directory.store import Store
    store = Store(running.config.db_path, clock=running.clock)
    assert store.latest_checkpoint() is not None
    store.close()
