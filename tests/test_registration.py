# -*- coding: utf-8 -*-
"""F1: proof-of-endpoint registration, rejection cases, update vs fresh."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory.crypto import KeyPair
from tests.conftest import http_get, http_post, make_agent, register_agent


def _submit(url, agent, **over):
    manifest = over.pop("manifest", agent.manifest())
    pub = over.pop("public_key_b64", agent.public_key_b64)
    sig = over.pop("manifest_signature", agent.sign_manifest(manifest))
    return http_post(
        f"{url}/v1/register",
        {"manifest": manifest, "public_key_b64": pub, "manifest_signature": sig},
    )


def test_happy_path_register_search_profile(running):
    agent = make_agent("Peluqueria Euraka")
    resp = register_agent(running.url, agent)
    assert resp["status"] == "registered"
    assert resp["agent_url"] == f"/v1/agents/{agent.fingerprint}"

    status, found = http_get(f"{running.url}/v1/search?capability=caldav")
    assert status == 200
    assert found["total"] == 1
    assert found["results"][0]["manifest"]["agent"]["fingerprint"] == agent.fingerprint
    assert "trust" in found["results"][0]

    status, profile = http_get(f"{running.url}/v1/agents/{agent.fingerprint}")
    assert status == 200
    assert profile["manifest"]["agent"]["fingerprint"] == agent.fingerprint
    assert profile["trust"]["endpoint_proof_at"] is not None


def test_bad_manifest_signature_rejected(running):
    agent = make_agent()
    fake = base64.b64encode(b"x" * 64).decode()
    status, resp = _submit(running.url, agent, manifest_signature=fake)
    assert status == 400
    assert resp["error"]["code"] == "SIGNATURE_MISMATCH"


def test_fingerprint_key_mismatch_rejected(running):
    agent = make_agent()
    other = KeyPair.generate()
    status, resp = _submit(
        running.url, agent, public_key_b64=other.public_key_b64()
    )
    assert status == 400
    assert resp["error"]["code"] == "FINGERPRINT_MISMATCH"


def test_forbidden_field_rejected(running):
    agent = make_agent()
    manifest = agent.manifest(nonce="should-not-be-here")
    status, resp = _submit(
        running.url, agent, manifest=manifest,
        manifest_signature=agent.sign_manifest(manifest),
    )
    assert status == 400
    assert resp["error"]["code"] == "FORBIDDEN_FIELD"


def test_float_price_rejected(running):
    agent = make_agent()
    manifest = agent.manifest(services=[{"id": "corte", "price": 15.0}])
    status, resp = _submit(
        running.url, agent, manifest=manifest,
        manifest_signature=agent.sign_manifest(manifest),
    )
    assert status == 400
    assert resp["error"]["code"] == "FLOAT_FORBIDDEN"


def test_malformed_json_rejected(running):
    import urllib.request

    req = urllib.request.Request(
        f"{running.url}/v1/register",
        data=b"{not json",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=5)
        assert False, "expected an HTTP error"
    except urllib.error.HTTPError as e:
        assert e.code == 400
        import json

        assert json.loads(e.read())["error"]["code"] == "INVALID_JSON"


def test_endpoint_without_scheme_rejected(running):
    agent = make_agent(endpoint="ftp://nope.example/x")
    manifest = agent.manifest()
    status, resp = _submit(
        running.url, agent, manifest=manifest,
        manifest_signature=agent.sign_manifest(manifest),
    )
    assert status == 400
    assert resp["error"]["code"] == "ENDPOINT_INVALID"


def test_endpoint_with_query_rejected(running):
    agent = make_agent(endpoint="https://ok.example/haap?x=1")
    manifest = agent.manifest()
    status, resp = _submit(
        running.url, agent, manifest=manifest,
        manifest_signature=agent.sign_manifest(manifest),
    )
    assert status == 400
    assert resp["error"]["code"] == "ENDPOINT_INVALID"


def test_oversized_manifest_rejected(running):
    agent = make_agent()
    big = "x" * (running.config.max_manifest_bytes + 10)
    manifest = agent.manifest(agent={"description": big})
    status, resp = _submit(
        running.url, agent, manifest=manifest,
        manifest_signature=agent.sign_manifest(manifest),
    )
    assert status == 413
    assert resp["error"]["code"] == "MANIFEST_TOO_LARGE"


def test_challenge_expired(running):
    agent = make_agent()
    _, resp = _submit(running.url, agent)
    running.clock.advance(running.config.challenge_ttl_s + 1)
    proof = agent.sign_nonce(resp["nonce"])
    status, resp2 = http_post(
        f"{running.url}/v1/register/complete",
        {"challenge_id": resp["challenge_id"], "fingerprint": agent.fingerprint,
         "endpoint_proof": proof},
    )
    assert status == 410
    assert resp2["error"]["code"] == "CHALLENGE_EXPIRED"


def test_challenge_reuse_rejected(running):
    agent = make_agent()
    _, resp = _submit(running.url, agent)
    proof = agent.sign_nonce(resp["nonce"])
    body = {"challenge_id": resp["challenge_id"], "fingerprint": agent.fingerprint,
            "endpoint_proof": proof}
    status1, _ = http_post(f"{running.url}/v1/register/complete", body)
    assert status1 == 201
    status2, resp2 = http_post(f"{running.url}/v1/register/complete", body)
    assert status2 == 409
    assert resp2["error"]["code"] == "CHALLENGE_USED"


def test_proof_signed_by_wrong_key_not_listed(running):
    agent = make_agent()
    _, resp = _submit(running.url, agent)
    impostor = KeyPair.generate()
    bad_proof = base64.b64encode(
        impostor.sign(resp["nonce"].encode("ascii"))
    ).decode()
    status, resp2 = http_post(
        f"{running.url}/v1/register/complete",
        {"challenge_id": resp["challenge_id"], "fingerprint": agent.fingerprint,
         "endpoint_proof": bad_proof},
    )
    assert status == 400
    assert resp2["error"]["code"] == "PROOF_INVALID"
    # Not listed.
    status3, _ = http_get(f"{running.url}/v1/agents/{agent.fingerprint}")
    assert status3 == 404


def test_public_key_mismatch_between_register_and_complete(running):
    agent = make_agent()
    _, resp = _submit(running.url, agent)
    other = KeyPair.generate()
    status, resp2 = http_post(
        f"{running.url}/v1/register/complete",
        {"challenge_id": resp["challenge_id"], "fingerprint": agent.fingerprint,
         "endpoint_proof": agent.sign_nonce(resp["nonce"]),
         "public_key_b64": other.public_key_b64()},
    )
    assert status == 400
    assert resp2["error"]["code"] == "KEY_MISMATCH"


def test_directory_full(running_full):
    running = running_full
    a1 = make_agent("A1")
    assert register_agent(running.url, a1)["status"] == "registered"
    a2 = make_agent("A2")
    status, resp = _submit(running.url, a2)
    assert status == 503
    assert resp["error"]["code"] == "DIRECTORY_FULL"


def test_reregister_live_is_update_not_duplicate(running):
    agent = make_agent()
    register_agent(running.url, agent)
    register_agent(running.url, agent)
    assert running.server.service.store.count_live() == 1


def test_reregister_after_expiry_is_fresh(running):
    agent = make_agent()
    register_agent(running.url, agent)
    running.clock.advance(running.config.ttl_seconds + 1)
    # Expired now.
    status, _ = http_get(f"{running.url}/v1/agents/{agent.fingerprint}")
    assert status == 404
    # Fresh registration works and re-lists.
    r2 = register_agent(running.url, agent)
    assert r2["status"] == "registered"
    assert running.server.service.store.count_live() == 1
