# -*- coding: utf-8 -*-
"""F4: L3 vouching — create, revoke, read graph, paths, caps, rules."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory.timeutil import to_rfc3339
from tests.conftest import http_get, http_post, make_agent, register_agent


def _vouch_body(running, voucher, vouchee, scope="identity", days=60):
    now = running.clock()
    body = {
        "voucher_fingerprint": voucher.fingerprint,
        "vouchee_fingerprint": vouchee.fingerprint,
        "scope": scope,
        "weight": 1,
        "note": "met via booking",
        "created_at": to_rfc3339(now),
        "expires_at": to_rfc3339(now + days * 86400),
    }
    body["signature"] = voucher.sign_payload(body)
    return body


def test_create_and_read_vouch(running):
    a, b = make_agent("A"), make_agent("B")
    register_agent(running.url, a)
    register_agent(running.url, b)
    st, resp = http_post(f"{running.url}/v1/vouches", _vouch_body(running, a, b))
    assert st == 201 and resp["status"] == "active"

    _, graph = http_get(f"{running.url}/v1/agents/{b.fingerprint}/vouches")
    assert len(graph["vouches_in"]) == 1
    assert graph["vouches_in"][0]["voucher_fingerprint"] == a.fingerprint

    _, prof = http_get(f"{running.url}/v1/agents/{b.fingerprint}")
    assert len(prof["trust"]["vouches_in"]) == 1


def test_revoke_vouch(running):
    a, b = make_agent("A"), make_agent("B")
    register_agent(running.url, a)
    register_agent(running.url, b)
    _, resp = http_post(f"{running.url}/v1/vouches", _vouch_body(running, a, b))
    vouch_id = resp["vouch_id"]

    revoke = {"voucher_fingerprint": a.fingerprint, "revoked_at": to_rfc3339(running.clock())}
    revoke["signature"] = a.sign_payload(
        {"voucher_fingerprint": a.fingerprint, "revoked_at": revoke["revoked_at"]}
    )
    import urllib.request
    req = urllib.request.Request(
        f"{running.url}/v1/vouches/{vouch_id}",
        data=__import__("json").dumps(revoke).encode(),
        headers={"Content-Type": "application/json"},
        method="DELETE",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 200
    _, graph = http_get(f"{running.url}/v1/agents/{b.fingerprint}/vouches")
    assert graph["vouches_in"] == []


def test_vouchee_must_be_listed(running):
    a = make_agent("A")
    b = make_agent("B")  # not registered
    register_agent(running.url, a)
    st, resp = http_post(f"{running.url}/v1/vouches", _vouch_body(running, a, b))
    assert st == 404 and resp["error"]["code"] == "VOUCHEE_NOT_LISTED"


def test_vouch_expiry_in_past_rejected(running):
    a, b = make_agent("A"), make_agent("B")
    register_agent(running.url, a)
    register_agent(running.url, b)
    st, resp = http_post(f"{running.url}/v1/vouches", _vouch_body(running, a, b, days=-1))
    assert st == 400 and resp["error"]["code"] == "VOUCH_EXPIRED"


def test_vouch_expiry_too_far_rejected(running):
    a, b = make_agent("A"), make_agent("B")
    register_agent(running.url, a)
    register_agent(running.url, b)
    st, resp = http_post(f"{running.url}/v1/vouches", _vouch_body(running, a, b, days=200))
    assert st == 400 and resp["error"]["code"] == "VOUCH_INVALID"


def test_duplicate_active_vouch_rejected(running):
    a, b = make_agent("A"), make_agent("B")
    register_agent(running.url, a)
    register_agent(running.url, b)
    http_post(f"{running.url}/v1/vouches", _vouch_body(running, a, b, scope="identity"))
    st, resp = http_post(f"{running.url}/v1/vouches", _vouch_body(running, a, b, scope="identity"))
    assert st == 409 and resp["error"]["code"] == "VOUCH_EXISTS"


def test_outgoing_cap_of_ten(running):
    a = make_agent("A")
    register_agent(running.url, a)
    for i in range(running.config.vouch_max_outgoing):
        b = make_agent(f"B{i}")
        register_agent(running.url, b)
        st, _ = http_post(f"{running.url}/v1/vouches", _vouch_body(running, a, b))
        assert st == 201
    extra = make_agent("extra")
    register_agent(running.url, extra)
    st, resp = http_post(f"{running.url}/v1/vouches", _vouch_body(running, a, extra))
    assert st == 429 and resp["error"]["code"] == "VOUCH_LIMIT_REACHED"


def test_trust_paths_depth_two(running):
    a, b, c = make_agent("A"), make_agent("B"), make_agent("C")
    for ag in (a, b, c):
        register_agent(running.url, ag)
    http_post(f"{running.url}/v1/vouches", _vouch_body(running, a, b))
    http_post(f"{running.url}/v1/vouches", _vouch_body(running, b, c))
    _, resp = http_get(
        f"{running.url}/v1/trust/paths?from={a.fingerprint}&to={c.fingerprint}&max_depth=2"
    )
    assert len(resp["paths"]) == 1
    path = resp["paths"][0]
    assert path[0]["voucher_fingerprint"] == a.fingerprint
    assert path[-1]["vouchee_fingerprint"] == c.fingerprint
    # No path within depth 2 to an unrelated agent.
    _, none = http_get(
        f"{running.url}/v1/trust/paths?from={c.fingerprint}&to={a.fingerprint}"
    )
    assert none["paths"] == []
