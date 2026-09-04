# -*- coding: utf-8 -*-
"""F3: L2 domain verification (DNS TXT + HTTPS well-known), server-side."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tests.conftest import StubResolver, http_get, http_post, make_agent, register_agent


@pytest.fixture()
def dns_server(make_server):
    resolver = StubResolver()
    return make_server(resolver=resolver)


def _request_domain(running, agent, domain, method):
    body = {"fingerprint": agent.fingerprint, "domain": domain, "method": method}
    body["signature"] = agent.sign_payload(
        {"fingerprint": agent.fingerprint, "domain": domain, "method": method}
    )
    return http_post(f"{running.url}/v1/verify-domain", body)


def _confirm(running, agent, verification_id):
    body = {"fingerprint": agent.fingerprint, "verification_id": verification_id}
    body["signature"] = agent.sign_payload(
        {"fingerprint": agent.fingerprint, "verification_id": verification_id}
    )
    return http_post(f"{running.url}/v1/verify-domain/confirm", body)


def test_dns_txt_happy_path(dns_server):
    running = dns_server
    agent = make_agent("Euraka", endpoint="https://euraka.example/haap")
    register_agent(running.url, agent)

    st, resp = _request_domain(running, agent, "euraka.example", "dns_txt")
    assert st == 202
    token = resp["token"]
    running.resolver.txt["_haap.euraka.example"] = [f"haap-verify={token}"]

    st2, resp2 = _confirm(running, agent, resp["verification_id"])
    assert st2 == 200
    assert resp2["status"] == "verified"
    assert resp2["endpoint_match"] is True

    # Reflected in the trust block + searchable via domain_verified filter.
    _, prof = http_get(f"{running.url}/v1/agents/{agent.fingerprint}")
    assert prof["trust"]["domain_verified"] is True
    assert prof["trust"]["domain_verification"]["domain"] == "euraka.example"
    _, s = http_get(f"{running.url}/v1/search?domain_verified=true")
    assert s["total"] == 1
    # Status endpoint marks it primary (matches the endpoint host).
    _, status = http_get(f"{running.url}/v1/verify-domain/status?fingerprint={agent.fingerprint}")
    assert status["verifications"][0]["primary"] is True


def test_well_known_happy_path(dns_server):
    running = dns_server
    agent = make_agent("WK", endpoint="https://wk.example/haap")
    register_agent(running.url, agent)
    st, resp = _request_domain(running, agent, "wk.example", "https_well_known")
    assert st == 202
    running.resolver.well_known["wk.example"] = resp["token"]
    st2, resp2 = _confirm(running, agent, resp["verification_id"])
    assert st2 == 200 and resp2["status"] == "verified"


def test_dns_txt_not_found(dns_server):
    running = dns_server
    agent = make_agent("NF", endpoint="https://nf.example/haap")
    register_agent(running.url, agent)
    _, resp = _request_domain(running, agent, "nf.example", "dns_txt")
    st, resp2 = _confirm(running, agent, resp["verification_id"])
    assert st == 422
    assert resp2["error"]["code"] == "DNS_TXT_NOT_FOUND"


def test_domain_endpoint_mismatch(dns_server):
    running = dns_server
    agent = make_agent("MM", endpoint="https://mine.example/haap")
    register_agent(running.url, agent)
    # Verify a domain the endpoint does not live under.
    _, resp = _request_domain(running, agent, "other.example", "dns_txt")
    running.resolver.txt["_haap.other.example"] = [f"haap-verify={resp['token']}"]
    st, resp2 = _confirm(running, agent, resp["verification_id"])
    assert st == 422
    assert resp2["error"]["code"] == "DOMAIN_ENDPOINT_MISMATCH"


def test_verification_token_expires(dns_server):
    running = dns_server
    agent = make_agent("EX", endpoint="https://ex.example/haap")
    register_agent(running.url, agent)
    _, resp = _request_domain(running, agent, "ex.example", "dns_txt")
    running.resolver.txt["_haap.ex.example"] = [f"haap-verify={resp['token']}"]
    running.clock.advance(running.config.domain_token_ttl_s + 1)
    st, resp2 = _confirm(running, agent, resp["verification_id"])
    assert st == 410
    assert resp2["error"]["code"] == "VERIFICATION_EXPIRED"


def test_verification_single_use(dns_server):
    running = dns_server
    agent = make_agent("SU", endpoint="https://su.example/haap")
    register_agent(running.url, agent)
    _, resp = _request_domain(running, agent, "su.example", "dns_txt")
    running.resolver.txt["_haap.su.example"] = [f"haap-verify={resp['token']}"]
    st1, _ = _confirm(running, agent, resp["verification_id"])
    assert st1 == 200
    st2, resp2 = _confirm(running, agent, resp["verification_id"])
    assert st2 == 409
    assert resp2["error"]["code"] == "VERIFICATION_USED"


def test_bad_signature_rejected(dns_server):
    running = dns_server
    agent = make_agent("BS", endpoint="https://bs.example/haap")
    register_agent(running.url, agent)
    body = {"fingerprint": agent.fingerprint, "domain": "bs.example", "method": "dns_txt",
            "signature": "AAAA"}
    st, resp = http_post(f"{running.url}/v1/verify-domain", body)
    assert st == 400 and resp["error"]["code"] == "SIGNATURE_MISMATCH"


def test_pending_verification_limit(dns_server):
    running = dns_server
    agent = make_agent("LIM", endpoint="https://lim.example/haap")
    register_agent(running.url, agent)
    for _ in range(running.config.max_pending_verifications):
        st, _ = _request_domain(running, agent, "lim.example", "dns_txt")
        assert st == 202
    st, resp = _request_domain(running, agent, "lim.example", "dns_txt")
    assert st == 429
    assert resp["error"]["code"] == "VERIFICATION_LIMIT_REACHED"


def test_90_day_expiry_downgrade(dns_server):
    running = dns_server
    agent = make_agent("DG", endpoint="https://dg.example/haap")
    register_agent(running.url, agent)
    _, resp = _request_domain(running, agent, "dg.example", "dns_txt")
    running.resolver.txt["_haap.dg.example"] = [f"haap-verify={resp['token']}"]
    _confirm(running, agent, resp["verification_id"])
    _, prof = http_get(f"{running.url}/v1/agents/{agent.fingerprint}")
    assert prof["trust"]["domain_verified"] is True
    # Keep the entry alive with heartbeats past the 90-day verification TTL.
    from haap_directory.timeutil import to_rfc3339
    for _ in range(120):
        running.clock.advance(running.config.ttl_seconds - 100)
        ts = to_rfc3339(running.clock())
        http_post(f"{running.url}/v1/heartbeat", {
            "fingerprint": agent.fingerprint, "timestamp": ts,
            "signature": agent.sign_nonce(f"heartbeat:{agent.fingerprint}:{ts}")})
    _, prof2 = http_get(f"{running.url}/v1/agents/{agent.fingerprint}")
    assert prof2["trust"]["domain_verified"] is False
