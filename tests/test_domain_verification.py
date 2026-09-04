# -*- coding: utf-8 -*-
"""L2 domain verification (F3, SPEC §3.3 / §4.3).

The DNS and HTTPS checks are stubbed at the ``verify`` module boundary so the
protocol flow (challenge, signature, expiry, endpoint-match, persistence,
trust-block surfacing, audit) is exercised deterministically without network.
A couple of unit tests exercise the real parsers with synthetic dig/HTTP
responses.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory import service as service_mod  # noqa: E402
from haap_directory import verify as verify_mod  # noqa: E402
from haap_directory.errors import DirectoryError  # noqa: E402

from conftest import http_get, http_post, make_agent, register_agent  # noqa: E402


def _listed_agent(running, endpoint=None):
    """Register a fresh agent and return the Agent object."""
    agent = make_agent(endpoint=endpoint) if endpoint else make_agent()
    register_agent(running.url, agent)
    return agent


def _sign(agent, body: bytes) -> str:
    return base64.b64encode(agent.keypair.sign(body)).decode("ascii")


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


@pytest.fixture()
def dns_ok(monkeypatch):
    """Stub the DNS TXT check to always find the token."""
    calls = {}

    def fake(domain, token):
        calls["domain"], calls["token"] = domain, token
        return None

    monkeypatch.setattr(service_mod, "check_dns_txt", fake)
    return calls


@pytest.fixture()
def well_known_ok(monkeypatch):
    calls = {}

    def fake(domain, token):
        calls["domain"], calls["token"] = domain, token
        return None

    monkeypatch.setattr(service_mod, "check_https_well_known", fake)
    return calls


def _request_verification(running, agent, domain, method):
    body = _canonical(
        {"fingerprint": agent.fingerprint, "domain": domain, "method": method}
    )
    return http_post(
        f"{running.url}/v1/verify-domain",
        {
            "fingerprint": agent.fingerprint,
            "domain": domain,
            "method": method,
            "signature": _sign(agent, body),
        },
    )


def _confirm(running, agent, verification_id):
    body = _canonical(
        {"fingerprint": agent.fingerprint, "verification_id": verification_id}
    )
    return http_post(
        f"{running.url}/v1/verify-domain/confirm",
        {
            "fingerprint": agent.fingerprint,
            "verification_id": verification_id,
            "signature": _sign(agent, body),
        },
    )


def test_domain_happy_path_dns_txt(running, dns_ok):
    agent = _listed_agent(running, endpoint="https://euraka.example.com/haap/messages")
    code, resp = _request_verification(running, agent, "euraka.example.com", "dns_txt")
    assert code == 202
    assert resp["domain"] == "euraka.example.com"
    assert resp["method"] == "dns_txt"
    assert len(resp["token"]) >= 32
    assert "_haap.euraka.example.com" in resp["instructions"]

    code, done = _confirm(running, agent, resp["verification_id"])
    assert code == 200
    assert done["status"] == "verified"
    assert done["domain"] == "euraka.example.com"
    assert done["endpoint_match"] is True
    # the stub saw exactly the server-issued token
    assert dns_ok["token"] == resp["token"]

    # trust block now surfaces domain_verified
    code, prof = http_get(f"{running.url}/v1/agents/{agent.fingerprint}")
    assert code == 200
    assert prof["trust"]["domain_verified"] is True
    assert prof["trust"]["domain_verification"]["domain"] == "euraka.example.com"
    assert prof["trust"]["domain_verification"]["primary"] is True

    # public status endpoint
    code, st = http_get(
        f"{running.url}/v1/verify-domain/status?fingerprint={agent.fingerprint}"
    )
    assert code == 200
    assert st["verifications"][0]["domain"] == "euraka.example.com"
    assert st["verifications"][0]["primary"] is True

    # audit recorded the verification
    entries = running.server.service.store.audit_entries()
    assert any(e["event"] == "domain.verified" for e in entries)


def test_domain_well_known_flow(running, well_known_ok):
    agent = _listed_agent(running, endpoint="https://booking.acme.dev/haap")
    code, resp = _request_verification(running, agent, "acme.dev", "https_well_known")
    assert code == 202
    code, done = _confirm(running, agent, resp["verification_id"])
    assert code == 200 and done["status"] == "verified"
    assert well_known_ok["domain"] == "acme.dev"


def test_domain_invalid_rejected(running):
    agent = _listed_agent(running)
    for bad in ("https://evil.com", "evil.com:8080", "", "not a domain"):
        code, resp = _request_verification(running, agent, bad, "dns_txt")
        assert code == 400, bad
        assert resp["error"]["code"] == "DOMAIN_INVALID", bad
    code, resp = _request_verification(running, agent, "ok.example", "bogus_method")
    assert code == 400 and resp["error"]["code"] == "INVALID_SCHEMA"


def test_domain_signature_required(running):
    agent = _listed_agent(running)
    code, resp = http_post(
        f"{running.url}/v1/verify-domain",
        {"fingerprint": agent.fingerprint, "domain": "ok.example",
         "method": "dns_txt", "signature": "AAAA"},
    )
    assert code == 400 and resp["error"]["code"] == "SIGNATURE_MISMATCH"


def test_domain_not_listed_agent(running):
    stranger = make_agent()
    code, resp = _request_verification(running, stranger, "ok.example", "dns_txt")
    assert code == 404 and resp["error"]["code"] == "AGENT_NOT_LISTED"


def test_domain_endpoint_mismatch(running, dns_ok):
    # endpoint on foo.com but verifying bar.com -> rejected
    agent = _listed_agent(running, endpoint="https://foo.com/haap")
    code, resp = _request_verification(running, agent, "bar.com", "dns_txt")
    assert code == 202
    code, done = _confirm(running, agent, resp["verification_id"])
    assert code == 422
    assert done["error"]["code"] == "DOMAIN_ENDPOINT_MISMATCH"


def test_domain_token_not_found(running, monkeypatch):
    def fail(domain, token):
        raise DirectoryError("DNS_TXT_NOT_FOUND")

    monkeypatch.setattr(service_mod, "check_dns_txt", fail)
    agent = _listed_agent(running, endpoint="https://euraka.example.com/haap")
    code, resp = _request_verification(running, agent, "euraka.example.com", "dns_txt")
    assert code == 202
    code, done = _confirm(running, agent, resp["verification_id"])
    assert code == 422 and done["error"]["code"] == "DNS_TXT_NOT_FOUND"
    # confirm is retryable until expiry (challenge NOT consumed)
    monkeypatch.setattr(
        service_mod, "check_dns_txt", lambda d, t: None
    )
    code, done = _confirm(running, agent, resp["verification_id"])
    assert code == 200 and done["status"] == "verified"


def test_domain_expiry_and_90d_downgrade(running, dns_ok):
    agent = _listed_agent(running, endpoint="https://euraka.example.com/haap")
    code, resp = _request_verification(running, agent, "euraka.example.com", "dns_txt")
    assert code == 202
    # let the 30-minute token expire
    running.clock.advance(1801)
    code, done = _confirm(running, agent, resp["verification_id"])
    assert code == 410 and done["error"]["code"] == "VERIFICATION_EXPIRED"


def test_domain_used_challenge_single_use(running, dns_ok):
    agent = _listed_agent(running, endpoint="https://euraka.example.com/haap")
    code, resp = _request_verification(running, agent, "euraka.example.com", "dns_txt")
    code, done = _confirm(running, agent, resp["verification_id"])
    assert code == 200
    # replaying the confirm fails: verification single-use
    code, done2 = _confirm(running, agent, resp["verification_id"])
    assert code == 409 and done2["error"]["code"] == "VERIFICATION_USED"


# -- real parser unit tests (no network) -----------------------------------

def test_dig_parser_finds_token():
    out = (
        "euraka.example.com. 300 IN TXT \"haap-verify=deadbeef\"\n"
        "euraka.example.com. 300 IN TXT \"spf=none\"\n"
    )
    tokens = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "TXT":
            tokens.append(" ".join(parts[4:]).strip('"'))
    assert any(t == "haap-verify=deadbeef" for t in tokens)


def test_validate_domain_rules():
    assert verify_mod.validate_domain("euraka.example.com") == "euraka.example.com"
    for bad in ("https://x.com", "x.com:443", "a b.com", "", "x"):
        with pytest.raises(DirectoryError) as ei:
            verify_mod.validate_domain(bad)
        assert ei.value.code == "DOMAIN_INVALID"


def test_registrable_domain():
    assert verify_mod.registrable_domain("a.b.example.com") == "example.com"
    assert verify_mod.registrable_domain("example.com") == "example.com"
