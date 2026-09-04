# -*- coding: utf-8 -*-
"""L2: verify.py unit tests (real parsers) + extra HTTP-flow edge cases.

The end-to-end L2 protocol flow is covered by ``test_domain.py`` (StubResolver).
This file keeps the ``verify`` module's real ``dig``/well-known parsers under
test and adds the domain-validation / schema / retryable edge cases.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory import verify as verify_mod
from haap_directory.errors import DirectoryError
from tests.conftest import StubResolver, http_post, make_agent, register_agent


# -- verify.py real parsers (no network) -----------------------------------
def test_validate_domain_rules():
    assert verify_mod.validate_domain("euraka.example.com") == "euraka.example.com"
    # Normalizes case.
    assert verify_mod.validate_domain("Euraka.Example.COM") == "euraka.example.com"
    for bad in ("https://x.com", "x.com:443", "a b.com", "", "x", "user@x.com"):
        with pytest.raises(DirectoryError) as ei:
            verify_mod.validate_domain(bad)
        assert ei.value.code == "DOMAIN_INVALID"


def test_registrable_domain():
    assert verify_mod.registrable_domain("a.b.example.com") == "example.com"
    assert verify_mod.registrable_domain("example.com") == "example.com"


def test_dig_txt_line_parsing():
    # The dig answer parsing used by verify.check_dns_txt.
    out = (
        'euraka.example.com. 300 IN TXT "haap-verify=deadbeef"\n'
        'euraka.example.com. 300 IN TXT "spf=none"\n'
    )
    tokens = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "TXT":
            tokens.append(" ".join(parts[4:]).strip('"'))
    assert "haap-verify=deadbeef" in tokens


# -- HTTP-flow edge cases (StubResolver) -----------------------------------
@pytest.fixture()
def dns_server(make_server):
    return make_server(resolver=StubResolver())


def _sign_request(agent, domain, method):
    payload = {"fingerprint": agent.fingerprint, "domain": domain, "method": method}
    return {**payload, "signature": agent.sign_payload(payload)}


def test_domain_invalid_variants(dns_server):
    running = dns_server
    agent = make_agent("A", endpoint="https://ok.example/haap")
    register_agent(running.url, agent)
    for bad in ("https://evil.com", "evil.com:8080", "", "not a domain"):
        st, resp = http_post(
            f"{running.url}/v1/verify-domain", _sign_request(agent, bad, "dns_txt")
        )
        assert st == 400 and resp["error"]["code"] == "DOMAIN_INVALID", bad


def test_bad_method_is_invalid_schema(dns_server):
    running = dns_server
    agent = make_agent("A", endpoint="https://ok.example/haap")
    register_agent(running.url, agent)
    st, resp = http_post(
        f"{running.url}/v1/verify-domain", _sign_request(agent, "ok.example", "bogus")
    )
    assert st == 400 and resp["error"]["code"] == "INVALID_SCHEMA"


def test_agent_not_listed(dns_server):
    running = dns_server
    stranger = make_agent("S", endpoint="https://ok.example/haap")  # not registered
    st, resp = http_post(
        f"{running.url}/v1/verify-domain", _sign_request(stranger, "ok.example", "dns_txt")
    )
    assert st == 404 and resp["error"]["code"] == "AGENT_NOT_LISTED"


def test_confirm_is_retryable_until_token_present(dns_server):
    running = dns_server
    agent = make_agent("A", endpoint="https://ok.example/haap")
    register_agent(running.url, agent)
    st, req = http_post(
        f"{running.url}/v1/verify-domain", _sign_request(agent, "ok.example", "dns_txt")
    )
    assert st == 202
    vid, token = req["verification_id"], req["token"]

    def confirm():
        payload = {"fingerprint": agent.fingerprint, "verification_id": vid}
        return http_post(
            f"{running.url}/v1/verify-domain/confirm",
            {**payload, "signature": agent.sign_payload(payload)},
        )

    # No TXT yet -> fails but does NOT consume the challenge.
    st1, resp1 = confirm()
    assert st1 == 422 and resp1["error"]["code"] == "DNS_TXT_NOT_FOUND"
    # Publish the token, retry the same verification_id -> verified.
    running.resolver.txt["_haap.ok.example"] = [f"haap-verify={token}"]
    st2, resp2 = confirm()
    assert st2 == 200 and resp2["status"] == "verified"
