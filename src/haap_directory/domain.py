# -*- coding: utf-8 -*-
"""L2 — domain / business verification (SPEC §3.3, §4.3).

Proves the key holder controls a domain, via a directory-performed DNS TXT
lookup at ``_haap.<domain>`` or an HTTPS well-known fetch. This is a *signal*
(`domain_verified`), never "verified business" and never KYC.
"""

from __future__ import annotations

import secrets
from typing import Optional
from urllib.parse import urlsplit

from .config import DirectoryConfig
from .errors import DirectoryError
from .resolver import Resolver, SystemResolver
from .signing import subset, verify_over
from .store import Store, load_manifest_json
from .timeutil import Clock, system_clock, to_rfc3339
from .verify import validate_domain  # dig-based checker's domain validator

_METHODS = ("dns_txt", "https_well_known")


def endpoint_host(manifest: dict) -> str:
    endpoint = (manifest.get("agent") or {}).get("endpoint", "")
    return (urlsplit(endpoint).hostname or "").lower()


def host_under_domain(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


class DomainService:
    """Server-side domain-control verification and its trust signal."""

    def __init__(
        self,
        store: Store,
        config: DirectoryConfig,
        clock: Clock = system_clock,
        resolver: Optional[Resolver] = None,
    ):
        self.store = store
        self.config = config
        self._clock = clock
        self.resolver: Resolver = resolver or SystemResolver()

    def now(self) -> float:
        return self._clock()

    def _live_agent(self, fingerprint: str) -> dict:
        row = self.store.get_agent_row(fingerprint)
        if not (row and self.store.is_live_row(row)):
            raise DirectoryError("AGENT_NOT_LISTED")
        return row

    def request_verification(self, body: dict) -> dict:
        fingerprint = str(body.get("fingerprint", ""))
        domain = validate_domain(body.get("domain"))
        method = str(body.get("method", ""))
        if method not in _METHODS:
            raise DirectoryError("INVALID_SCHEMA", "method must be dns_txt or https_well_known")
        row = self._live_agent(fingerprint)
        if not verify_over(
            row["public_key_b64"],
            subset(body, ("fingerprint", "domain", "method")),
            str(body.get("signature", "")),
        ):
            raise DirectoryError("SIGNATURE_MISMATCH")

        verification_id = "vd_" + secrets.token_hex(16)
        token = secrets.token_hex(32)
        self.store.insert_domain_challenge(
            challenge_id=verification_id,
            fingerprint=fingerprint,
            domain=domain,
            method=method,
            token=token,
            ttl_s=self.config.domain_token_ttl_s,
            max_pending=self.config.max_pending_verifications,
        )
        if method == "dns_txt":
            instructions = (
                f"Publish TXT record at _haap.{domain} with value "
                f"haap-verify={token} (TTL <= 300 recommended)"
            )
        else:
            instructions = (
                f"Serve https://{domain}/.well-known/haap-verify.txt containing "
                f"exactly: {token}"
            )
        expires = self.now() + self.config.domain_token_ttl_s
        return {
            "verification_id": verification_id,
            "domain": domain,
            "method": method,
            "token": token,
            "instructions": instructions,
            "expires_at": to_rfc3339(expires),
            "ttl_seconds": self.config.domain_token_ttl_s,
        }

    def confirm(self, body: dict) -> dict:
        fingerprint = str(body.get("fingerprint", ""))
        verification_id = str(body.get("verification_id", ""))
        row = self._live_agent(fingerprint)
        if not verify_over(
            row["public_key_b64"],
            subset(body, ("fingerprint", "verification_id")),
            str(body.get("signature", "")),
        ):
            raise DirectoryError("SIGNATURE_MISMATCH")

        ch = self.store.get_challenge(verification_id)
        if ch is None or ch.get("kind") != "domain":
            raise DirectoryError("VERIFICATION_NOT_FOUND")
        if ch["fingerprint"] != fingerprint:
            raise DirectoryError("VERIFICATION_NOT_FOUND")
        if ch["used"]:
            raise DirectoryError("VERIFICATION_USED")
        if ch["expires_epoch"] < int(self.now()):
            raise DirectoryError("VERIFICATION_EXPIRED")

        domain, method, token = ch["domain"], ch["method"], ch["nonce"]
        host = endpoint_host(load_manifest_json(row))
        endpoint_match = host_under_domain(host, domain)
        if not endpoint_match:
            raise DirectoryError("DOMAIN_ENDPOINT_MISMATCH")

        self._check_control(domain, method, token)

        result = self.store.confirm_domain_verification(
            challenge_id=verification_id,
            verification_id=verification_id,
            fingerprint=fingerprint,
            domain=domain,
            method=method,
            ttl_days=self.config.domain_verification_ttl_days,
            endpoint_match=endpoint_match,
        )
        return {
            "status": "verified",
            "domain": domain,
            "method": method,
            "verified_at": result["verified_at"],
            "expires_at": result["expires_at"],
            "endpoint_match": True,
        }

    def _check_control(self, domain: str, method: str, token: str) -> None:
        """Delegate to the injected resolver, which raises a stable code on
        failure (``DNS_TXT_NOT_FOUND``, ``WELL_KNOWN_*``, ``DNS_ERROR_TEMPORARY``)."""
        self.resolver.check(domain, method, token)

    # -- signals -----------------------------------------------------------
    def status(self, fingerprint: str) -> list[dict]:
        row = self.store.get_agent_row(fingerprint)
        host = endpoint_host(load_manifest_json(row)) if row else ""
        out = []
        for v in self.store.active_domain_verifications(fingerprint):
            out.append({
                "domain": v["domain"],
                "method": v["method"],
                "verified_at": v["verified_at"],
                "expires_at": v["expires_at"],
                "primary": bool(host and host_under_domain(host, v["domain"])),
            })
        return out

    def primary_verification(self, fingerprint: str, host: str) -> Optional[dict]:
        """The live verification whose domain the endpoint host lives under."""
        best = None
        for v in self.store.active_domain_verifications(fingerprint):
            if host and host_under_domain(host, v["domain"]):
                if best is None or v["verified_epoch"] > best["verified_epoch"]:
                    best = v
        return best
