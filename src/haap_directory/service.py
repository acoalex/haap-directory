# -*- coding: utf-8 -*-
"""Directory business logic — no HTTP here (SPEC §4, §5).

Implements the L1 proof-of-endpoint registration state machine, heartbeats
(v1 signed + legacy unsigned), search and profile, and the per-listing trust
block. Every state change goes through ``store`` so it is persisted and
appended to the L5 audit chain in the same transaction.

L2 (domain), L3 (vouching) and L4 (reputation) are future phases; the trust
block already carries their fields with honest "no signal yet" defaults so
the wire shape is stable (SPEC §5.2).
"""

from __future__ import annotations

import math
import secrets
from typing import Any, Optional

from . import PROTOCOL_VERSION, __version__
from .canonical import canonical_json
from .config import DirectoryConfig
from .crypto import KeyPair, b64d, verify_with
from .errors import DirectoryError
from .identity import fingerprint_of_public_key
from .manifest import validate_manifest
from .store import Store, load_manifest_json
from .timeutil import Clock, from_rfc3339, system_clock, to_rfc3339
from .verify import (
    check_dns_txt,
    check_https_well_known,
    registrable_domain,
    validate_domain,
)
from urllib.parse import urlsplit

MAX_CLOCK_SKEW_S = 300


def _within(parent: str, child: str) -> bool:
    """True if ``child == parent`` or ``child`` ends with ``.parent``."""
    return child == parent or child.endswith("." + parent)
NONCE_PREFIX = "v1:register:"


class DirectoryService:
    """Stateful directory logic bound to a store, a signing key and a clock."""

    def __init__(
        self,
        store: Store,
        keypair: KeyPair,
        config: DirectoryConfig,
        clock: Clock = system_clock,
    ):
        self.store = store
        self.keypair = keypair
        self.config = config
        self._clock = clock
        self.directory_fingerprint = fingerprint_of_public_key(keypair.public_key)
        # Prune stale entries on startup (SPEC §5.3, §7 F2).
        self.store.prune_expired()

    def now(self) -> float:
        return self._clock()

    # -- L1 registration ---------------------------------------------------
    def submit_registration(
        self, manifest: Any, public_key_b64: str, manifest_signature: str
    ) -> dict:
        """Step 1: verify the signed manifest and issue an endpoint challenge."""
        validate_manifest(manifest)
        canonical = canonical_json(manifest)
        if len(canonical) > self.config.max_manifest_bytes:
            raise DirectoryError("MANIFEST_TOO_LARGE")
        fingerprint = manifest["agent"]["fingerprint"]

        try:
            raw_pub = b64d(public_key_b64)
        except Exception as exc:  # noqa: BLE001 - malformed base64
            raise DirectoryError("INVALID_SCHEMA", "public_key_b64 is not valid base64") from exc
        if len(raw_pub) != 32 or fingerprint_of_public_key(raw_pub) != fingerprint:
            raise DirectoryError("FINGERPRINT_MISMATCH")

        try:
            sig = b64d(manifest_signature)
        except Exception as exc:  # noqa: BLE001
            raise DirectoryError("SIGNATURE_MISMATCH", "signature is not valid base64") from exc
        if not verify_with(raw_pub, canonical, sig):
            raise DirectoryError("SIGNATURE_MISMATCH")

        # Capacity: cap total listed agents; an already-live fp may re-register.
        row = self.store.get_agent_row(fingerprint)
        already_live = self.store.is_live_row(row) if row else False
        if not already_live and self.store.count_live() >= self.config.max_agents:
            raise DirectoryError("DIRECTORY_FULL")

        challenge_id = "ch_" + secrets.token_hex(16)
        nonce = NONCE_PREFIX + secrets.token_hex(32)
        endpoint = manifest["agent"]["endpoint"]
        self.store.insert_challenge(
            challenge_id=challenge_id,
            fingerprint=fingerprint,
            nonce=nonce,
            public_key_b64=public_key_b64,
            endpoint=endpoint,
            ttl_s=self.config.challenge_ttl_s,
            manifest_json=canonical.decode("utf-8"),
            max_pending=self.config.max_pending_challenges,
        )
        expires = self.now() + self.config.challenge_ttl_s
        return {
            "challenge_id": challenge_id,
            "nonce": nonce,
            "registry_fingerprint": self.directory_fingerprint,
            "directory_fingerprint": self.directory_fingerprint,
            "expires_at": to_rfc3339(expires),
            "algorithm": "ed25519",
            "ttl_seconds": self.config.challenge_ttl_s,
        }

    def complete_registration(
        self,
        fingerprint: str,
        endpoint_proof_b64: str,
        challenge_id: Optional[str] = None,
        public_key_b64: str = "",
    ) -> dict:
        """Step 2: verify the endpoint proof and list the agent.

        ``challenge_id`` is the canonical v1 selector; when absent (legacy
        client) the most recent pending challenge for ``fingerprint`` is used.
        """
        if challenge_id:
            challenge = self.store.get_challenge(challenge_id)
        else:
            challenge = self.store.latest_pending_challenge(fingerprint)
        if challenge is None:
            raise DirectoryError("CHALLENGE_NOT_FOUND")
        if challenge["fingerprint"] != fingerprint:
            raise DirectoryError("FINGERPRINT_MISMATCH")
        if challenge["used"]:
            raise DirectoryError("CHALLENGE_USED")
        if challenge["expires_epoch"] < int(self.now()):
            raise DirectoryError("CHALLENGE_EXPIRED")
        if public_key_b64 and public_key_b64 != challenge["public_key_b64"]:
            raise DirectoryError("KEY_MISMATCH")

        bound_key_b64 = challenge["public_key_b64"]
        try:
            raw_pub = b64d(bound_key_b64)
            proof = b64d(endpoint_proof_b64)
        except Exception as exc:  # noqa: BLE001
            raise DirectoryError("PROOF_INVALID", "proof is not valid base64") from exc
        if not verify_with(raw_pub, challenge["nonce"].encode("ascii"), proof):
            raise DirectoryError("PROOF_INVALID")

        now = self.now()
        row = self.store.complete_registration(
            challenge_id=challenge["challenge_id"],
            fingerprint=fingerprint,
            public_key_b64=bound_key_b64,
            manifest_json=challenge["manifest_json"],
            ttl_s=self.config.ttl_seconds,
            endpoint_proof_at_epoch=now,
        )
        return {
            "status": "registered",
            "agent_url": f"/v1/agents/{fingerprint}",
            "expires_at": row["expires_at"],
            "directory_fingerprint": self.directory_fingerprint,
            "ttl_seconds": int(self.config.ttl_seconds),
        }

    # -- L2 domain verification ----------------------------------------------
    def request_domain_verification(
        self,
        fingerprint: str,
        domain: str,
        method: str,
        signature_b64: str,
        body_canonical: bytes,
    ) -> dict:
        """Issue an L2 challenge (SPEC §4.3). Must be signed by the agent key."""
        row = self.store.get_agent_row(fingerprint)
        if not (row and self.store.is_live_row(row)):
            raise DirectoryError("AGENT_NOT_LISTED")
        if method not in ("dns_txt", "https_well_known"):
            raise DirectoryError(
                "INVALID_SCHEMA", "method must be dns_txt or https_well_known"
            )
        domain = validate_domain(domain)

        if not verify_with(b64d(row["public_key_b64"]), body_canonical, b64d(signature_b64)):
            raise DirectoryError("SIGNATURE_MISMATCH")

        if (
            self.store.count_pending_domain_challenges(fingerprint)
            >= self.config.max_pending_domain_verifications
        ):
            raise DirectoryError("VERIFICATION_LIMIT_REACHED")

        verification_id = "vd_" + secrets.token_hex(16)
        token = secrets.token_hex(32)  # 128-bit+ random hex token
        instructions = (
            f"Publish TXT record at _haap.{domain} with value "
            f"haap-verify={token} (TTL <= 300 recommended)"
            if method == "dns_txt"
            else f"Serve https://{domain}/.well-known/haap-verify.txt with the "
            f"exact body {token} (or .json {{\"haap_verify_token\": \"{token}\"}})"
        )
        self.store.insert_challenge(
            challenge_id=verification_id,
            fingerprint=fingerprint,
            nonce=token,
            public_key_b64=row["public_key_b64"],
            endpoint="",
            ttl_s=self.config.domain_challenge_ttl_s,
            kind="domain",
            audit_event="domain.challenge_issued",
            max_pending=None,
            manifest_json=None,
            domain=domain,
            method=method,
        )
        expires = self.now() + self.config.domain_challenge_ttl_s
        return {
            "verification_id": verification_id,
            "domain": domain,
            "method": method,
            "token": token,
            "instructions": instructions,
            "expires_at": to_rfc3339(expires),
            "ttl_seconds": self.config.domain_challenge_ttl_s,
        }

    def confirm_domain_verification(
        self,
        fingerprint: str,
        verification_id: str,
        signature_b64: str,
        body_canonical: bytes,
    ) -> dict:
        """Run the server-side check and persist the verification (§4.3)."""
        challenge = self.store.get_challenge(verification_id)
        if challenge is None or challenge.get("kind") != "domain":
            raise DirectoryError("VERIFICATION_NOT_FOUND")
        if challenge["fingerprint"] != fingerprint:
            raise DirectoryError("FINGERPRINT_MISMATCH")
        if challenge["used"]:
            raise DirectoryError("VERIFICATION_USED")
        if challenge["expires_epoch"] < int(self.now()):
            raise DirectoryError("VERIFICATION_EXPIRED")

        row = self.store.get_agent_row(fingerprint)
        if not (row and self.store.is_live_row(row)):
            raise DirectoryError("AGENT_NOT_LISTED")
        if not verify_with(b64d(row["public_key_b64"]), body_canonical, b64d(signature_b64)):
            raise DirectoryError("SIGNATURE_MISMATCH")

        # Domain and method come from the challenge itself (server-issued),
        # never from the request body.
        domain = challenge["domain"] if "domain" in challenge.keys() else None
        method = challenge["method"] if "method" in challenge.keys() else None
        if not domain or not method:
            raise DirectoryError("VERIFICATION_NOT_FOUND")

        # Endpoint-domain consistency (SPEC §3.3): the declared endpoint host
        # MUST be the verified domain or a subdomain of it.
        manifest = load_manifest_json(row)
        endpoint_host = urlsplit(manifest["agent"]["endpoint"]).hostname or ""
        endpoint_match = _within(domain, endpoint_host.lower())
        if not endpoint_match:
            raise DirectoryError("DOMAIN_ENDPOINT_MISMATCH")

        token = challenge["nonce"]
        if method == "dns_txt":
            check_dns_txt(domain, token)
        else:
            check_https_well_known(domain, token)

        self.store.mark_challenge_used(verification_id)
        now = self.now()
        vrow = self.store.insert_domain_verification(
            verification_id="dv_" + secrets.token_hex(16),
            fingerprint=fingerprint,
            domain=domain,
            method=method,
            verified_at_epoch=now,
            validity_days=self.config.domain_validity_days,
            endpoint_match=True,
            challenge_id=verification_id,
        )
        return {
            "status": "verified",
            "domain": domain,
            "method": method,
            "verified_at": vrow["verified_at"],
            "expires_at": vrow["expires_at"],
            "endpoint_match": True,
        }

    def domain_verification_status(self, fingerprint: str) -> dict:
        """Public verification state for an agent (§4.3 status endpoint)."""
        rows = self.store.active_domain_verifications(fingerprint)
        agent_row = self.store.get_agent_row(fingerprint)
        endpoint_host = ""
        if agent_row:
            manifest = load_manifest_json(agent_row)
            endpoint_host = (urlsplit(manifest["agent"]["endpoint"]).hostname or "").lower()
        primary_assigned = False
        out = []
        for r in rows:
            primary = False
            if not primary_assigned and _within(r["domain"], endpoint_host):
                primary = True
                primary_assigned = True
            out.append(
                {
                    "domain": r["domain"],
                    "method": r["method"],
                    "verified_at": r["verified_at"],
                    "expires_at": r["expires_at"],
                    "primary": primary,
                }
            )
        return {"fingerprint": fingerprint, "verifications": out}

    # -- heartbeats --------------------------------------------------------
    def heartbeat_v1(self, fingerprint: str, timestamp: str, signature_b64: str) -> dict:
        """Signed heartbeat (SPEC §4.7). Never confirms fingerprint existence."""
        try:
            ts_epoch = from_rfc3339(timestamp)
        except (ValueError, TypeError) as exc:
            raise DirectoryError("STALE_TIMESTAMP", "unparseable timestamp") from exc
        if abs(self.now() - ts_epoch) > MAX_CLOCK_SKEW_S:
            raise DirectoryError("STALE_TIMESTAMP")

        row = self.store.get_agent_row(fingerprint)
        if not (row and self.store.is_live_row(row)):
            raise DirectoryError("UNKNOWN_OR_EXPIRED")

        message = f"heartbeat:{fingerprint}:{timestamp}".encode("ascii")
        try:
            ok = verify_with(b64d(row["public_key_b64"]), message, b64d(signature_b64))
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            # Do not confirm existence to a caller that cannot sign.
            raise DirectoryError("UNKNOWN_OR_EXPIRED")

        fresh = self.store.heartbeat(fingerprint, self.config.ttl_seconds)
        if fresh is None:
            raise DirectoryError("UNKNOWN_OR_EXPIRED")
        return {
            "status": "ok",
            "expires_at": fresh["expires_at"],
            "ttl_seconds": int(self.config.ttl_seconds),
        }

    def heartbeat_legacy(self, fingerprint: str) -> bool:
        """Unsigned legacy heartbeat ``{fingerprint}`` (audit-flagged)."""
        fresh = self.store.heartbeat(fingerprint, self.config.ttl_seconds, legacy=True)
        return fresh is not None

    # -- search & profile --------------------------------------------------
    def search(self, query: "SearchQuery") -> dict:
        rows = self.store.live_agents()
        matches: list[dict] = []
        for row in rows:
            manifest = load_manifest_json(row)
            if not _matches_query(manifest, query):
                continue
            trust = self.build_trust_block(row)
            if not _passes_trust_filters(trust, query):
                continue
            matches.append({"row": row, "manifest": manifest, "trust": trust})

        total = len(matches)
        window = matches[query.offset : query.offset + query.limit]
        return {
            "results": [{"manifest": m["manifest"], "trust": m["trust"]} for m in window],
            "manifests": [m["manifest"] for m in window],  # legacy projection
            "total": total,
            "limit": query.limit,
            "offset": query.offset,
            "directory_fingerprint": self.directory_fingerprint,
        }

    def get_agent(self, fingerprint: str) -> dict:
        row = self.store.get_agent_row(fingerprint)
        if row is None:
            raise DirectoryError("AGENT_NOT_FOUND")
        if not self.store.is_live_row(row):
            # Do not distinguish suspended from expired for anonymous callers.
            raise DirectoryError("AGENT_NOT_LISTED")
        return {"manifest": load_manifest_json(row), "trust": self.build_trust_block(row)}

    def build_trust_block(self, row: dict) -> dict:
        """The §5.2 trust block. L2 is live; L3–L4 carry honest defaults."""
        now = self.now()
        age_days = round((now - row["registered_epoch"]) / 86400.0, 4)
        fresh = bool(
            row["last_heartbeat_epoch"] is not None
            and (now - row["last_heartbeat_epoch"]) <= self.config.ttl_seconds
        )
        # L2: newest active verification whose domain matches the endpoint
        # host is surfaced as primary (SPEC §3.3).
        verifications = self.store.active_domain_verifications(row["fingerprint"])
        endpoint_host = ""
        manifest = load_manifest_json(row)
        endpoint_host = (urlsplit(manifest["agent"]["endpoint"]).hostname or "").lower()
        domain_verified = False
        domain_verification = None
        for v in verifications:
            if _within(v["domain"], endpoint_host):
                domain_verified = True
                domain_verification = {
                    "domain": v["domain"],
                    "method": v["method"],
                    "verified_at": v["verified_at"],
                    "expires_at": v["expires_at"],
                    "primary": True,
                }
                break
        return {
            "directory_fingerprint": self.directory_fingerprint,
            "listed_since": row["registered_at"],
            "age_days": age_days,
            "last_heartbeat": row["last_heartbeat"],
            "fresh": fresh,
            "endpoint_proof_at": row["endpoint_proof_at"],
            "domain_verified": domain_verified,
            "domain_verification": domain_verification,
            "vouches_in": [],
            "vouch_annotations": {
                "mutual_vouch_density": 0.0,
                "vouchers_share_registration_cluster": False,
            },
            "reports": {
                "by_category": {},
                "unique_reporters": 0,
                "first_at": None,
                "last_at": None,
            },
            "status": row["status"],
            "suspension": None,
            "block_recommendation": None,
            "reputation_history": [],
            "audit_verifiable": True,
        }

    # -- health ------------------------------------------------------------
    def health(self, uptime_s: float) -> dict:
        head = self.store.audit_head()
        return {
            "status": "ok",
            "version": __version__,
            "protocol_version": PROTOCOL_VERSION,
            "agents": self.store.count_live(),
            "suspended": 0,
            "pending_verifications": 0,
            "chain_seq": head["seq"],
            "uptime_s": round(uptime_s, 1),
            "directory_fingerprint": self.directory_fingerprint,
            "api": {"completion_route": "/v1/register/complete"},
        }


class SearchQuery:
    """Parsed, clamped search parameters (SPEC §4.6)."""

    def __init__(
        self,
        capability: str = "",
        q: str = "",
        geo: str = "",
        limit: int = 20,
        offset: int = 0,
        min_age_hours: float = 0.0,
        domain_verified: Optional[bool] = None,
        not_suspended: bool = True,
        min_vouches_in: int = 0,
        recent_reports_max: Optional[int] = None,
    ):
        self.capability = (capability or "").strip().lower()
        self.q = (q or "").strip().lower()
        self.geo = _parse_geo(geo)
        self.limit = max(0, min(int(limit), 100))
        self.offset = max(0, int(offset))
        self.min_age_hours = float(min_age_hours or 0.0)
        self.domain_verified = domain_verified
        self.not_suspended = bool(not_suspended)
        self.min_vouches_in = int(min_vouches_in or 0)
        self.recent_reports_max = recent_reports_max


def _parse_geo(geo: str) -> Optional[tuple[float, float, float]]:
    if not geo:
        return None
    try:
        lat, lon, radius = (float(p) for p in geo.split(","))
        return lat, lon, radius
    except (ValueError, TypeError):
        return None


def _geo_of(manifest: dict) -> Optional[tuple[float, float]]:
    geo = (manifest.get("agent") or {}).get("geo") or {}
    if "lat_microdeg" in geo and "lon_microdeg" in geo:
        try:
            return geo["lat_microdeg"] / 1e6, geo["lon_microdeg"] / 1e6
        except (TypeError, ValueError):
            return None
    if "lat" in geo and "lon" in geo:
        try:
            return float(geo["lat"]), float(geo["lon"])
        except (TypeError, ValueError):
            return None
    return None


def _haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    r = 6371.0088
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def _matches_query(manifest: dict, query: "SearchQuery") -> bool:
    agent = manifest.get("agent") or {}
    if query.capability:
        haystack: list[str] = [str(agent.get("speciality", ""))]
        for svc in manifest.get("services") or []:
            haystack.append(str(svc.get("id", "")))
            haystack.append(str(svc.get("category", "")))
        haystack.extend(str(t) for t in manifest.get("tools") or [])
        haystack.extend(str(s.get("name", "")) for s in manifest.get("skills") or [])
        if not any(query.capability in h.lower() for h in haystack if h):
            return False
    if query.q:
        blob = canonical_json(manifest).decode("utf-8").lower()
        if not all(word in blob for word in query.q.split()):
            return False
    if query.geo is not None:
        point = _geo_of(manifest)
        if point is None:
            return False
        lat, lon, radius = query.geo
        if _haversine_km((lat, lon), point) > radius:
            return False
    return True


def _passes_trust_filters(trust: dict, query: "SearchQuery") -> bool:
    if query.not_suspended and trust["status"] == "suspended":
        return False
    if query.min_age_hours and (trust["age_days"] * 24.0) < query.min_age_hours:
        return False
    if query.domain_verified is True and not trust["domain_verified"]:
        return False
    if query.min_vouches_in and len(trust["vouches_in"]) < query.min_vouches_in:
        return False
    if query.recent_reports_max is not None:
        if trust["reports"]["unique_reporters"] > query.recent_reports_max:
            return False
    return True
