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
from .domain import DomainService, endpoint_host
from .errors import DirectoryError
from .identity import fingerprint_of_public_key
from .manifest import validate_manifest
from .resolver import Resolver
from .store import Store, load_manifest_json
from .timeutil import Clock, from_rfc3339, system_clock, to_rfc3339

MAX_CLOCK_SKEW_S = 300
NONCE_PREFIX = "v1:register:"


class DirectoryService:
    """Stateful directory logic bound to a store, a signing key and a clock."""

    def __init__(
        self,
        store: Store,
        keypair: KeyPair,
        config: DirectoryConfig,
        clock: Clock = system_clock,
        resolver: Optional[Resolver] = None,
    ):
        self.store = store
        self.keypair = keypair
        self.config = config
        self._clock = clock
        self.directory_fingerprint = fingerprint_of_public_key(keypair.public_key)
        self.domain = DomainService(store, config, clock, resolver)
        # L3/L4/L5 sub-services are attached by their phases (see below).
        self.vouches = None
        self.reputation = None
        self.moderation = None
        self.audit = None
        self._attach_subservices()
        # Prune stale entries on startup (SPEC §5.3, §7 F2).
        self.store.prune_expired()

    def _attach_subservices(self) -> None:
        """Wire L3 (vouching), L4 (reputation + moderation) and L5 (audit)."""
        from .audit_service import AuditService
        from .moderation import ModerationService
        from .reputation import ReputationService
        from .vouching import VouchService

        self.vouches = VouchService(self.store, self.config, self._clock)
        self.reputation = ReputationService(self.store, self.config, self._clock)
        self.moderation = ModerationService(
            self.store, self.config, self._clock, self.reputation
        )
        self.audit = AuditService(self.store, self.keypair, self.config, self._clock)

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
        """The §5.2 trust block, assembled from the L1–L5 signals available."""
        now = self.now()
        fingerprint = row["fingerprint"]
        age_days = round((now - row["registered_epoch"]) / 86400.0, 4)
        fresh = bool(
            row["last_heartbeat_epoch"] is not None
            and (now - row["last_heartbeat_epoch"]) <= self.config.ttl_seconds
        )

        # L2: domain verification signal (primary = matches the endpoint host).
        host = endpoint_host(load_manifest_json(row))
        primary = self.domain.primary_verification(fingerprint, host)
        domain_block = None
        if primary is not None:
            domain_block = {
                "domain": primary["domain"],
                "method": primary["method"],
                "verified_at": primary["verified_at"],
                "expires_at": primary["expires_at"],
                "primary": True,
            }

        # L3/L4 signals (present when their services are wired in).
        vouches_in = self.vouches.inbound_signal(fingerprint) if self.vouches else []
        vouch_annotations = (
            self.vouches.annotations(fingerprint) if self.vouches
            else {"mutual_vouch_density": 0.0, "vouchers_share_registration_cluster": False}
        )
        reports = (
            self.reputation.counters(fingerprint) if self.reputation
            else {"by_category": {}, "unique_reporters": 0, "first_at": None, "last_at": None}
        )
        block_recommendation = (
            self.reputation.block_recommendation(fingerprint) if self.reputation else None
        )
        suspension = None
        if row["status"] == "suspended" and row["suspension_json"]:
            try:
                suspension = json.loads(row["suspension_json"])
            except (ValueError, TypeError):
                suspension = None

        return {
            "directory_fingerprint": self.directory_fingerprint,
            "listed_since": row["registered_at"],
            "age_days": age_days,
            "last_heartbeat": row["last_heartbeat"],
            "fresh": fresh,
            "endpoint_proof_at": row["endpoint_proof_at"],
            "domain_verified": domain_block is not None,
            "domain_verification": domain_block,
            "vouches_in": vouches_in,
            "vouch_annotations": vouch_annotations,
            "reports": reports,
            "status": row["status"],
            "suspension": suspension,
            "block_recommendation": block_recommendation,
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
            "suspended": self.store.count_suspended(),
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
