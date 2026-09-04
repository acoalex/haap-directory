# -*- coding: utf-8 -*-
"""L3 — vouching: expiring, revocable, scoped peer statements (SPEC §3.4, §4.4).

A vouch is an opinion with a signature, not a fact. The directory enforces
*mechanics* only (live keys, caps, expiry, revocation validity) and serves the
graph as raw edges — never an aggregate score. Consumers apply their own trust
set. Collusion rings are made *visible*, not "stopped".
"""

from __future__ import annotations

import secrets
from collections import deque
from typing import Optional

from .config import DirectoryConfig
from .errors import DirectoryError
from .signing import verify_over
from .store import Store
from .timeutil import Clock, from_rfc3339, system_clock

_CANONICAL_SCOPE_PREFIXES = ("identity", "task_delivery", "service:", "payment")


class VouchService:
    def __init__(self, store: Store, config: DirectoryConfig, clock: Clock = system_clock):
        self.store = store
        self.config = config
        self._clock = clock

    def now(self) -> float:
        return self._clock()

    def _pubkey_of_live(self, fingerprint: str, missing_code: str) -> str:
        row = self.store.get_agent_row(fingerprint)
        if not (row and self.store.is_live_row(row)):
            raise DirectoryError(missing_code)
        return row["public_key_b64"]

    def create(self, body: dict) -> dict:
        voucher = str(body.get("voucher_fingerprint", ""))
        vouchee = str(body.get("vouchee_fingerprint", ""))
        scope = body.get("scope")
        weight = body.get("weight", 1)
        note = body.get("note")
        expires_at = body.get("expires_at")
        created_at = body.get("created_at")

        if not isinstance(scope, str) or not scope or scope != scope.lower():
            raise DirectoryError("VOUCH_INVALID", "scope must be a lowercase string")
        if weight != 1:
            raise DirectoryError("VOUCH_INVALID", "weight must be 1 in v1")
        if not isinstance(expires_at, str) or not isinstance(created_at, str):
            raise DirectoryError("VOUCH_INVALID", "created_at and expires_at are required")
        try:
            created_epoch = from_rfc3339(created_at)
            expires_epoch = int(from_rfc3339(expires_at))
        except (ValueError, TypeError) as exc:
            raise DirectoryError("VOUCH_INVALID", "unparseable timestamp") from exc
        if expires_epoch <= int(self.now()):
            raise DirectoryError("VOUCH_EXPIRED", "expires_at is in the past")
        if expires_epoch - created_epoch > self.config.vouch_max_expiry_days * 86400:
            raise DirectoryError("VOUCH_INVALID", "expiry exceeds the maximum window")

        voucher_key = self._pubkey_of_live(voucher, "VOUCHER_NOT_LISTED")
        self._pubkey_of_live(vouchee, "VOUCHEE_NOT_LISTED")

        signed = {k: v for k, v in body.items() if k != "signature"}
        if not verify_over(voucher_key, signed, str(body.get("signature", ""))):
            raise DirectoryError("SIGNATURE_MISMATCH")

        vouch_id = "vc_" + secrets.token_hex(16)
        row = self.store.create_vouch(
            vouch_id=vouch_id,
            voucher=voucher,
            vouchee=vouchee,
            scope=scope,
            note=note if isinstance(note, str) else None,
            expires_at_epoch=expires_epoch,
            signature_b64=str(body.get("signature", "")),
            max_outgoing=self.config.vouch_max_outgoing,
        )
        return {
            "vouch_id": row["vouch_id"],
            "status": "active",
            "voucher": voucher,
            "vouchee": vouchee,
            "scope": scope,
            "expires_at": row["expires_at"],
        }

    def revoke(self, vouch_id: str, body: dict) -> dict:
        voucher = str(body.get("voucher_fingerprint", ""))
        revoked_at = body.get("revoked_at")
        row = self.store.get_agent_row(voucher)
        if row is None:
            raise DirectoryError("SIGNATURE_MISMATCH", "unknown voucher")
        signed = {"voucher_fingerprint": voucher, "revoked_at": revoked_at}
        if not verify_over(row["public_key_b64"], signed, str(body.get("signature", ""))):
            raise DirectoryError("SIGNATURE_MISMATCH")
        self.store.revoke_vouch(vouch_id, voucher, self.now())
        return {"status": "revoked", "vouch_id": vouch_id}

    # -- read/graph --------------------------------------------------------
    def _tenure_hours(self, voucher: str, created_epoch: float) -> Optional[int]:
        row = self.store.get_agent_row(voucher)
        if row is None:
            return None
        return max(0, int((created_epoch - row["registered_epoch"]) / 3600))

    def inbound_signal(self, fingerprint: str) -> list[dict]:
        out = []
        for v in self.store.inbound_vouches(fingerprint, active_only=True):
            out.append({
                "voucher_fingerprint": v["voucher_fingerprint"],
                "scope": v["scope"],
                "created_at": v["created_at"],
                "expires_at": v["expires_at"],
                "revoked_at": v["revoked_at"],
                "voucher_tenure_hours": self._tenure_hours(
                    v["voucher_fingerprint"], v["created_epoch"]
                ),
            })
        return out

    def annotations(self, fingerprint: str) -> dict:
        inbound = self.store.inbound_vouches(fingerprint, active_only=True)
        vouchers = [v["voucher_fingerprint"] for v in inbound]
        # Mutual-vouch density: share of inbound vouchers this agent also
        # vouches back to (a cheap ring signal, exposed raw — never a verdict).
        outgoing_targets = {
            v["vouchee_fingerprint"]
            for v in self.store.outgoing_vouches(fingerprint)
            if v["revoked_at"] is None
        }
        mutual = sum(1 for v in vouchers if v in outgoing_targets)
        density = round(mutual / len(vouchers), 4) if vouchers else 0.0
        return {
            "mutual_vouch_density": density,
            # Registration-IP clustering is not tracked in this build; exposed
            # as False rather than fabricated (honest "no signal").
            "vouchers_share_registration_cluster": False,
        }

    def inbound_graph(self, fingerprint: str) -> dict:
        return {
            "fingerprint": fingerprint,
            "vouches_in": self.inbound_signal(fingerprint),
            "annotations": self.annotations(fingerprint),
        }

    def outgoing_graph(self, fingerprint: str) -> dict:
        edges = []
        for v in self.store.outgoing_vouches(fingerprint):
            edges.append({
                "voucher_fingerprint": v["voucher_fingerprint"],
                "vouchee_fingerprint": v["vouchee_fingerprint"],
                "scope": v["scope"],
                "created_at": v["created_at"],
                "expires_at": v["expires_at"],
                "revoked_at": v["revoked_at"],
            })
        return {"fingerprint": fingerprint, "vouches_out": edges}

    def trust_paths(self, source: str, target: str, max_depth: int = 2) -> dict:
        """BFS over active edges only, capped at depth 2 (SPEC §3.4.2)."""
        max_depth = max(1, min(int(max_depth), 2))
        edges = self.store.active_vouch_edges()
        adj: dict[str, list[dict]] = {}
        for e in edges:
            adj.setdefault(e["voucher_fingerprint"], []).append(e)

        paths: list[list[dict]] = []
        queue: deque[tuple[str, list[dict], set]] = deque([(source, [], {source})])
        while queue:
            node, path, seen = queue.popleft()
            if len(path) >= max_depth:
                continue
            for edge in adj.get(node, []):
                nxt = edge["vouchee_fingerprint"]
                new_path = path + [edge]
                if nxt == target:
                    paths.append(new_path)
                    continue
                if nxt not in seen:
                    queue.append((nxt, new_path, seen | {nxt}))
        return {"paths": paths}
