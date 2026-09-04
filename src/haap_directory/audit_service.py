# -*- coding: utf-8 -*-
"""L5 — transparency service: checkpoints, verification, response signing.

Wraps the append-only hash chain persisted by ``store`` (SPEC §3.6, §4.8).
The directory key signs the chain head hourly and on shutdown; audit responses
carry ``X-HAAP-Directory-Signature`` so consumers can detect a rewrite of
anything they have already seen.
"""

from __future__ import annotations

from typing import Optional

from . import audit
from .canonical import canonical_json
from .config import DirectoryConfig
from .crypto import KeyPair, b64e
from .identity import fingerprint_of_public_key
from .store import Store
from .timeutil import Clock, from_rfc3339, system_clock, to_rfc3339


class AuditService:
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

    def now(self) -> float:
        return self._clock()

    def sign_body(self, obj) -> str:
        """b64 Ed25519 signature over the canonical JSON of a response body."""
        return b64e(self.keypair.sign(canonical_json(obj)))

    # -- checkpoints -------------------------------------------------------
    def _checkpoint_payload(self, head: dict) -> dict:
        return {"seq": head["seq"], "entry_hash": head["entry_hash"], "ts": head["ts"]}

    def head(self) -> dict:
        head = self.store.audit_head()
        payload = self._checkpoint_payload(head)
        return {**payload, "checkpoint_signature": self.sign_body(payload)}

    def create_checkpoint(self) -> dict:
        head = self.store.audit_head()
        payload = self._checkpoint_payload(head)
        signature = self.sign_body(payload)
        self.store.insert_checkpoint(head["seq"], head["entry_hash"], head["ts"], signature)
        return {**payload, "signature": signature}

    def maybe_checkpoint(self, force: bool = False) -> Optional[dict]:
        """Create a checkpoint if the cadence has elapsed (or forced)."""
        last = self.store.latest_checkpoint()
        if not force and last is not None:
            try:
                elapsed = self.now() - from_rfc3339(last["ts"])
            except (ValueError, TypeError):
                elapsed = self.config.checkpoint_interval_s
            if elapsed < self.config.checkpoint_interval_s:
                return None
        return self.create_checkpoint()

    def checkpoints(self) -> dict:
        return {"checkpoints": self.store.list_checkpoints(limit=1000)}

    # -- verification ------------------------------------------------------
    def verify(self, seq: int) -> dict:
        entries = self.store.audit_entries(after=-1, limit=1000)
        # Page through if needed to reach ``seq``.
        while entries and entries[-1]["seq"] < seq:
            more = self.store.audit_entries(after=entries[-1]["seq"], limit=1000)
            if not more:
                break
            entries.extend(more)
        subset = [e for e in entries if e["seq"] <= seq]
        valid = audit.verify_chain(subset)
        computed_head = subset[-1]["entry_hash"] if subset else None
        return {"valid": valid, "computed_head": computed_head}

    def agent_audit(self, fingerprint: str) -> dict:
        """Redacted per-agent audit view (detail_hash only, no detail body)."""
        return {
            "fingerprint": fingerprint,
            "entries": self.store.audit_entries_for_fingerprint(fingerprint),
        }
