# -*- coding: utf-8 -*-
"""L4 moderation — moderator-key actions (SPEC §3.5.5, §4.5, §9.4).

Moderator actions are the only human judgement in the hot path, and they are
all L5-audited with the moderator key fingerprint + reason. Moderators are
operator-held Ed25519 keys configured out of band (``config.moderator_keys``).
"""

from __future__ import annotations

import secrets
from typing import Optional

from .config import DirectoryConfig
from .crypto import b64d
from .errors import DirectoryError
from .identity import fingerprint_of_public_key
from .signing import verify_over
from .store import Store
from .timeutil import Clock, system_clock


class ModerationService:
    def __init__(
        self,
        store: Store,
        config: DirectoryConfig,
        clock: Clock = system_clock,
        reputation=None,
    ):
        self.store = store
        self.config = config
        self._clock = clock
        self.reputation = reputation
        # fingerprint -> public_key_b64 for every configured moderator key.
        self.moderators: dict[str, str] = {}
        for key_b64 in config.moderator_keys or []:
            try:
                fp = fingerprint_of_public_key(b64d(key_b64))
            except Exception:  # noqa: BLE001 - skip malformed config entries
                continue
            self.moderators[fp] = key_b64

    def now(self) -> float:
        return self._clock()

    def _authorize_moderator(self, moderator_fp: str, signed: dict, signature_b64: str) -> None:
        key_b64 = self.moderators.get(moderator_fp)
        if key_b64 is None:
            raise DirectoryError("MODERATOR_UNKNOWN")
        if not verify_over(key_b64, signed, signature_b64):
            raise DirectoryError("TAKEDOWN_UNAUTHORIZED")

    def takedown(self, report_id: str, body: dict) -> dict:
        moderator = str(body.get("moderator_fingerprint", ""))
        reason = str(body.get("reason", ""))
        self._authorize_moderator(
            moderator,
            {"moderator_fingerprint": moderator, "report_id": report_id, "reason": reason},
            str(body.get("signature", "")),
        )
        report = self.store.get_report(report_id)
        if report is None:
            raise DirectoryError("REPORT_NOT_FOUND")
        target = report["target_fingerprint"]
        row = self.store.suspend_agent(
            target,
            rule=f"moderator takedown: {reason}",
            evidence_reports=[report_id],
            actor=f"moderator:{moderator}",
            event="moderator.takedown",
        )
        if row is None:
            raise DirectoryError("AGENT_NOT_FOUND")
        return {"status": "suspended", "agent": {"fingerprint": target}}

    def suspend(self, fingerprint: str, body: dict) -> dict:
        moderator = str(body.get("moderator_fingerprint", ""))
        reason = str(body.get("reason", ""))
        self._authorize_moderator(
            moderator,
            {"moderator_fingerprint": moderator, "fingerprint": fingerprint, "reason": reason},
            str(body.get("signature", "")),
        )
        row = self.store.suspend_agent(
            fingerprint,
            rule=f"moderator suspend: {reason}",
            evidence_reports=[],
            actor=f"moderator:{moderator}",
            event="moderator.suspend",
        )
        if row is None:
            raise DirectoryError("AGENT_NOT_FOUND")
        return {"status": "suspended", "agent": {"fingerprint": fingerprint}}

    def unsuspend(self, fingerprint: str, body: dict) -> dict:
        moderator = str(body.get("moderator_fingerprint", ""))
        self._authorize_moderator(
            moderator,
            {"moderator_fingerprint": moderator, "fingerprint": fingerprint},
            str(body.get("signature", "")),
        )
        row = self.store.unsuspend_agent(
            fingerprint, actor=f"moderator:{moderator}", ttl_s=self.config.ttl_seconds
        )
        if row is None:
            raise DirectoryError("AGENT_NOT_FOUND")
        return {"status": "listed", "agent": {"fingerprint": fingerprint}}

    def appeal(self, fingerprint: str, body: dict) -> dict:
        """Signed by the agent (not a moderator)."""
        row = self.store.get_agent_row(fingerprint)
        if row is None:
            raise DirectoryError("AGENT_NOT_FOUND")
        statement = str(body.get("statement", ""))
        if not verify_over(
            row["public_key_b64"],
            {"fingerprint": fingerprint, "statement": statement},
            str(body.get("signature", "")),
        ):
            raise DirectoryError("SIGNATURE_MISMATCH")
        appeal_id = "ap_" + secrets.token_hex(12)
        self.store.create_appeal(appeal_id, fingerprint, statement)
        return {"appeal_id": appeal_id, "status": "open"}
