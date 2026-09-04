# -*- coding: utf-8 -*-
"""L4 — behavioural reputation: reports, decay, auto-suspend (SPEC §3.5, §4.5).

Deterministic, transparent automata over signed reports. Counters are raw
facts; the only automated action is a published, audited auto-suspend for a
narrow set of abuse classes. Reports are allegations, never findings — the
directory never marks a target "guilty".
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Optional

from .canonical import canonical_json
from .config import DirectoryConfig
from .errors import DirectoryError
from .signing import verify_over
from .store import Store
from .timeutil import Clock, system_clock

CATEGORIES = {
    "impersonation_attempt", "endpoint_hijack", "phishing", "spam", "fraud",
    "payment_fraud", "abusive_content", "protocol_violation", "report_abuse",
}
ABUSE_CLASSES = {"spam", "phishing", "impersonation_attempt", "endpoint_hijack"}
SEVERITIES = {"low", "medium", "high"}
EVIDENCE_KINDS = {"envelope", "url", "transcript", "none"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ReputationService:
    def __init__(self, store: Store, config: DirectoryConfig, clock: Clock = system_clock):
        self.store = store
        self.config = config
        self._clock = clock

    def now(self) -> float:
        return self._clock()

    def create_report(self, body: dict) -> dict:
        reporter = str(body.get("reporter_fingerprint", ""))
        target = str(body.get("target_fingerprint", ""))
        category = str(body.get("category", ""))
        severity = str(body.get("severity", ""))
        evidence = body.get("evidence") or {}

        if category not in CATEGORIES:
            raise DirectoryError("REPORT_INVALID", "unknown category")
        if severity not in SEVERITIES:
            raise DirectoryError("REPORT_INVALID", "invalid severity")
        if not isinstance(evidence, dict) or evidence.get("kind") not in EVIDENCE_KINDS:
            raise DirectoryError("REPORT_INVALID", "invalid evidence.kind")
        if not reporter:
            raise DirectoryError("REPORT_INVALID", "reporter_fingerprint is required")

        target_row = self.store.get_agent_row(target)
        if not (target_row and self.store.is_live_row(target_row)):
            raise DirectoryError("TARGET_NOT_LISTED")

        reporter_row = self.store.get_agent_row(reporter)
        if not (reporter_row and self.store.is_live_row(reporter_row)):
            raise DirectoryError("REPORTER_NOT_ELIGIBLE")

        signed = {k: v for k, v in body.items() if k != "signature"}
        if not verify_over(reporter_row["public_key_b64"], signed, str(body.get("signature", ""))):
            raise DirectoryError("SIGNATURE_MISMATCH")

        tenure_ok = (
            self.now() - reporter_row["registered_epoch"]
        ) >= self.config.report_tenure_hours * 3600
        counts = bool(tenure_ok)

        report_id = str(body.get("report_id") or ("rp_" + secrets.token_hex(16)))
        evidence_hash = _sha256(canonical_json(evidence))
        description = evidence.get("description")
        description_hash = _sha256(description.encode("utf-8")) if isinstance(description, str) else None

        self.store.create_report(
            report_id=report_id,
            reporter=reporter,
            target=target,
            category=category,
            severity=severity,
            evidence_kind=str(evidence.get("kind")),
            evidence_hash=evidence_hash,
            description_hash=description_hash,
            occurred_at=body.get("occurred_at"),
            counts=counts,
            dup_window_s=self.config.report_dup_window_hours * 3600,
        )

        if counts and category in ABUSE_CLASSES:
            self._maybe_auto_suspend(target, category)

        return {
            "report_id": report_id,
            "status": "recorded",
            "counts_toward_automation": counts,
        }

    def _maybe_auto_suspend(self, target: str, category: str) -> None:
        reporters = self.store.unique_eligible_reporters_in_window(
            target, category, self.config.report_window_days * 86400
        )
        if len(reporters) < self.config.auto_suspend_threshold:
            return
        row = self.store.get_agent_row(target)
        if row is None or row["status"] != "listed":
            return
        self.store.suspend_agent(
            target,
            rule=(
                f">= {self.config.auto_suspend_threshold} unique eligible reporters in "
                f"{self.config.report_window_days}d ({category})"
            ),
            evidence_reports=sorted(reporters),
            actor="directory",
            event="report.auto_suspend",
        )

    # -- signals -----------------------------------------------------------
    def counters(self, fingerprint: str) -> dict:
        return self.store.report_counters(
            fingerprint, self.config.report_decay_days * 86400
        )

    def block_recommendation(self, fingerprint: str) -> Optional[dict]:
        """Pure function of recent counters — data, never enforcement."""
        window = self.config.report_window_days * 86400
        fraud = self.store.unique_eligible_reporters_in_window(fingerprint, "fraud", window)
        payment = self.store.unique_eligible_reporters_in_window(
            fingerprint, "payment_fraud", window
        )
        if len(set(fraud) | set(payment)) >= 2:
            return {"default_max_contact_rate_h": 1}
        return None

    def report_war(self, a: str, b: str) -> bool:
        return self.store.mutual_report_count(
            a, b, self.config.report_war_days * 86400
        ) >= 2

    def public_reports(self, fingerprint: str) -> dict:
        """Counters + recent metadata (never full evidence bodies)."""
        return {"fingerprint": fingerprint, "reports": self.counters(fingerprint)}
