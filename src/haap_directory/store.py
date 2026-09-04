# -*- coding: utf-8 -*-
"""SQLite persistence layer — all SQL lives here (SPEC §5.3).

Concurrency model: one connection (``check_same_thread=False``) guarded by a
single re-entrant lock, in WAL mode, with explicit ``BEGIN IMMEDIATE`` write
transactions. SQLite is single-writer; serializing writers behind one lock is
correct and simple at v1 scale, and it lets the L5 audit entry be appended in
the *same* transaction as the state change it records (SPEC §3.6.1, §5.3).

Every method that changes state also appends exactly one audit entry, so
"audit rows == mutating ops" holds by construction.

Time is read through an injected clock (epoch seconds) so expiry is testable
without real sleeps.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from . import audit
from .errors import DirectoryError
from .timeutil import Clock, from_rfc3339, system_clock, to_rfc3339

SCHEMA_VERSION = "1"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    fingerprint       TEXT PRIMARY KEY,
    public_key_b64    TEXT NOT NULL,
    manifest_json     TEXT NOT NULL,
    registered_at     TEXT NOT NULL,
    registered_epoch  INTEGER NOT NULL,
    last_heartbeat    TEXT,
    last_heartbeat_epoch INTEGER,
    endpoint_proof_at TEXT,
    expires_at        TEXT NOT NULL,
    expires_epoch     INTEGER NOT NULL,
    status            TEXT NOT NULL DEFAULT 'listed',
    suspension_json   TEXT,
    suspended_at      TEXT,
    is_history        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_expires ON agents(expires_epoch);

CREATE TABLE IF NOT EXISTS challenges (
    challenge_id   TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,          -- 'endpoint' | 'domain'
    fingerprint    TEXT NOT NULL,
    public_key_b64 TEXT,
    domain         TEXT,
    method         TEXT,
    nonce          TEXT NOT NULL,
    endpoint       TEXT,
    manifest_json  TEXT,                   -- validated manifest captured at submit
    created_at     TEXT NOT NULL,
    created_epoch  INTEGER NOT NULL,
    expires_epoch  INTEGER NOT NULL,
    used           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_challenges_fp ON challenges(fingerprint);
CREATE INDEX IF NOT EXISTS idx_challenges_exp ON challenges(expires_epoch);

CREATE TABLE IF NOT EXISTS domain_verifications (
    id             TEXT PRIMARY KEY,
    fingerprint    TEXT NOT NULL,
    domain         TEXT NOT NULL,
    method         TEXT NOT NULL,
    verified_at    TEXT NOT NULL,
    verified_epoch INTEGER NOT NULL,
    expires_at     TEXT NOT NULL,
    expires_epoch  INTEGER NOT NULL,
    endpoint_match INTEGER NOT NULL DEFAULT 0,
    challenge_id   TEXT
);
CREATE INDEX IF NOT EXISTS idx_dv_fp ON domain_verifications(fingerprint);

CREATE TABLE IF NOT EXISTS vouches (
    vouch_id            TEXT PRIMARY KEY,
    voucher_fingerprint TEXT NOT NULL,
    vouchee_fingerprint TEXT NOT NULL,
    scope               TEXT NOT NULL,
    note                TEXT,
    weight              INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL,
    created_epoch       INTEGER NOT NULL,
    expires_at          TEXT NOT NULL,
    expires_epoch       INTEGER NOT NULL,
    revoked_at          TEXT,
    signature_b64       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vouches_vouchee ON vouches(vouchee_fingerprint);
CREATE INDEX IF NOT EXISTS idx_vouches_voucher ON vouches(voucher_fingerprint);

CREATE TABLE IF NOT EXISTS reports (
    report_id           TEXT PRIMARY KEY,
    reporter_fingerprint TEXT,
    target_fingerprint  TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL,
    evidence_kind       TEXT NOT NULL,
    evidence_hash       TEXT,
    description_hash    TEXT,
    occurred_at         TEXT,
    submitted_at        TEXT NOT NULL,
    submitted_epoch     INTEGER NOT NULL,
    counts              INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'recorded'
);
CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target_fingerprint);
CREATE INDEX IF NOT EXISTS idx_reports_reporter ON reports(reporter_fingerprint);

CREATE TABLE IF NOT EXISTS audit_log (
    seq         INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    event       TEXT NOT NULL,
    fingerprint TEXT,
    actor       TEXT NOT NULL,
    result      TEXT NOT NULL,
    detail_hash TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_fp ON audit_log(fingerprint);

CREATE TABLE IF NOT EXISTS checkpoints (
    seq          INTEGER PRIMARY KEY,   -- audit head seq at checkpoint time
    entry_hash   TEXT NOT NULL,
    ts           TEXT NOT NULL,
    signature_b64 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS appeals (
    appeal_id   TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    statement   TEXT,
    submitted_at TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open'   -- open | granted | denied
);
CREATE INDEX IF NOT EXISTS idx_appeals_fp ON appeals(fingerprint);
"""


class Store:
    """SQLite-backed directory state with an in-transaction audit chain."""

    def __init__(self, db_path: str, clock: Clock = system_clock):
        self.db_path = db_path
        self._clock = clock
        self._lock = threading.RLock()
        directory = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.isolation_level = None  # manual transaction control
        self._configure()
        self._migrate()
        self._ensure_genesis()

    # -- lifecycle ---------------------------------------------------------
    def _configure(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.execute("PRAGMA busy_timeout=5000;")

    def _migrate(self) -> None:
        # ``executescript`` runs in its own (auto-committed) transaction, so it
        # must NOT be nested inside a manual BEGIN/COMMIT. With
        # ``isolation_level=None`` the plain statements below auto-commit too.
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
                (SCHEMA_VERSION,),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def now(self) -> float:
        return self._clock()

    # -- transaction helper ------------------------------------------------
    @contextmanager
    def _write(self) -> Iterator[sqlite3.Cursor]:
        """A serialized write transaction (BEGIN IMMEDIATE ... COMMIT)."""
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE;")
            try:
                yield cur
                self._conn.execute("COMMIT;")
            except Exception:
                self._conn.execute("ROLLBACK;")
                raise

    # -- audit chain -------------------------------------------------------
    def _append_audit(
        self,
        cur: sqlite3.Cursor,
        event: str,
        actor: str,
        result: str,
        fingerprint: Optional[str],
        detail: Optional[Any],
        ts: Optional[str] = None,
    ) -> dict:
        """Append one hash-chain entry inside the caller's transaction."""
        row = cur.execute(
            "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            seq, prev_hash = 0, audit.GENESIS_PREV_HASH
        else:
            seq, prev_hash = row["seq"] + 1, row["entry_hash"]
        ts = ts or to_rfc3339(self.now())
        entry = audit.build_entry(
            seq=seq,
            ts=ts,
            event=event,
            actor=actor,
            result=result,
            prev_hash=prev_hash,
            detail_hash_hex=audit.detail_hash(detail),
            fingerprint=fingerprint,
        )
        ehash = audit.entry_hash(entry)
        cur.execute(
            "INSERT INTO audit_log(seq, ts, event, fingerprint, actor, result, "
            "detail_hash, prev_hash, entry_hash) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                seq,
                ts,
                event,
                fingerprint,
                actor,
                result,
                entry["detail_hash"],
                prev_hash,
                ehash,
            ),
        )
        cur.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('chain_head_seq', ?)",
            (str(seq),),
        )
        entry["entry_hash"] = ehash
        return entry

    def _ensure_genesis(self) -> None:
        with self._write() as cur:
            row = cur.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()
            if row["n"] == 0:
                self._append_audit(
                    cur,
                    event=audit.GENESIS_EVENT,
                    actor="directory",
                    result="ok",
                    fingerprint=None,
                    detail={"schema_version": SCHEMA_VERSION},
                )

    def audit_head(self) -> dict:
        with self._lock:
            row = self._conn.execute(
                "SELECT seq, ts, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return {"seq": row["seq"], "ts": row["ts"], "entry_hash": row["entry_hash"]}

    def audit_entries(self, after: int = -1, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_log WHERE seq > ? ORDER BY seq ASC LIMIT ?",
                (after, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- challenges --------------------------------------------------------
    def insert_challenge(
        self,
        challenge_id: str,
        fingerprint: str,
        nonce: str,
        public_key_b64: str,
        endpoint: str,
        ttl_s: int,
        kind: str = "endpoint",
        audit_event: str = "register.challenge_issued",
        max_pending: Optional[int] = None,
        manifest_json: Optional[str] = None,
    ) -> None:
        now = self.now()
        with self._write() as cur:
            if max_pending is not None:
                pending = cur.execute(
                    "SELECT COUNT(*) AS n FROM challenges WHERE used=0 AND expires_epoch > ?",
                    (int(now),),
                ).fetchone()["n"]
                if pending >= max_pending:
                    # Evict the oldest pending challenge to make room (audited).
                    victim = cur.execute(
                        "SELECT challenge_id FROM challenges WHERE used=0 "
                        "ORDER BY created_epoch ASC LIMIT 1"
                    ).fetchone()
                    if victim is not None:
                        cur.execute(
                            "DELETE FROM challenges WHERE challenge_id=?",
                            (victim["challenge_id"],),
                        )
                        self._append_audit(
                            cur, "challenge.evicted", "directory", "ok",
                            None, {"challenge_id": victim["challenge_id"]},
                        )
            cur.execute(
                "INSERT INTO challenges(challenge_id, kind, fingerprint, public_key_b64, "
                "nonce, endpoint, manifest_json, created_at, created_epoch, expires_epoch, used) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,0)",
                (
                    challenge_id,
                    kind,
                    fingerprint,
                    public_key_b64,
                    nonce,
                    endpoint,
                    manifest_json,
                    to_rfc3339(now),
                    int(now),
                    int(now + ttl_s),
                ),
            )
            self._append_audit(
                cur, audit_event, f"agent:{fingerprint}", "ok",
                fingerprint, {"challenge_id": challenge_id},
            )

    def get_challenge(self, challenge_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM challenges WHERE challenge_id=?", (challenge_id,)
            ).fetchone()
        return dict(row) if row else None

    def latest_pending_challenge(self, fingerprint: str, kind: str = "endpoint") -> Optional[dict]:
        """Most recent unused challenge for a fingerprint (legacy complete)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM challenges WHERE fingerprint=? AND kind=? AND used=0 "
                "ORDER BY created_epoch DESC LIMIT 1",
                (fingerprint, kind),
            ).fetchone()
        return dict(row) if row else None

    def mark_challenge_used(self, challenge_id: str) -> None:
        with self._write() as cur:
            cur.execute(
                "UPDATE challenges SET used=1 WHERE challenge_id=?", (challenge_id,)
            )

    # -- agents ------------------------------------------------------------
    def get_agent_row(self, fingerprint: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
        return dict(row) if row else None

    def is_live_row(self, row: dict) -> bool:
        return (
            row is not None
            and row["status"] == "listed"
            and not row["is_history"]
            and row["expires_epoch"] >= int(self.now())
        )

    def _upsert_agent_cur(
        self,
        cur: sqlite3.Cursor,
        fingerprint: str,
        public_key_b64: str,
        manifest_json: str,
        ttl_s: float,
        endpoint_proof_at_epoch: float,
    ) -> tuple[dict, bool]:
        """List (or refresh) an agent inside an open transaction.

        Re-registration of a *live* entry keeps ``registered_at`` (update);
        a previously-expired/absent entry is a fresh insert. Returns the row
        and whether the entry was already live (an update).
        """
        now = self.now()
        existing = cur.execute(
            "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        was_live = (
            existing is not None
            and existing["status"] == "listed"
            and not existing["is_history"]
            and existing["expires_epoch"] >= int(now)
        )
        registered_at = existing["registered_at"] if was_live else to_rfc3339(now)
        registered_epoch = existing["registered_epoch"] if was_live else int(now)
        expires_epoch = int(now + ttl_s)
        cur.execute(
            "INSERT INTO agents(fingerprint, public_key_b64, manifest_json, "
            "registered_at, registered_epoch, last_heartbeat, last_heartbeat_epoch, "
            "endpoint_proof_at, expires_at, expires_epoch, status, suspension_json, "
            "suspended_at, is_history) VALUES(?,?,?,?,?,?,?,?,?,?, 'listed', NULL, NULL, 0) "
            "ON CONFLICT(fingerprint) DO UPDATE SET "
            "public_key_b64=excluded.public_key_b64, manifest_json=excluded.manifest_json, "
            "registered_at=excluded.registered_at, registered_epoch=excluded.registered_epoch, "
            "last_heartbeat=excluded.last_heartbeat, "
            "last_heartbeat_epoch=excluded.last_heartbeat_epoch, "
            "endpoint_proof_at=excluded.endpoint_proof_at, expires_at=excluded.expires_at, "
            "expires_epoch=excluded.expires_epoch, status='listed', suspension_json=NULL, "
            "suspended_at=NULL, is_history=0",
            (
                fingerprint,
                public_key_b64,
                manifest_json,
                registered_at,
                registered_epoch,
                to_rfc3339(now),
                int(now),
                to_rfc3339(endpoint_proof_at_epoch),
                to_rfc3339(now + ttl_s),
                expires_epoch,
            ),
        )
        row = cur.execute(
            "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        return dict(row), was_live

    def complete_registration(
        self,
        challenge_id: str,
        fingerprint: str,
        public_key_b64: str,
        manifest_json: str,
        ttl_s: float,
        endpoint_proof_at_epoch: float,
    ) -> dict:
        """Atomically consume a verified challenge and list the agent.

        The challenge's ``used`` flag is re-checked under the write lock so a
        replayed completion loses the race with ``CHALLENGE_USED``. Crypto
        proof verification happens in the service before this call.
        """
        from .errors import DirectoryError  # local import avoids a cycle

        with self._write() as cur:
            ch = cur.execute(
                "SELECT used FROM challenges WHERE challenge_id=?", (challenge_id,)
            ).fetchone()
            if ch is None:
                raise DirectoryError("CHALLENGE_NOT_FOUND")
            if ch["used"]:
                raise DirectoryError("CHALLENGE_USED")
            cur.execute(
                "UPDATE challenges SET used=1 WHERE challenge_id=?", (challenge_id,)
            )
            row, was_live = self._upsert_agent_cur(
                cur, fingerprint, public_key_b64, manifest_json, ttl_s,
                endpoint_proof_at_epoch,
            )
            self._append_audit(
                cur,
                "register.updated" if was_live else "register.completed",
                f"agent:{fingerprint}",
                "ok",
                fingerprint,
                {"expires_epoch": row["expires_epoch"], "challenge_id": challenge_id},
            )
            return row

    def heartbeat(self, fingerprint: str, ttl_s: float, legacy: bool = False) -> Optional[dict]:
        """Renew a live entry's TTL. Returns the row or None if not live."""
        now = self.now()
        with self._write() as cur:
            row = cur.execute(
                "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if (
                row is None
                or row["status"] != "listed"
                or row["is_history"]
                or row["expires_epoch"] < int(now)
            ):
                return None
            expires_epoch = int(now + ttl_s)
            cur.execute(
                "UPDATE agents SET last_heartbeat=?, last_heartbeat_epoch=?, "
                "expires_at=?, expires_epoch=? WHERE fingerprint=?",
                (to_rfc3339(now), int(now), to_rfc3339(now + ttl_s), expires_epoch, fingerprint),
            )
            self._append_audit(
                cur,
                "heartbeat.legacy_unsigned" if legacy else "heartbeat.ok",
                f"agent:{fingerprint}",
                "ok",
                fingerprint,
                {"expires_epoch": expires_epoch},
            )
            fresh = cur.execute(
                "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            return dict(fresh)

    def prune_expired(self) -> int:
        """Transition listed entries past their TTL to 'expired' (audited).

        Called on startup and lazily before reads. Idempotent: an already
        expired row is not touched again.
        """
        now = int(self.now())
        with self._write() as cur:
            rows = cur.execute(
                "SELECT fingerprint FROM agents WHERE status='listed' "
                "AND is_history=0 AND expires_epoch < ?",
                (now,),
            ).fetchall()
            for r in rows:
                fp = r["fingerprint"]
                cur.execute(
                    "UPDATE agents SET status='expired', is_history=1 WHERE fingerprint=?",
                    (fp,),
                )
                self._append_audit(
                    cur, "agent.expired", "directory", "ok", fp, {"at": now}
                )
            return len(rows)

    def live_agents(self) -> list[dict]:
        self.prune_expired()
        now = int(self.now())
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM agents WHERE status='listed' AND is_history=0 "
                "AND expires_epoch >= ? ORDER BY registered_epoch ASC",
                (now,),
            ).fetchall()
        return [dict(r) for r in rows]

    def count_live(self) -> int:
        self.prune_expired()
        now = int(self.now())
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM agents WHERE status='listed' "
                "AND is_history=0 AND expires_epoch >= ?",
                (now,),
            ).fetchone()
        return int(row["n"])

    def count_total_agents(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM agents").fetchone()
        return int(row["n"])

    # -- L2 domain verification -------------------------------------------
    def insert_domain_challenge(
        self,
        challenge_id: str,
        fingerprint: str,
        domain: str,
        method: str,
        token: str,
        ttl_s: int,
        max_pending: int,
    ) -> None:
        now = self.now()
        with self._write() as cur:
            pending = cur.execute(
                "SELECT COUNT(*) AS n FROM challenges WHERE kind='domain' "
                "AND fingerprint=? AND used=0 AND expires_epoch > ?",
                (fingerprint, int(now)),
            ).fetchone()["n"]
            if pending >= max_pending:
                raise DirectoryError("VERIFICATION_LIMIT_REACHED")
            cur.execute(
                "INSERT INTO challenges(challenge_id, kind, fingerprint, domain, method, "
                "nonce, created_at, created_epoch, expires_epoch, used) "
                "VALUES(?,'domain',?,?,?,?,?,?,?,0)",
                (
                    challenge_id,
                    fingerprint,
                    domain,
                    method,
                    token,
                    to_rfc3339(now),
                    int(now),
                    int(now + ttl_s),
                ),
            )
            self._append_audit(
                cur, "domain.verify_requested", f"agent:{fingerprint}", "ok",
                fingerprint, {"domain": domain, "method": method},
            )

    def confirm_domain_verification(
        self,
        challenge_id: str,
        verification_id: str,
        fingerprint: str,
        domain: str,
        method: str,
        ttl_days: int,
        endpoint_match: bool,
    ) -> dict:
        """Consume a domain token and persist a 90-day verification (atomic)."""
        now = self.now()
        expires_epoch = int(now + ttl_days * 86400)
        with self._write() as cur:
            ch = cur.execute(
                "SELECT used FROM challenges WHERE challenge_id=? AND kind='domain'",
                (challenge_id,),
            ).fetchone()
            if ch is None:
                raise DirectoryError("VERIFICATION_NOT_FOUND")
            if ch["used"]:
                raise DirectoryError("VERIFICATION_USED")
            cur.execute("UPDATE challenges SET used=1 WHERE challenge_id=?", (challenge_id,))
            cur.execute(
                "INSERT INTO domain_verifications(id, fingerprint, domain, method, "
                "verified_at, verified_epoch, expires_at, expires_epoch, endpoint_match, "
                "challenge_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    verification_id,
                    fingerprint,
                    domain,
                    method,
                    to_rfc3339(now),
                    int(now),
                    to_rfc3339(expires_epoch),
                    expires_epoch,
                    1 if endpoint_match else 0,
                    challenge_id,
                ),
            )
            self._append_audit(
                cur, "domain.verified", f"agent:{fingerprint}", "ok",
                fingerprint, {"domain": domain, "method": method},
            )
            row = cur.execute(
                "SELECT * FROM domain_verifications WHERE id=?", (verification_id,)
            ).fetchone()
            return dict(row)

    def active_domain_verifications(self, fingerprint: str) -> list[dict]:
        now = int(self.now())
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM domain_verifications WHERE fingerprint=? AND expires_epoch >= ? "
                "ORDER BY verified_epoch DESC",
                (fingerprint, now),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- L3 vouching -------------------------------------------------------
    def create_vouch(
        self,
        vouch_id: str,
        voucher: str,
        vouchee: str,
        scope: str,
        note: Optional[str],
        expires_at_epoch: int,
        signature_b64: str,
        max_outgoing: int,
    ) -> dict:
        now = self.now()
        with self._write() as cur:
            active_out = cur.execute(
                "SELECT COUNT(*) AS n FROM vouches WHERE voucher_fingerprint=? "
                "AND revoked_at IS NULL AND expires_epoch >= ?",
                (voucher, int(now)),
            ).fetchone()["n"]
            if active_out >= max_outgoing:
                raise DirectoryError("VOUCH_LIMIT_REACHED")
            dup = cur.execute(
                "SELECT 1 FROM vouches WHERE voucher_fingerprint=? AND vouchee_fingerprint=? "
                "AND scope=? AND revoked_at IS NULL AND expires_epoch >= ?",
                (voucher, vouchee, scope, int(now)),
            ).fetchone()
            if dup is not None:
                raise DirectoryError("VOUCH_EXISTS")
            cur.execute(
                "INSERT INTO vouches(vouch_id, voucher_fingerprint, vouchee_fingerprint, "
                "scope, note, weight, created_at, created_epoch, expires_at, expires_epoch, "
                "revoked_at, signature_b64) VALUES(?,?,?,?,?,1,?,?,?,?,NULL,?)",
                (
                    vouch_id,
                    voucher,
                    vouchee,
                    scope,
                    note,
                    to_rfc3339(now),
                    int(now),
                    to_rfc3339(expires_at_epoch),
                    expires_at_epoch,
                    signature_b64,
                ),
            )
            self._append_audit(
                cur, "vouch.created", f"agent:{voucher}", "ok",
                vouchee, {"vouch_id": vouch_id, "scope": scope},
            )
            row = cur.execute("SELECT * FROM vouches WHERE vouch_id=?", (vouch_id,)).fetchone()
            return dict(row)

    def revoke_vouch(self, vouch_id: str, voucher: str, revoked_at_epoch: float) -> dict:
        with self._write() as cur:
            row = cur.execute(
                "SELECT * FROM vouches WHERE vouch_id=?", (vouch_id,)
            ).fetchone()
            if row is None or row["revoked_at"] is not None:
                raise DirectoryError("VOUCH_NOT_FOUND")
            if row["voucher_fingerprint"] != voucher:
                raise DirectoryError("SIGNATURE_MISMATCH", "revocation not by the voucher")
            cur.execute(
                "UPDATE vouches SET revoked_at=? WHERE vouch_id=?",
                (to_rfc3339(revoked_at_epoch), vouch_id),
            )
            self._append_audit(
                cur, "vouch.revoked", f"agent:{voucher}", "ok",
                row["vouchee_fingerprint"], {"vouch_id": vouch_id},
            )
            return dict(cur.execute(
                "SELECT * FROM vouches WHERE vouch_id=?", (vouch_id,)).fetchone())

    def inbound_vouches(self, fingerprint: str, active_only: bool = True) -> list[dict]:
        now = int(self.now())
        with self._lock:
            if active_only:
                rows = self._conn.execute(
                    "SELECT * FROM vouches WHERE vouchee_fingerprint=? AND revoked_at IS NULL "
                    "AND expires_epoch >= ? ORDER BY created_epoch DESC",
                    (fingerprint, now),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM vouches WHERE vouchee_fingerprint=? ORDER BY created_epoch DESC",
                    (fingerprint,),
                ).fetchall()
        return [dict(r) for r in rows]

    def outgoing_vouches(self, fingerprint: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM vouches WHERE voucher_fingerprint=? ORDER BY created_epoch DESC",
                (fingerprint,),
            ).fetchall()
        return [dict(r) for r in rows]

    def active_vouch_edges(self) -> list[dict]:
        now = int(self.now())
        with self._lock:
            rows = self._conn.execute(
                "SELECT voucher_fingerprint, vouchee_fingerprint, scope, created_at, "
                "expires_at, revoked_at FROM vouches WHERE revoked_at IS NULL AND expires_epoch >= ?",
                (now,),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- L4 reports & moderation ------------------------------------------
    def create_report(
        self,
        report_id: str,
        reporter: Optional[str],
        target: str,
        category: str,
        severity: str,
        evidence_kind: str,
        evidence_hash: Optional[str],
        description_hash: Optional[str],
        occurred_at: Optional[str],
        counts: bool,
        dup_window_s: int,
    ) -> dict:
        now = self.now()
        with self._write() as cur:
            if reporter is not None:
                dup = cur.execute(
                    "SELECT 1 FROM reports WHERE reporter_fingerprint=? AND target_fingerprint=? "
                    "AND category=? AND submitted_epoch > ?",
                    (reporter, target, category, int(now - dup_window_s)),
                ).fetchone()
                if dup is not None:
                    raise DirectoryError("REPORT_EXISTS")
            cur.execute(
                "INSERT INTO reports(report_id, reporter_fingerprint, target_fingerprint, "
                "category, severity, evidence_kind, evidence_hash, description_hash, "
                "occurred_at, submitted_at, submitted_epoch, counts, status) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'recorded')",
                (
                    report_id,
                    reporter,
                    target,
                    category,
                    severity,
                    evidence_kind,
                    evidence_hash,
                    description_hash,
                    occurred_at,
                    to_rfc3339(now),
                    int(now),
                    1 if counts else 0,
                ),
            )
            self._append_audit(
                cur, "report.recorded", f"agent:{reporter}" if reporter else "human_moderation_channel",
                "ok", target, {"report_id": report_id, "category": category, "counts": counts},
            )
            return dict(cur.execute(
                "SELECT * FROM reports WHERE report_id=?", (report_id,)).fetchone())

    def unique_eligible_reporters_in_window(
        self, target: str, category: str, window_s: int
    ) -> list[str]:
        now = self.now()
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT reporter_fingerprint FROM reports WHERE target_fingerprint=? "
                "AND category=? AND counts=1 AND reporter_fingerprint IS NOT NULL "
                "AND submitted_epoch > ?",
                (target, category, int(now - window_s)),
            ).fetchall()
        return [r["reporter_fingerprint"] for r in rows]

    def report_counters(self, target: str, decay_s: int) -> dict:
        now = self.now()
        floor = int(now - decay_s)
        with self._lock:
            rows = self._conn.execute(
                "SELECT category, reporter_fingerprint, submitted_at, submitted_epoch "
                "FROM reports WHERE target_fingerprint=? AND submitted_epoch > ?",
                (target, floor),
            ).fetchall()
        by_category: dict[str, int] = {}
        reporters = set()
        first_at = last_at = None
        for r in rows:
            by_category[r["category"]] = by_category.get(r["category"], 0) + 1
            if r["reporter_fingerprint"]:
                reporters.add(r["reporter_fingerprint"])
            if first_at is None or r["submitted_epoch"] < first_at[0]:
                first_at = (r["submitted_epoch"], r["submitted_at"])
            if last_at is None or r["submitted_epoch"] > last_at[0]:
                last_at = (r["submitted_epoch"], r["submitted_at"])
        return {
            "by_category": by_category,
            "unique_reporters": len(reporters),
            "first_at": first_at[1] if first_at else None,
            "last_at": last_at[1] if last_at else None,
        }

    def mutual_report_count(self, a: str, b: str, window_s: int) -> int:
        now = self.now()
        floor = int(now - window_s)
        with self._lock:
            ab = self._conn.execute(
                "SELECT COUNT(*) AS n FROM reports WHERE reporter_fingerprint=? "
                "AND target_fingerprint=? AND submitted_epoch > ?",
                (a, b, floor),
            ).fetchone()["n"]
            ba = self._conn.execute(
                "SELECT COUNT(*) AS n FROM reports WHERE reporter_fingerprint=? "
                "AND target_fingerprint=? AND submitted_epoch > ?",
                (b, a, floor),
            ).fetchone()["n"]
        return min(ab, ba)

    def suspend_agent(
        self, fingerprint: str, rule: str, evidence_reports: list, actor: str, event: str
    ) -> Optional[dict]:
        now = self.now()
        with self._write() as cur:
            row = cur.execute(
                "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if row is None:
                return None
            suspension = {
                "rule": rule,
                "evidence_reports": evidence_reports,
                "at": to_rfc3339(now),
            }
            cur.execute(
                "UPDATE agents SET status='suspended', suspension_json=?, suspended_at=? "
                "WHERE fingerprint=?",
                (json.dumps(suspension), to_rfc3339(now), fingerprint),
            )
            self._append_audit(
                cur, event, actor, "suspended", fingerprint, suspension
            )
            return dict(cur.execute(
                "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)).fetchone())

    def unsuspend_agent(self, fingerprint: str, actor: str, ttl_s: float) -> Optional[dict]:
        now = self.now()
        with self._write() as cur:
            row = cur.execute(
                "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            if row is None or row["status"] != "suspended":
                return None
            # Restore to listed with a fresh TTL window from now.
            cur.execute(
                "UPDATE agents SET status='listed', suspension_json=NULL, suspended_at=NULL, "
                "is_history=0, expires_at=?, expires_epoch=? WHERE fingerprint=?",
                (to_rfc3339(now + ttl_s), int(now + ttl_s), fingerprint),
            )
            self._append_audit(
                cur, "moderator.unsuspend", actor, "ok", fingerprint, {}
            )
            return dict(cur.execute(
                "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)).fetchone())

    def get_report(self, report_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM reports WHERE report_id=?", (report_id,)
            ).fetchone()
        return dict(row) if row else None

    def create_appeal(self, appeal_id: str, fingerprint: str, statement: str) -> dict:
        now = self.now()
        with self._write() as cur:
            cur.execute(
                "INSERT INTO appeals(appeal_id, fingerprint, statement, submitted_at, status) "
                "VALUES(?,?,?,?, 'open')",
                (appeal_id, fingerprint, statement, to_rfc3339(now)),
            )
            self._append_audit(
                cur, "appeal.submitted", f"agent:{fingerprint}", "ok",
                fingerprint, {"appeal_id": appeal_id},
            )
            return dict(cur.execute(
                "SELECT * FROM appeals WHERE appeal_id=?", (appeal_id,)).fetchone())

    # -- L5 checkpoints & agent audit -------------------------------------
    def insert_checkpoint(self, seq: int, entry_hash: str, ts: str, signature_b64: str) -> None:
        with self._write() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO checkpoints(seq, entry_hash, ts, signature_b64) "
                "VALUES(?,?,?,?)",
                (seq, entry_hash, ts, signature_b64),
            )

    def latest_checkpoint(self) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM checkpoints ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def list_checkpoints(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM checkpoints ORDER BY seq ASC LIMIT ?", (int(limit),)
            ).fetchall()
        return [dict(r) for r in rows]

    def audit_entry(self, seq: int) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM audit_log WHERE seq=?", (seq,)
            ).fetchone()
        return dict(row) if row else None

    def audit_entries_for_fingerprint(self, fingerprint: str, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, ts, event, fingerprint, actor, result, detail_hash "
                "FROM audit_log WHERE fingerprint=? ORDER BY seq ASC LIMIT ?",
                (fingerprint, int(limit)),
            ).fetchall()
        return [dict(r) for r in rows]

    def count_suspended(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM agents WHERE status='suspended'"
            ).fetchone()
        return int(row["n"])

    # -- misc --------------------------------------------------------------
    def meta_get(self, key: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key=?", (key,)
            ).fetchone()
        return row["value"] if row else None


def load_manifest_json(row: dict) -> dict:
    """Decode the stored manifest JSON of an agent row."""
    return json.loads(row["manifest_json"])
