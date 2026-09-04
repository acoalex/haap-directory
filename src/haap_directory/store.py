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
    verified_epoch INTEGER NOT NULL DEFAULT 0,
    expires_at     TEXT NOT NULL,
    expires_epoch  INTEGER NOT NULL DEFAULT 0,
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
    expires_at          TEXT NOT NULL,
    revoked_at          TEXT,
    signature_b64       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vouches_vouchee ON vouches(vouchee_fingerprint);

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
    counts              INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'recorded'
);
CREATE INDEX IF NOT EXISTS idx_reports_target ON reports(target_fingerprint);

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
            # Additive migration for pre-existing domain_verifications tables
            # created before the epoch columns existed (F3).
            cols = {
                r["name"]
                for r in self._conn.execute(
                    "PRAGMA table_info(domain_verifications)"
                ).fetchall()
            }
            if "verified_epoch" not in cols:
                self._conn.execute(
                    "ALTER TABLE domain_verifications "
                    "ADD COLUMN verified_epoch INTEGER NOT NULL DEFAULT 0"
                )
            if "expires_epoch" not in cols:
                self._conn.execute(
                    "ALTER TABLE domain_verifications "
                    "ADD COLUMN expires_epoch INTEGER NOT NULL DEFAULT 0"
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
        domain: Optional[str] = None,
        method: Optional[str] = None,
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
                "nonce, endpoint, manifest_json, domain, method, "
                "created_at, created_epoch, expires_epoch, used) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0)",
                (
                    challenge_id,
                    kind,
                    fingerprint,
                    public_key_b64,
                    nonce,
                    endpoint,
                    manifest_json,
                    domain,
                    method,
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

    # -- domain verifications (L2) ------------------------------------------
    def insert_domain_verification(
        self,
        verification_id: str,
        fingerprint: str,
        domain: str,
        method: str,
        verified_at_epoch: float,
        validity_days: float,
        endpoint_match: bool,
        challenge_id: str,
    ) -> dict:
        """Persist a successful L2 check (audited) and return the row."""
        now = verified_at_epoch
        expires_epoch = int(now + validity_days * 86400.0)
        with self._write() as cur:
            cur.execute(
                "INSERT INTO domain_verifications(id, fingerprint, domain, method, "
                "verified_at, verified_epoch, expires_at, expires_epoch, "
                "endpoint_match, challenge_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
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
                cur,
                "domain.verified",
                f"agent:{fingerprint}",
                "ok",
                fingerprint,
                {
                    "domain": domain,
                    "method": method,
                    "verification_id": verification_id,
                    "endpoint_match": bool(endpoint_match),
                },
            )
            row = cur.execute(
                "SELECT * FROM domain_verifications WHERE id=?", (verification_id,)
            ).fetchone()
            return dict(row)

    def active_domain_verifications(self, fingerprint: str) -> list[dict]:
        """Unexpired verification rows for an agent, newest first."""
        now = int(self.now())
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM domain_verifications WHERE fingerprint=? "
                "AND expires_epoch >= ? ORDER BY verified_epoch DESC",
                (fingerprint, now),
            ).fetchall()
        return [dict(r) for r in rows]

    def count_pending_domain_challenges(self, fingerprint: str) -> int:
        now = int(self.now())
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM challenges WHERE fingerprint=? "
                "AND kind='domain' AND used=0 AND expires_epoch > ?",
                (fingerprint, now),
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
