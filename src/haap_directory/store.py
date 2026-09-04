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

CREATE TABLE IF NOT EXISTS appeal (
    appeal_id       TEXT PRIMARY KEY,
    fingerprint     TEXT NOT NULL,
    statement       TEXT NOT NULL,
    submitted_at    TEXT NOT NULL,
    submitted_epoch INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    decided_at      TEXT,
    decided_by      TEXT,
    decided_by_fp   TEXT
);
CREATE INDEX IF NOT EXISTS idx_appeal_fp ON appeal(fingerprint);

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
        # F4 additive migrations: epoch columns on the pre-reserved vouches /
        # reports tables so windows and expiry are compared on ints, not RFC3339
        # text (same reasoning as the F3 domain_verifications migration above).
        add = {
            "vouches": {"created_epoch": "INTEGER NOT NULL DEFAULT 0",
                        "expires_epoch": "INTEGER NOT NULL DEFAULT 0",
                        "revoked_epoch": "INTEGER"},
            "reports": {"submitted_epoch": "INTEGER NOT NULL DEFAULT 0",
                        "occurred_epoch": "INTEGER"},
        }
        with self._lock:
            for table, columns in add.items():
                present = {
                    r["name"] for r in self._conn.execute(
                        f"PRAGMA table_info({table})"
                    ).fetchall()
                }
                for name, decl in columns.items():
                    if name not in present:
                        self._conn.execute(
                            f"ALTER TABLE {table} ADD COLUMN {name} {decl}"
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

    # -- L3 vouches / L4 reports & suspension (F4) -------------------------
    def insert_vouch(
        self,
        vouch_id: str,
        voucher_fingerprint: str,
        vouchee_fingerprint: str,
        scope: str,
        note: Optional[str],
        weight: int,
        signature_b64: str,
        created_epoch: float,
        expires_epoch: float,
    ) -> dict:
        """Persist a granted vouch (audited) and return its row."""
        now = created_epoch
        with self._write() as cur:
            cur.execute(
                "INSERT INTO vouches(vouch_id, voucher_fingerprint, "
                "vouchee_fingerprint, scope, note, weight, signature_b64, "
                "created_at, created_epoch, expires_at, expires_epoch, "
                "revoked_at, revoked_epoch) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
                (
                    vouch_id,
                    voucher_fingerprint,
                    vouchee_fingerprint,
                    scope,
                    note,
                    weight,
                    signature_b64,
                    to_rfc3339(now),
                    int(now),
                    to_rfc3339(expires_epoch),
                    int(expires_epoch),
                ),
            )
            self._append_audit(
                cur,
                "vouch.granted",
                f"agent:{voucher_fingerprint}",
                "ok",
                vouchee_fingerprint,
                {
                    "vouch_id": vouch_id,
                    "voucher": voucher_fingerprint,
                    "vouchee": vouchee_fingerprint,
                    "scope": scope,
                    "expires_epoch": int(expires_epoch),
                },
            )
            row = cur.execute(
                "SELECT * FROM vouches WHERE vouch_id=?", (vouch_id,)
            ).fetchone()
            return dict(row)

    def active_vouch(
        self, voucher_fingerprint: str, vouchee_fingerprint: str, scope: str
    ) -> Optional[dict]:
        """A non-revoked, not-yet-expired vouch ('active'), if one exists."""
        now = int(self.now())
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM vouches WHERE voucher_fingerprint=? AND "
                "vouchee_fingerprint=? AND scope=? AND revoked_at IS NULL "
                "AND expires_epoch >= ? LIMIT 1",
                (voucher_fingerprint, vouchee_fingerprint, scope, now),
            ).fetchone()
        return dict(row) if row else None

    def get_vouch(self, vouch_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM vouches WHERE vouch_id=?", (vouch_id,)
            ).fetchone()
        return dict(row) if row else None

    def active_outgoing_count(self, voucher_fingerprint: str) -> int:
        """Number of currently-active outgoing vouches by a voucher (§4.4 cap)."""
        now = int(self.now())
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM vouches WHERE voucher_fingerprint=? "
                "AND revoked_at IS NULL AND expires_epoch >= ?",
                (voucher_fingerprint, now),
            ).fetchone()
        return int(row["n"])

    def revoke_vouch(self, vouch_id: str, revoked_epoch: float) -> Optional[dict]:
        """Revoke a vouch if it is currently active; else None."""
        now = int(revoked_epoch)
        with self._write() as cur:
            row = cur.execute(
                "SELECT * FROM vouches WHERE vouch_id=?", (vouch_id,)
            ).fetchone()
            if (
                row is None
                or row["revoked_at"] is not None
                or row["expires_epoch"] < int(now)
            ):
                return None
            cur.execute(
                "UPDATE vouches SET revoked_at=?, revoked_epoch=? WHERE vouch_id=?",
                (to_rfc3339(now), int(now), vouch_id),
            )
            self._append_audit(
                cur,
                "vouch.revoked",
                "directory",
                "ok",
                row["vouchee_fingerprint"],
                {"vouch_id": vouch_id, "voucher": row["voucher_fingerprint"]},
            )
            fresh = cur.execute(
                "SELECT * FROM vouches WHERE vouch_id=?", (vouch_id,)
            ).fetchone()
            return dict(fresh)

    def list_vouches(
        self,
        fingerprint: str,
        direction: str,
        only_active: bool = True,
    ) -> list[dict]:
        """Inbound (vouches into ``fingerprint``) or outbound (from it).

        Active edges exclude revoked/expired ones; each returned row gains a
        ``status`` ('active'/'revoked'/'expired') for the consumer.
        """
        now = int(self.now())
        if direction == "incoming":
            cond = "vouchee_fingerprint=?"
        elif direction == "outgoing":
            cond = "voucher_fingerprint=?"
        else:  # pragma: no cover - caller guards
            raise ValueError("direction must be 'incoming' or 'outgoing'")
        if only_active:
            cond += " AND revoked_at IS NULL AND expires_epoch >= " + str(now)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM vouches WHERE {cond} "
                "ORDER BY created_epoch DESC",
                (fingerprint,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if d["revoked_at"] is not None:
                status = "revoked"
            elif d["expires_epoch"] < now:
                status = "expired"
            else:
                status = "active"
            d["status"] = status
            out.append(d)
        return out

    def active_vouch_count(self, fingerprint: str) -> int:
        """Total active inbound vouches for ``fingerprint`` (visible edges)."""
        now = int(self.now())
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM vouches WHERE vouchee_fingerprint=? "
                "AND revoked_at IS NULL AND expires_epoch >= ?",
                (fingerprint, now),
            ).fetchone()
        return int(row["n"])

    def insert_report(
        self,
        report_id: str,
        reporter_fingerprint: Optional[str],
        target_fingerprint: str,
        category: str,
        severity: str,
        evidence_kind: str,
        evidence_hash: Optional[str],
        description_hash: Optional[str],
        occurred_at: Optional[str],
        occurrence_count: int,
        submitted_epoch: float,
    ) -> str:
        """Persist a recorded report (audited) and return the report id.

        ``occurrence_count`` records how many times the reporter observed the
        behaviour (minimum 1) — surfaced to consumers but the directory never
        weights automation by it, only by eligible *unique reporters*.
        """
        now = submitted_epoch
        reporter = reporter_fingerprint or "human_moderation_channel"
        occurrence_count = max(1, int(occurrence_count or 1))
        with self._write() as cur:
            cur.execute(
                "INSERT INTO reports(report_id, reporter_fingerprint, "
                "target_fingerprint, category, severity, evidence_kind, "
                "evidence_hash, description_hash, occurred_at, submitted_at, "
                "submitted_epoch, counts, status) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?, 'recorded')",
                (
                    report_id,
                    reporter,
                    target_fingerprint,
                    category,
                    severity,
                    evidence_kind,
                    evidence_hash,
                    description_hash,
                    occurred_at,
                    to_rfc3339(now),
                    int(now),
                    occurrence_count,
                ),
            )
            self._append_audit(
                cur,
                "report.recorded",
                f"agent:{reporter}" if reporter_fingerprint else "human_moderation_channel",
                "ok",
                target_fingerprint,
                {
                    "report_id": report_id,
                    "reporter": reporter,
                    "target": target_fingerprint,
                    "category": category,
                },
            )
            return report_id

    def recent_report_by(
        self,
        reporter_fingerprint: str,
        target_fingerprint: str,
        category: str,
        window_s: int,
    ) -> Optional[dict]:
        """Most recent report by ``reporter`` on ``target`` in ``category`` if
        inside the throttle window, else None."""
        now = int(self.now())
        lower = now - window_s
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM reports WHERE reporter_fingerprint=? AND "
                "target_fingerprint=? AND category=? AND submitted_epoch >= ? "
                "ORDER BY submitted_epoch DESC LIMIT 1",
                (reporter_fingerprint, target_fingerprint, category, lower),
            ).fetchone()
        return dict(row) if row else None

    def unique_reporters_in_window(
        self,
        target_fingerprint: str,
        category: str,
        window_s: int,
        decay_s: int,
        min_reporter_tenure_s: int,
    ) -> tuple[list[dict], bool]:
        """Eligible reports against a target in a rolling window.

        Returns (rows, has_recent_decayed_report) where rows are the reports
        whose reporter is a currently-live, listed agent registered >=
        ``min_reporter_tenure_s`` ago and report is within ``window_s``;
        decay_s bounds how old a report can be before it stops counting at all.
        Aggregation over per-reporter rows so one reporter counts once.
        """
        now = int(self.now())
        lower_bounds = now - window_s
        oldest = now - decay_s
        # Non-decayed reports in the window for the target+category.
        with self._lock:
            rows = self._conn.execute(
                "SELECT r.*, a.registered_epoch AS reporter_registered, "
                "a.status AS reporter_status, a.is_history AS reporter_history "
                "FROM reports r JOIN agents a ON a.fingerprint=r.reporter_fingerprint "
                "WHERE r.target_fingerprint=? AND r.category=? "
                "AND r.submitted_epoch >= ? AND r.submitted_epoch >= ? "
                "ORDER BY r.submitted_epoch ASC",
                (target_fingerprint, category, oldest, lower_bounds),
            ).fetchall()
        eligible = []
        seen_reporter = set()
        for r in rows:
            if (
                r["reporter_fingerprint"] not in seen_reporter
                and r["reporter_status"] == "listed"
                and not r["reporter_history"]
                and r["reporter_registered"]
                and (now - r["reporter_registered"]) >= min_reporter_tenure_s
            ):
                seen_reporter.add(r["reporter_fingerprint"])
                eligible.append(dict(r))
        # Whether the agent holds any decayed report (from reporters not in the
        # window, older than decay, still visible).
        with self._lock:
            has_decayed = bool(
                self._conn.execute(
                    "SELECT 1 FROM reports WHERE target_fingerprint=? AND "
                    "category=? AND submitted_epoch < ? LIMIT 1",
                    (target_fingerprint, category, oldest),
                ).fetchone()
            )
        return eligible, has_decayed

    def list_reports(
        self, target_fingerprint: str, category: Optional[str] = None
    ) -> list[dict]:
        """All visible reports against a target (live + decayed history)."""
        with self._lock:
            if category:
                rows = self._conn.execute(
                    "SELECT * FROM reports WHERE target_fingerprint=? AND category=? "
                    "ORDER BY submitted_epoch DESC",
                    (target_fingerprint, category),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM reports WHERE target_fingerprint=? "
                    "ORDER BY submitted_epoch DESC",
                    (target_fingerprint,),
                ).fetchall()
        return [dict(r) for r in rows]

    def set_agent_suspended(
        self,
        fingerprint: str,
        rule: str,
        reason: str,
        evidence_reports: list[str],
        at_epoch: float,
        actor: str,
        event: str,
    ) -> Optional[dict]:
        """Suspend a listed agent (auto or moderator). Returns updated row."""
        now = int(at_epoch)
        suspension = {
            "rule": rule,
            "reason": reason,
            "evidence_reports": evidence_reports,
            "at": to_rfc3339(now),
            "by": actor,
        }
        with self._write() as cur:
            row = cur.execute(
                "UPDATE agents SET status='suspended', suspension_json=?, "
                "suspended_at=? WHERE fingerprint=?",
                (json.dumps(suspension), to_rfc3339(now), fingerprint),
            )
            if row.rowcount == 0:
                return None
            self._append_audit(
                cur,
                event,
                actor,
                "suspended",
                fingerprint,
                suspension,
            )
            fresh = cur.execute(
                "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            return dict(fresh)

    def clear_agent_suspension(
        self, fingerprint: str, at_epoch: float, actor: str, event: str
    ) -> Optional[dict]:
        """Lift a suspension (moderator unsuspend/appeal grant)."""
        now = int(at_epoch)
        with self._write() as cur:
            row = cur.execute(
                "UPDATE agents SET status='listed', suspension_json=NULL, "
                "suspended_at=NULL WHERE fingerprint=? AND status='suspended'",
                (fingerprint,),
            )
            if row.rowcount == 0:
                return None
            self._append_audit(cur, event, actor, "ok", fingerprint, {"at": now})
            fresh = cur.execute(
                "SELECT * FROM agents WHERE fingerprint=?", (fingerprint,)
            ).fetchone()
            return dict(fresh)

    def find_report(self, report_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM reports WHERE report_id=?", (report_id,)
            ).fetchone()
        return dict(row) if row else None

    def insert_appeal(
        self,
        appeal_id: str,
        fingerprint: str,
        statement: str,
        submitted_epoch: float,
    ) -> dict:
        """Record an agent's appeal against its suspension (audited)."""
        now = int(submitted_epoch)
        with self._write() as cur:
            cur.execute(
                "INSERT OR REPLACE INTO appeal(appeal_id, fingerprint, "
                "statement, submitted_at, submitted_epoch, status, decided_at) "
                "VALUES(?,?,?,?,?,'pending',NULL)",
                (appeal_id, fingerprint, statement, to_rfc3339(now), now),
            )
            self._append_audit(
                cur,
                "appeal.submitted",
                f"agent:{fingerprint}",
                "ok",
                fingerprint,
                {"appeal_id": appeal_id, "statement_length": len(statement)},
            )
            row = cur.execute(
                "SELECT * FROM appeal WHERE appeal_id=?", (appeal_id,)
            ).fetchone()
            return dict(row)

    def get_appeal(self, appeal_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM appeal WHERE appeal_id=?", (appeal_id,)
            ).fetchone()
        return dict(row) if row else None

    def decide_appeal(
        self,
        appeal_id: str,
        fingerprint: str,
        decision: str,
        decided_epoch: float,
        actor_fp: str,
    ) -> Optional[dict]:
        """Mark an appeal granted/denied by a moderator. Returns row or None."""
        now = int(decided_epoch)
        event = "appeal.granted" if decision == "granted" else "appeal.denied"
        with self._write() as cur:
            appeal = cur.execute(
                "SELECT * FROM appeal WHERE appeal_id=?", (appeal_id,)
            ).fetchone()
            if appeal is None or appeal["status"] != "pending":
                return None
            cur.execute(
                "UPDATE appeal SET status=?, decided_at=?, decided_by=?, "
                "decided_by_fp=? WHERE appeal_id=?",
                (decision, to_rfc3339(now), f"moderator:{actor_fp}", actor_fp, appeal_id),
            )
            self._append_audit(
                cur, event, actor_fp, "ok", fingerprint or appeal["fingerprint"],
                {"appeal_id": appeal_id, "decision": decision},
            )
            fresh = cur.execute(
                "SELECT * FROM appeal WHERE appeal_id=?", (appeal_id,)
            ).fetchone()
            return dict(fresh)

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
