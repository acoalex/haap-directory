# -*- coding: utf-8 -*-
"""L5 transparency: append-only, hash-chained audit log helpers (SPEC §3.6).

Pure functions only — no storage. ``store.py`` calls these to append an
entry inside the same SQLite transaction as the state change it records, so
there is never a window where state moved without a log line.

Chain construction (normative, SPEC §3.6.1):

    entry[n]      = {seq, ts, event, fingerprint, actor, result,
                     detail_hash, prev_hash}
    entry_hash[n] = sha256(canonical_json(entry[n]))
    entry[0]      = genesis: prev_hash = "0" * 64

``detail_hash`` is the sha256 of the canonical JSON of a detail object, so
sensitive detail bodies never enter the chain — only their hash does.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from .canonical import canonical_json

GENESIS_PREV_HASH = "0" * 64
GENESIS_EVENT = "chain.genesis"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detail_hash(detail: Optional[Any]) -> str:
    """sha256 hex of the canonical JSON of a detail object ({} if None)."""
    return sha256_hex(canonical_json(detail if detail is not None else {}))


def build_entry(
    seq: int,
    ts: str,
    event: str,
    actor: str,
    result: str,
    prev_hash: str,
    detail_hash_hex: str,
    fingerprint: Optional[str] = None,
) -> dict:
    """Construct the canonical audit entry object (without ``entry_hash``)."""
    return {
        "seq": seq,
        "ts": ts,
        "event": event,
        "fingerprint": fingerprint,
        "actor": actor,
        "result": result,
        "detail_hash": detail_hash_hex,
        "prev_hash": prev_hash,
    }


def entry_hash(entry: dict) -> str:
    """entry_hash[n] = sha256(canonical_json(entry[n]))."""
    return sha256_hex(canonical_json(entry))


def verify_chain(entries: list[dict]) -> bool:
    """Verify a contiguous list of entries links correctly.

    Each ``entries[i]`` is a full row dict containing at least the canonical
    fields plus the stored ``entry_hash``. Re-computes every hash and checks
    ``prev_hash`` linkage. Returns ``True`` iff the chain is intact.
    """
    prev = None
    for row in entries:
        core = build_entry(
            seq=row["seq"],
            ts=row["ts"],
            event=row["event"],
            actor=row["actor"],
            result=row["result"],
            prev_hash=row["prev_hash"],
            detail_hash_hex=row["detail_hash"],
            fingerprint=row.get("fingerprint"),
        )
        if entry_hash(core) != row["entry_hash"]:
            return False
        if prev is not None and row["prev_hash"] != prev:
            return False
        prev = row["entry_hash"]
    return True
