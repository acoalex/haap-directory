# -*- coding: utf-8 -*-
"""Federation seam — an audit-chain mirror (SPEC §6.4, §7 F6).

A mirror ingests a directory's public hash chain (``/v1/audit/log``), verifies
its linkage locally, and reproduces the head. Two independent operators whose
mirrors agree on a head prove they saw the same ordered world — federation
without a central registry-of-directories. This is deliberately read-only and
dependency-free (stdlib HTTP + the local chain verifier).
"""

from __future__ import annotations

import json
import urllib.request
from typing import Optional

from . import audit


def _get(url: str, timeout: float = 10.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def ingest_chain(base_url: str, page: int = 500) -> dict:
    """Download and verify a directory's full audit chain.

    Returns ``{seq, entry_hash, entries, verified, matches_served_head}``.
    """
    base = base_url.rstrip("/")
    entries: list[dict] = []
    after = -1
    while True:
        body = _get(f"{base}/v1/audit/log?after={after}&limit={page}")
        batch = body.get("entries", [])
        if not batch:
            break
        entries.extend(batch)
        after = batch[-1]["seq"]
        if len(batch) < page:
            break

    verified = audit.verify_chain(entries)
    served_head = _get(f"{base}/v1/audit/head")
    local_head_hash = entries[-1]["entry_hash"] if entries else None
    return {
        "seq": entries[-1]["seq"] if entries else -1,
        "entry_hash": local_head_hash,
        "entries": entries,
        "verified": verified,
        "matches_served_head": (
            verified and local_head_hash == served_head.get("entry_hash")
        ),
    }
