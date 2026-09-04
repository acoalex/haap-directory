# -*- coding: utf-8 -*-
"""L5 foundation: every op appends, chain is hash-linked and tamper-evident."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory import audit
from tests.conftest import http_get, make_agent, register_agent


def test_every_mutation_appends_one_entry(running):
    head0 = running.server.service.store.audit_head()["seq"]
    register_agent(running.url, make_agent("A"))
    head1 = running.server.service.store.audit_head()["seq"]
    # A registration appends: challenge_issued + register.completed (>= 2 entries).
    assert head1 >= head0 + 2


def test_chain_links_and_verifies(running):
    for i in range(3):
        register_agent(running.url, make_agent(f"A{i}"))
    entries = running.server.service.store.audit_entries(after=-1, limit=1000)
    assert entries[0]["event"] == audit.GENESIS_EVENT
    assert audit.verify_chain(entries) is True


def test_audit_log_endpoint_contiguous(running):
    register_agent(running.url, make_agent("A"))
    status, body = http_get(f"{running.url}/v1/audit/log?after=-1&limit=1000")
    assert status == 200
    seqs = [e["seq"] for e in body["entries"]]
    assert seqs == list(range(len(seqs)))
    assert body["head"]["seq"] == seqs[-1]


def test_tampering_breaks_verification(running):
    register_agent(running.url, make_agent("A"))
    entries = running.server.service.store.audit_entries(after=-1, limit=1000)
    assert audit.verify_chain(entries) is True
    # Flip one event field: re-hash no longer matches the stored entry_hash.
    entries[1]["event"] = "register.tampered"
    assert audit.verify_chain(entries) is False


def test_detail_hash_carries_no_secret_body(running):
    register_agent(running.url, make_agent("A"))
    entries = running.server.service.store.audit_entries(after=-1, limit=1000)
    for e in entries:
        # Only a hash is stored, never a detail body.
        assert len(e["detail_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in e["detail_hash"])
