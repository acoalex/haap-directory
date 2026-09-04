# -*- coding: utf-8 -*-
"""F0: persistent store, health, config precedence, audit genesis."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory import audit
from haap_directory.config import DEFAULT_CONFIG_PATH, DirectoryConfig
from haap_directory.store import Store
from tests.conftest import MutableClock, http_get, register_agent, make_agent


def test_health_boots_empty(running):
    status, body = http_get(f"{running.url}/health")
    assert status == 200
    assert body["status"] == "ok"
    assert body["agents"] == 0
    assert body["version"]
    assert body["directory_fingerprint"].startswith("HF-")
    assert body["api"]["completion_route"] == "/v1/register/complete"


def test_genesis_entry_created(tmp_path):
    clock = MutableClock()
    store = Store(str(tmp_path / "g.db"), clock=clock)
    head = store.audit_head()
    assert head["seq"] == 0
    entries = store.audit_entries(after=-1, limit=10)
    assert len(entries) == 1
    assert entries[0]["event"] == audit.GENESIS_EVENT
    assert entries[0]["prev_hash"] == audit.GENESIS_PREV_HASH
    store.close()


def test_persistence_across_restart(tmp_path):
    clock = MutableClock()
    db = str(tmp_path / "p.db")
    store = Store(db, clock=clock)
    store.insert_challenge(
        challenge_id="ch_x",
        fingerprint="HF-0000000000000000",
        nonce="v1:register:abc",
        public_key_b64="pk",
        endpoint="http://x.example",
        ttl_s=120,
    )
    store.close()

    store2 = Store(db, clock=clock)
    ch = store2.get_challenge("ch_x")
    assert ch is not None and ch["nonce"] == "v1:register:abc"
    # No secrets leak into the challenge row beyond the (public) key material.
    assert "private_key" not in ch
    store2.close()


def test_config_precedence_cli_over_file_over_env(tmp_path, monkeypatch):
    cfg_file = tmp_path / "dird.json"
    cfg_file.write_text(json.dumps({"port": 5000, "ttl_hours": 12}))
    monkeypatch.setenv("HAAP_DIRD_PORT", "9000")
    monkeypatch.setenv("HAAP_DIRD_MAX_AGENTS", "42")

    cfg = DirectoryConfig.load(
        cli_overrides={"port": 7000}, config_path=str(cfg_file)
    )
    # CLI wins over file wins over env for port.
    assert cfg.port == 7000
    # File value used where no CLI override.
    assert cfg.ttl_hours == 12
    # Env used where neither file nor CLI set it.
    assert cfg.max_agents == 42


def test_count_live_after_registration(running):
    agent = make_agent("Counter")
    resp = register_agent(running.url, agent)
    assert resp["status"] == "registered"
    assert running.server.service.store.count_live() == 1
