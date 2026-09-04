# -*- coding: utf-8 -*-
"""Shared test fixtures for the HAAP directory.

Real HTTP on an ephemeral 127.0.0.1 port (like the existing haap tests), an
injectable ``MutableClock`` so TTL/expiry logic is exercised without sleeping,
and a small agent kit that signs extended manifests the way the wire expects.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory.config import DirectoryConfig  # noqa: E402
from haap_directory.crypto import KeyPair  # noqa: E402
from haap_directory.http_api import DirectoryHTTPServer  # noqa: E402
from haap_directory.identity import fingerprint_of_public_key  # noqa: E402


class MutableClock:
    """A controllable clock: call to read, ``advance`` to move it forward."""

    def __init__(self, start: float = 1_700_000_000.0):
        self.t = float(start)

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += float(seconds)


@dataclass
class Agent:
    """A test agent: key pair + fingerprint + manifest signing helpers."""

    keypair: KeyPair
    name: str = "Test Agent"
    endpoint: str = "http://agent.example:8443/haap/messages"

    @property
    def fingerprint(self) -> str:
        return fingerprint_of_public_key(self.keypair.public_key)

    @property
    def public_key_b64(self) -> str:
        return self.keypair.public_key_b64()

    def manifest(self, **overrides) -> dict:
        manifest = {
            "format": "haap-public-manifest-v1",
            "protocol_version": "1.0",
            "agent": {
                "fingerprint": self.fingerprint,
                "name": self.name,
                "speciality": "citas-peluqueria",
                "endpoint": self.endpoint,
            },
            "message_types": ["hello", "task_request", "ping"],
            "skills": [{"name": "booking", "description": "appointment booking"}],
            "tools": ["caldav"],
        }
        agent_over = overrides.pop("agent", None)
        if agent_over:
            manifest["agent"].update(agent_over)
        manifest.update(overrides)
        return manifest

    def sign_manifest(self, manifest: dict) -> str:
        canonical = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return base64.b64encode(self.keypair.sign(canonical)).decode("ascii")

    def sign_nonce(self, nonce: str) -> str:
        return base64.b64encode(self.keypair.sign(nonce.encode("ascii"))).decode("ascii")


def make_agent(name: str = "Test Agent", endpoint: Optional[str] = None) -> Agent:
    kwargs = {"keypair": KeyPair.generate(), "name": name}
    if endpoint is not None:
        kwargs["endpoint"] = endpoint
    return Agent(**kwargs)


# -- HTTP helpers ----------------------------------------------------------
def http_post(url: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def http_get(url: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def register_agent(url: str, agent: Agent) -> dict:
    """Full 3-step v1 registration; returns the completion response."""
    manifest = agent.manifest()
    _, resp = http_post(
        f"{url}/v1/register",
        {
            "manifest": manifest,
            "public_key_b64": agent.public_key_b64,
            "manifest_signature": agent.sign_manifest(manifest),
        },
    )
    proof = agent.sign_nonce(resp["nonce"])
    _, resp2 = http_post(
        f"{url}/v1/register/complete",
        {
            "challenge_id": resp["challenge_id"],
            "fingerprint": agent.fingerprint,
            "endpoint_proof": proof,
            "public_key_b64": agent.public_key_b64,
        },
    )
    return resp2


@dataclass
class RunningServer:
    url: str
    server: DirectoryHTTPServer
    clock: MutableClock
    config: DirectoryConfig


@pytest.fixture()
def clock() -> MutableClock:
    return MutableClock()


@pytest.fixture()
def make_server(tmp_path, clock):
    """Factory building started directory servers sharing the test clock."""
    servers: list[DirectoryHTTPServer] = []
    counter = {"n": 0}

    def _factory(**config_overrides) -> RunningServer:
        counter["n"] += 1
        db_path = str(tmp_path / f"dird_{counter['n']}.db")
        defaults = dict(
            db_path=db_path,
            host="127.0.0.1",
            port=0,
            # Generous rate limits so multi-agent tests are not throttled;
            # dedicated abuse tests set their own low limits.
            rate_register_per_hour=100_000,
            rate_search_per_min=100_000,
        )
        defaults.update(config_overrides)
        config = DirectoryConfig(**defaults)
        keypair = KeyPair.generate()
        server = DirectoryHTTPServer.build(config, keypair, clock=clock)
        http = server.start()
        servers.append(server)
        url = f"http://127.0.0.1:{http.server_address[1]}"
        return RunningServer(url=url, server=server, clock=clock, config=config)

    yield _factory

    for s in servers:
        s.stop()


@pytest.fixture()
def running(make_server) -> RunningServer:
    return make_server()


@pytest.fixture()
def running_full(make_server) -> RunningServer:
    """A directory whose agent cap is 1, for the DIRECTORY_FULL path."""
    return make_server(max_agents=1)
