# -*- coding: utf-8 -*-
"""Backwards compatibility: the UNMODIFIED ``haap`` client works against us.

The standalone directory must serve the legacy routes so the unmodified
``haap.registry_client`` (register / search / heartbeat) keeps working
without changes (SPEC §4.9, §6.3).

The haap client package is located via the ``HAAP_REPO`` env var or the
sibling ``../haap`` checkout. If neither is present the test is skipped with
a clear reason (it cannot run without the companion package).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def _find_haap_repo() -> Path | None:
    candidates = []
    if os.environ.get("HAAP_REPO"):
        candidates.append(Path(os.environ["HAAP_REPO"]))
    candidates.append(Path(__file__).resolve().parents[2] / "haap")
    for path in candidates:
        if (path / "haap" / "registry_client.py").exists():
            return path
    return None


_HAAP_REPO = _find_haap_repo()
pytestmark = pytest.mark.skipif(
    _HAAP_REPO is None,
    reason="companion haap client package not found (set HAAP_REPO or place ../haap)",
)

if _HAAP_REPO is not None:
    sys.path.insert(0, str(_HAAP_REPO))


def test_unmodified_client_register_search_heartbeat(running):
    from haap.identity import IdentityStore
    from haap.registry_client import heartbeat, register, search

    from tests.conftest import make_agent  # noqa: F401 - ensures src path set

    tmp = Path(running.config.db_path).parent
    business = IdentityStore(str(tmp / "biz")).create(
        "Peluqueria Euraka", endpoint_url="http://biz.example:8443/haap/messages"
    )

    resp = register(
        running.url,
        business,
        "http://biz.example:8443/haap/messages",
        speciality="citas-peluqueria",
    )
    assert resp["status"] == "registered"

    # Legacy unsigned heartbeat renews the entry.
    assert heartbeat(running.url, business.fingerprint) is True

    # Discovery by capability returns bare manifests.
    results = search(running.url, capability="citas-peluqueria")
    assert len(results) == 1
    assert results[0]["agent"]["fingerprint"] == business.fingerprint
    assert results[0]["agent"]["endpoint"] == "http://biz.example:8443/haap/messages"

    # Free-text search also finds it.
    assert len(search(running.url, q="peluqueria")) == 1
