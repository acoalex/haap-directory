# -*- coding: utf-8 -*-
"""F4: L4 reports, eligibility, auto-suspend automaton, moderation, appeal."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from haap_directory.timeutil import to_rfc3339
from tests.conftest import http_get, http_post, make_agent, register_agent

# Keep entries alive for the whole 72 h+ tenure window in reputation tests.
LONG_TTL = {"ttl_hours": 10_000}


def _report_body(running, reporter, target, category="spam", severity="high", kind="envelope"):
    body = {
        "reporter_fingerprint": reporter.fingerprint,
        "target_fingerprint": target.fingerprint,
        "category": category,
        "severity": severity,
        "evidence": {"kind": kind, "description": "demanded prepayment then vanished"},
        "occurred_at": to_rfc3339(running.clock()),
    }
    body["signature"] = reporter.sign_payload(body)
    return body


def test_young_reporter_recorded_but_not_counted(running):
    reporter, target = make_agent("R"), make_agent("T")
    register_agent(running.url, reporter)
    register_agent(running.url, target)
    st, resp = http_post(f"{running.url}/v1/reports", _report_body(running, reporter, target))
    assert st == 202
    assert resp["counts_toward_automation"] is False


def test_duplicate_report_rejected(running):
    reporter, target = make_agent("R"), make_agent("T")
    register_agent(running.url, reporter)
    register_agent(running.url, target)
    http_post(f"{running.url}/v1/reports", _report_body(running, reporter, target))
    st, resp = http_post(f"{running.url}/v1/reports", _report_body(running, reporter, target))
    assert st == 409 and resp["error"]["code"] == "REPORT_EXISTS"


def test_target_must_be_listed(running):
    reporter = make_agent("R")
    target = make_agent("T")  # not registered
    register_agent(running.url, reporter)
    st, resp = http_post(f"{running.url}/v1/reports", _report_body(running, reporter, target))
    assert st == 404 and resp["error"]["code"] == "TARGET_NOT_LISTED"


def test_auto_suspend_after_three_eligible_reporters(make_server):
    running = make_server(**LONG_TTL)
    target = make_agent("Target")
    register_agent(running.url, target)
    reporters = [make_agent(f"R{i}") for i in range(3)]
    for r in reporters:
        register_agent(running.url, r)
    # Age everyone past the 72 h tenure requirement.
    running.clock.advance(running.config.report_tenure_hours * 3600 + 60)
    for i, r in enumerate(reporters):
        st, resp = http_post(f"{running.url}/v1/reports", _report_body(running, r, target, "spam"))
        assert st == 202
        assert resp["counts_toward_automation"] is True
    # Third eligible report in the abuse class auto-suspends the target.
    st, _ = http_get(f"{running.url}/v1/agents/{target.fingerprint}")
    assert st == 404  # hidden from anonymous callers
    _, health = http_get(f"{running.url}/health")
    assert health["suspended"] == 1
    # The suspended target is excluded from search (not_suspended default);
    # the (unsuspended) reporters still appear.
    _, search = http_get(f"{running.url}/v1/search?capability=citas-peluqueria")
    fps = {r["manifest"]["agent"]["fingerprint"] for r in search["results"]}
    assert target.fingerprint not in fps
    assert len(fps) == 3


def test_non_abuse_class_does_not_auto_suspend(make_server):
    running = make_server(**LONG_TTL)
    target = make_agent("Target")
    register_agent(running.url, target)
    running.clock.advance(running.config.report_tenure_hours * 3600 + 60)
    for i in range(3):
        r = make_agent(f"R{i}")
        register_agent(running.url, r)
        http_post(f"{running.url}/v1/reports", _report_body(running, r, target, "abusive_content"))
    _, health = http_get(f"{running.url}/health")
    assert health["suspended"] == 0


def test_moderator_takedown(make_server):
    mod = make_agent("mod")
    running = make_server(moderator_keys=[mod.public_key_b64])
    reporter, target = make_agent("R"), make_agent("T")
    register_agent(running.url, reporter)
    register_agent(running.url, target)
    _, rep = http_post(f"{running.url}/v1/reports", _report_body(running, reporter, target, "fraud"))
    report_id = rep["report_id"]

    body = {"moderator_fingerprint": mod.fingerprint, "report_id": report_id, "reason": "scam"}
    body["signature"] = mod.sign_payload(body)
    # signature covers moderator_fingerprint+report_id+reason (subset used by server)
    body["signature"] = mod.sign_payload(
        {"moderator_fingerprint": mod.fingerprint, "report_id": report_id, "reason": "scam"}
    )
    st, resp = http_post(f"{running.url}/v1/reports/{report_id}/takedown", body)
    assert st == 200 and resp["status"] == "suspended"
    st2, _ = http_get(f"{running.url}/v1/agents/{target.fingerprint}")
    assert st2 == 404


def test_moderator_unknown_and_unauthorized(make_server):
    mod = make_agent("mod")
    running = make_server(moderator_keys=[mod.public_key_b64])
    reporter, target = make_agent("R"), make_agent("T")
    register_agent(running.url, reporter)
    register_agent(running.url, target)
    _, rep = http_post(f"{running.url}/v1/reports", _report_body(running, reporter, target, "fraud"))
    rid = rep["report_id"]

    # Unknown moderator fingerprint.
    stranger = make_agent("stranger")
    body = {"moderator_fingerprint": stranger.fingerprint, "report_id": rid, "reason": "x"}
    body["signature"] = stranger.sign_payload(body)
    st, resp = http_post(f"{running.url}/v1/reports/{rid}/takedown", body)
    assert st == 403 and resp["error"]["code"] == "MODERATOR_UNKNOWN"

    # Known moderator, bad signature.
    body2 = {"moderator_fingerprint": mod.fingerprint, "report_id": rid, "reason": "x",
             "signature": "AAAA"}
    st2, resp2 = http_post(f"{running.url}/v1/reports/{rid}/takedown", body2)
    assert st2 == 403 and resp2["error"]["code"] == "TAKEDOWN_UNAUTHORIZED"


def test_moderator_suspend_unsuspend_and_appeal(make_server):
    mod = make_agent("mod")
    running = make_server(moderator_keys=[mod.public_key_b64])
    target = make_agent("T")
    register_agent(running.url, target)

    sus = {"moderator_fingerprint": mod.fingerprint, "fingerprint": target.fingerprint,
           "reason": "manual"}
    sus["signature"] = mod.sign_payload(sus)
    sus["signature"] = mod.sign_payload(
        {"moderator_fingerprint": mod.fingerprint, "fingerprint": target.fingerprint,
         "reason": "manual"}
    )
    st, _ = http_post(f"{running.url}/v1/agents/{target.fingerprint}/suspend", sus)
    assert st == 200
    assert http_get(f"{running.url}/v1/agents/{target.fingerprint}")[0] == 404

    # Suspended agent can appeal (signed by the agent).
    appeal = {"fingerprint": target.fingerprint, "statement": "false positive"}
    appeal["signature"] = target.sign_payload(appeal)
    sta, respa = http_post(f"{running.url}/v1/agents/{target.fingerprint}/appeal", appeal)
    assert sta == 202 and respa["status"] == "open"

    # Moderator unsuspends -> listed again.
    uns = {"moderator_fingerprint": mod.fingerprint, "fingerprint": target.fingerprint}
    uns["signature"] = mod.sign_payload(uns)
    stu, _ = http_post(f"{running.url}/v1/agents/{target.fingerprint}/unsuspend", uns)
    assert stu == 200
    assert http_get(f"{running.url}/v1/agents/{target.fingerprint}")[0] == 200
