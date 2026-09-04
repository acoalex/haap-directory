# Moderation runbook

Moderation is the only human judgement in the directory's hot path, and every
moderator action is L5-audited with the moderator key fingerprint and a reason
(SPEC §3.5.5, §9.4). Moderators act on **defined abuse classes**, never on
opinion, and never issue a "trustworthiness" verdict — the directory is a phone
book, not a judge.

This document is append-only: record policy decisions here with a date so the
audit trail of *policy* is as durable as the audit trail of *actions*.

## Moderator keys

Moderators are operator-held Ed25519 keys. Configure their **public** keys
(standard base64) in `~/.haap/dird.json`:

```json
{ "moderator_keys": ["<b64 ed25519 public key>", "..."] }
```

Each configured key's fingerprint (`HF-…`) is the moderator identity that must
sign moderation requests. An unknown fingerprint → `MODERATOR_UNKNOWN` (403); a
bad signature → `TAKEDOWN_UNAUTHORIZED` (403). Keep moderator private keys off
the directory host; sign requests on a separate operator workstation.

## What is automated vs. human

- **Automated (no human):** auto-suspension when **≥ 3 unique eligible
  reporters** (registered, live, listed ≥ 72 h) report the same target in an
  **abuse class** (`spam`, `phishing`, `impersonation_attempt`,
  `endpoint_hijack`) within a rolling **7-day** window. This is a published,
  audited spam-filter-grade rule — not a verdict. Reports decay after 180 days.
- **Human (moderator key):** takedown on any category/evidence, direct
  suspend/unsuspend, and appeal decisions.

## Actions (all moderator-signed unless noted)

| Action | Route | Signed payload |
|---|---|---|
| Takedown a reported agent | `POST /v1/reports/{report_id}/takedown` | `{moderator_fingerprint, report_id, reason}` |
| Direct suspend | `POST /v1/agents/{fp}/suspend` | `{moderator_fingerprint, fingerprint, reason}` |
| Unsuspend / restore | `POST /v1/agents/{fp}/unsuspend` | `{moderator_fingerprint, fingerprint}` |
| Appeal (by the **agent**) | `POST /v1/agents/{fp}/appeal` | `{fingerprint, statement}` signed by the agent key |

Signatures are Ed25519 over the canonical JSON of the payload above
(`sort_keys`, compact separators, `ensure_ascii=false`).

## Handling appeals

1. A suspended agent submits a signed appeal; heartbeats are still accepted so
   the agent keeps its key alive during review.
2. Review the target's audit trail (`GET /v1/agents/{fp}/audit`) and the
   evidence reports referenced in the suspension record.
3. Decide: `unsuspend` (restores the entry with a fresh TTL, audited
   `moderator.unsuspend`) or leave suspended. Record the rationale here.

## Evidence handling

Report **evidence bodies never enter the public chain** — only a
`detail_hash`/`evidence_hash`. Store raw evidence (envelopes, transcripts) in a
separate encrypted store accessible to moderators and the reporter/owner. The
public record proves *that* a report existed and *what rule* acted on it,
without leaking the evidence contents.

## Policy log

- 2026-09-04 — v1 thresholds adopted from SPEC §3.5.2 (72 h tenure, 3 unique
  eligible reporters, 7-day window, abuse classes only, 180-day decay).
