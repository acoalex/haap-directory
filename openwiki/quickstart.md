---
type: guide
title: HAAP Directory Wiki — Starting Points & Routing Map
description: Init page for the HAAP Public Directory wiki — what haap-directory is, the one "phone book, not a notary — never a judge" principle, the source-of-truth order (code and tests above docs/SPEC.md above runbooks), the repo-wide invariants every page assumes, and the page hierarchy plus task-routing map across architecture, concepts, workflows, operations, integrations and testing.
tags: [guide, quickstart, routing-map, source-of-truth, invariants, phone-book-not-notary, trust-ladder, build-phases]
verified:
  - by: openwiki/0.5.0
    at: 2026-09-05T09:05:06.235Z
sources:
  - id: openwiki-source-8037e2358a2c4f9b2c722a11
    resource: repo://AGENTS.md
  - id: openwiki-source-4c7514ba555127e0fb04fe74
    resource: repo://docs/SPEC.md
  - id: openwiki-source-05ccef8d4cf1698187f20464
    resource: repo://pyproject.toml
  - id: openwiki-source-23775c3de52f3ab95a13cb8b
    resource: repo://README.md
  - id: openwiki-source-7662b79e453b4d3aefea8006
    resource: repo://src/haap_directory/__init__.py
  - id: openwiki-source-38a8d82920c26bbf3c6eb71b
    resource: repo://src/haap_directory/canonical.py
  - id: openwiki-source-35f0e9d8b3fcf8e1b780869e
    resource: repo://src/haap_directory/config.py
  - id: openwiki-source-4634abff3f002bcefeb4761d
    resource: repo://src/haap_directory/errors.py
  - id: openwiki-source-af259ed660aeb176e531abd1
    resource: repo://src/haap_directory/http_api.py
  - id: openwiki-source-85d0ca3a7d4bbbd91b92fc43
    resource: repo://src/haap_directory/keystore.py
  - id: openwiki-source-66832378937abcc3e6fe5f44
    resource: repo://src/haap_directory/service.py
  - id: openwiki-source-6e14101dd9159cdec2766a50
    resource: repo://src/haap_directory/store.py
  - id: openwiki-source-67b8fa66fab9f178b1793f43
    resource: repo://src/haap_directory/timeutil.py
  - id: openwiki-source-f0a6e7dc03522b2682f88655
    resource: repo://tests/conftest.py
  - id: openwiki-source-43c4fde5b0d4cc9555e00900
    resource: repo://tests/test_compat_client.py
generated: { by: "openwiki/0.5.0", at: "2026-09-05T09:05:06.235Z" }
---

# HAAP Directory Wiki — Starting Points & Routing Map

This wiki documents the **`haap-directory`** repository: the HAAP Public Directory, the federated **phone book** of the HAAP (Hermes Agent Alliance Protocol) ecosystem. Agents register an Ed25519-signed capability manifest, prove control of their messaging endpoint, keep their entry alive with signed heartbeats, and become discoverable by capability, geography, language and free text. It is the production, SQLite-backed evolution of the in-memory reference registry that ships inside the `haap` client package, and it stays **wire-compatible** with the unmodified `haap` client (`haap/registry_client.py`) while exposing a canonical `/v1` API plus thin legacy aliases. Every phase of the `docs/SPEC.md` §7 build plan (F0–F6) is implemented, tested, and green, so the full L0–L5 trust ladder is live.

Use this page to get oriented and to route yourself to the right page. For the deep component map, read [System Overview](/openwiki/architecture/overview.md) first; this page only orients and routes.

## The one non-negotiable design principle

> **The directory is a phone book, not a notary — and never a judge.**

Identity lives in the agents' Ed25519 keys, **not** in the directory. The directory verifies signature math and endpoint control — so a fully compromised directory can lie about *listings* but can never *sign as an agent* — and it returns **labelled signals with provenance** (`domain_verified`, `vouches_in`, `reports`, `status`, `block_recommendation`, `audit_verifiable`), **never** a "safe/trusted" verdict and never a collapsed trust score. The consumer always decides. If a change would make the directory *assert* trust rather than *report* facts, it is wrong. This stance is fixed in `AGENTS.md`, `docs/SPEC.md` §2.2 and the package docstring, and is enforced in code: the trust block assembled per listing (`DirectoryService.build_trust_block`) has no aggregate field, no rating, no verdict to return. Full semantics live on [Trust Model — The L0–L5 Ladder and "Phone Book, Not Notary"](/openwiki/concepts/trust-model.md).

## Authoritative sources, in order

When anything disagrees, the higher source wins — and divergences must be flagged, not hidden:

1. **Source code and tests** are the authoritative ground truth for how the system actually behaves.
2. **`docs/SPEC.md`** is the normative architecture and API contract (RFC 2119 MUST/SHOULD/MAY), self-contained, with the trust model (§3), HTTP contract (§4), data model (§5) and phased build plan (§7).
3. **`docs/OPERATE.md`** (operator runbook) and **`docs/MODERATION.md`** (append-only moderation runbook/policy log) are operational guidance that can lag code.

`AGENTS.md` is the agent-facing orientation for the repo itself; this wiki is its page-level companion. If a runbook or wiki page contradicts current code, trust the code and surface the discrepancy rather than papering over it.

## Repo-wide invariants every other page assumes

These constraints are cross-cutting. Every page in this wiki — architecture, concepts, workflows, operations, integrations and testing — builds on them, and every safe change preserves them:

- **Canonical JSON is frozen.** Anything signed is serialized as `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. The form is vendored byte-for-byte in `canonical.py` (no hard import dependency on the `haap` package); any deviation breaks signature verification. Spec: §2.3/§2.7.
- **Error codes are API.** `errors.py:ERROR_STATUS` is the SPEC §4.10 master table and is add-only: never rename, never remove, never repurpose. Every rejection uses the fixed envelope `{"error": {"code", "message", "request_id"}}`; messages are short and must not leak internals; `429`s carry `Retry-After`.
- **Audit chain equals mutations.** Every state change appends **exactly one** hash-chain entry **in the same `BEGIN IMMEDIATE` transaction** as the mutation (`Store._append_audit` runs inside the caller's write cursor). New mutating methods must preserve this invariant.
- **Single connection, single write lock.** One SQLite connection per process (WAL mode, manual transactions); all writes serialize behind one `threading.RLock` with `BEGIN IMMEDIATE ... COMMIT` and automatic rollback. Reads share the same connection. No connection pools, no async.
- **Time is injected.** All expiry, decay, freshness and checkpoint logic reads an injected `Clock` callable (`timeutil.system_clock` by default); store/service logic never calls `time.time()` directly, so tests can drive TTLs deterministically with a `MutableClock`.
- **Stdlib-first.** The HTTP surface is `http.server`, persistence is `sqlite3`, and `cryptography` (Ed25519) is the only runtime dependency. No FastAPI/Pydantic/uvicorn or new runtime deps; the validation those would give for free is implemented explicitly in `manifest.py` and the HTTP layer.
- **Legacy haap-client wire compatibility.** Legacy routes (`POST /register`, `/register/complete`, `/heartbeat`, `GET /search`, `GET /agents/{fp}`) must keep working for the unmodified `haap/registry_client.py`; `/v1/*` is canonical. The compat test runs only when `HAAP_REPO` (or a sibling `../haap` checkout) is present.

## Trust ladder and build status at a glance

The L0–L5 ladder is a set of *signals of increasing cost-to-fake*, each with its own protocol and workflow page. The directory reports them with provenance; it never judges.

| Layer | What the directory verifies / exposes | Code home | Wiki page |
|---|---|---|---|
| **L0** identity | Ed25519 key ↔ `HF-` fingerprint binding, signatures | `crypto.py`, `identity.py` | [Trust Model](/openwiki/concepts/trust-model.md) |
| **L1** proof-of-endpoint | single-use challenge signed by the bound key; heartbeats keep the entry fresh | `service.py`, `store.py` | [Registration & Heartbeat Lifecycle](/openwiki/workflows/registration-lifecycle.md) |
| **L2** domain control | server-run DNS TXT or HTTPS well-known checks; 90-day expiry | `domain.py`, `verify.py`, `resolver.py` | [Domain Verification](/openwiki/workflows/domain-verification.md) |
| **L3** vouching | signed, expiring, revocable peer statements; raw graph paths (depth ≤ 2) | `vouching.py` | [Vouching](/openwiki/workflows/vouching.md) |
| **L4** reputation & moderation | signed reports with decay, narrow auto-suspend; moderator-keyed human actions | `reputation.py`, `moderation.py` | [Reputation](/openwiki/workflows/reputation.md), [Moderation & Appeals](/openwiki/workflows/moderation-appeals.md) |
| **L5** audit transparency | append-only hash chain, signed checkpoints, signed responses | `audit.py`, `audit_service.py`, `store.py` | [Audit Transparency](/openwiki/workflows/audit-transparency.md), [Store & Audit Chain](/openwiki/architecture/store-and-audit.md) |

**Build status:** SPEC §7 phases F0 (skeleton/store/CLI) through F6 (federation seam, Docker, `/metrics`, rate-limit hardening) are all implemented, tested and green; see the README status table and [System Overview](/openwiki/architecture/overview.md).

## Routing map: the page hierarchy

Read top-down: **architecture → concepts → workflows → operations → integrations → testing**. Each page below is a one-line pointer; follow the link for the depth.

### Architecture — how it is built

- [System Overview](/openwiki/architecture/overview.md) — topology and ownership map: process entry points, HTTP → `DirectoryService` sub-services → `Store` layering, L0–L5 code mapping, F0–F6 status. **Start here before any other page.**
- [Service Layer](/openwiki/architecture/business-logic.md) — `DirectoryService` orchestration: L1 registration/heartbeat/search semantics, how the L2–L5 sub-services attach, `SearchQuery` parsing and filter semantics, and trust-block assembly.
- [HTTP Layer](/openwiki/architecture/http-layer.md) — the full HTTP surface: canonical `/v1` routes plus legacy aliases, request parsing and body caps, stable error envelope and `X-Request-Id`, per-IP rate limiting and trusted-proxy headers, signed audit responses, `/health` + `/metrics`, and the safe way to add an endpoint.
- [Store & Audit Chain](/openwiki/architecture/store-and-audit.md) — persistence internals: schema tables, the one-connection + `RLock` + `BEGIN IMMEDIATE` write model, the audit-equals-mutation invariant, pure chain math in `audit.py`, expiry/pruning, and the injected-clock requirement.

### Concepts — what the contracts mean

- [Trust Model](/openwiki/concepts/trust-model.md) — the semantic backbone: what each L0–L5 layer does and does not prove, Sybil economics, the consumer-decides stance, and how signals materialize in the trust block.
- [Signed Wire Format](/openwiki/concepts/signed-wire-format.md) — the substrate every signature depends on: frozen canonical JSON, Ed25519 raw-key/base64 conventions, fingerprint computation, the verify-over-subset request-signing pattern, manifest validation rules, and the stable error-code table.

### Workflows — end-to-end behaviours, one page per layer

- [Registration & Heartbeat Lifecycle (L1)](/openwiki/workflows/registration-lifecycle.md) — manifest submission → endpoint challenge → proof → signed (v1) and legacy heartbeats → TTL expiry and pruning; v1-vs-legacy body shapes.
- [Domain Verification (L2)](/openwiki/workflows/domain-verification.md) — request/confirm/status endpoints, single-use tokens, the injectable `Resolver` seam, the two server-executed checks (`dns_txt` via system `dig`; `https_well_known`), and stable failure codes.
- [Vouching (L3)](/openwiki/workflows/vouching.md) — create/revoke/read vouches, mechanics-only enforcement, graph reads and BFS trust paths, served as raw edges.
- [Reputation (L4)](/openwiki/workflows/reputation.md) — signed reports, eligibility, evidence hashing, rolling-window decay, deterministic auto-suspend, and `block_recommendation`.
- [Moderation & Appeals (L4)](/openwiki/workflows/moderation-appeals.md) — moderator-keyed takedown/suspend/unsuspend, agent-signed appeals, and the append-only moderation policy log.
- [Audit Transparency (L5)](/openwiki/workflows/audit-transparency.md) — the external face of the chain: `/v1/audit/*` endpoints, signed responses, checkpoint signing, tamper-evidence and consumer polling.

### Operations — run and operate an instance

- [Operations Runbook](/openwiki/operations/runbook.md) — `haap-dird` CLI and source launcher, config precedence with the full field set, directory-key lifecycle, `/health` and `/metrics` interpretation, WAL-snapshot backup/restore, abuse controls and caps, moderator-key config, the `dig` dependency, reverse-proxy/TLS guidance, Docker deployment, and the trust boundaries to communicate to consumers.

### Integrations — the outside world

- [Federation & Mirrors](/openwiki/integrations/federation-mirror.md) — how an independent mirror ingests `/v1/audit/log`, verifies chain linkage locally, and reproduces an identical head; what two agreeing mirrors prove.
- [Legacy haap Client Compatibility](/openwiki/integrations/legacy-client.md) — the wire contract with the unmodified `haap` package: which legacy routes and body shapes must keep working and how v1 differs.

### Testing — how correctness is enforced

- [Test Suite](/openwiki/testing/test-suite.md) — pytest configuration, shared fixtures (real HTTP on an ephemeral port, `MutableClock`, `StubResolver`, the `Agent` signing kit), the F0–F6 phase-mapped test files, the `HAAP_REPO`-gated compat test, and the test rules (injected clock, no real DNS/network, every rejection asserts its stable code).

## Task routing

| Task | Start at | Also check |
|---|---|---|
| Get oriented before any change | [System Overview](/openwiki/architecture/overview.md) | this page + [Trust Model](/openwiki/concepts/trust-model.md) |
| Add/change an HTTP endpoint, error, cap or rate limit | [HTTP Layer](/openwiki/architecture/http-layer.md) | [Signed Wire Format](/openwiki/concepts/signed-wire-format.md), [Test Suite](/openwiki/testing/test-suite.md) |
| Change registration/heartbeat/search semantics | [Registration & Heartbeat Lifecycle](/openwiki/workflows/registration-lifecycle.md) | [Service Layer](/openwiki/architecture/business-logic.md) |
| Touch SQL, schema or audit append | [Store & Audit Chain](/openwiki/architecture/store-and-audit.md) | the workflow page of the affected layer (audit-equals-mutation invariant) |
| Work on domain verification (L2) | [Domain Verification](/openwiki/workflows/domain-verification.md) | [Test Suite](/openwiki/testing/test-suite.md) (`StubResolver`) |
| Vouching (L3), reputation or moderation (L4) | [Vouching](/openwiki/workflows/vouching.md) · [Reputation](/openwiki/workflows/reputation.md) · [Moderation & Appeals](/openwiki/workflows/moderation-appeals.md) | `docs/MODERATION.md` policy log |
| Audit endpoints, checkpoints, response signing (L5) | [Audit Transparency](/openwiki/workflows/audit-transparency.md) | [Store & Audit Chain](/openwiki/architecture/store-and-audit.md) |
| Break or extend the `haap` client contract | [Legacy haap Client Compatibility](/openwiki/integrations/legacy-client.md) | compat test in [Test Suite](/openwiki/testing/test-suite.md) |
| Run, deploy, back up, tune limits, rotate keys | [Operations Runbook](/openwiki/operations/runbook.md) | `docs/OPERATE.md` |
| Consume or mirror the chain externally | [Federation & Mirrors](/openwiki/integrations/federation-mirror.md) | [Audit Transparency](/openwiki/workflows/audit-transparency.md) |
| Write or extend tests | [Test Suite](/openwiki/testing/test-suite.md) | `tests/conftest.py` fixtures |

## Working in this wiki

- Keep the hierarchy: **architecture → concepts → workflows → operations → integrations → testing**. Link across pages instead of duplicating their content.
- Treat the invariants above as read-only assumptions of every other page; an edit that breaks one is an edit to the code, documented on the owning architecture/workflow page.
- When a runbook, this wiki, or a doc diverges from what the code actually does, the code wins — correct the page and flag the divergence rather than preserving a stale claim.
