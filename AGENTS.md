# AGENTS.md — guidance for coding agents

This file orients AI agents (and new humans) working in the
`haap-directory` repo. Read it before making changes.

## What this is

The HAAP Public Directory is the federated **phone book** of the HAAP
(Hermes Agent Alliance Protocol) ecosystem. Agents register a signed
capability manifest, prove control of their messaging endpoint, keep their
entry alive with signed heartbeats, and become discoverable by search. It is
the production, SQLite-backed evolution of the in-memory reference registry
in the `haap` client package, and stays **wire-compatible** with it.

## The one principle you may not violate

> **The directory is a phone book, not a notary — and never a judge.**

Identity lives in the agents' Ed25519 keys, not in the directory. The
directory returns *labelled signals with provenance*
(`domain_verified`, `vouches_in`, `reports`, `status`,
`block_recommendation`, `audit_verifiable`) and **never** a "safe/trusted"
verdict or a collapsed trust score. If a change would make the directory
*assert* trust rather than *report* facts, it is wrong. See `docs/SPEC.md §2.2`.

## Build, run, test

```bash
pip install -e '.[dev]'                      # only runtime dep: cryptography
python -m pytest -q                          # full suite
HAAP_REPO=/path/to/haap python -m pytest -q  # + compat test against real client
haap-dird --db ./dird.db --port 8444         # run
python haap_dird.py --db ./dird.db --port 8444   # run without installing
```

There is no linter/type-checker configured; correctness is enforced by the
test suite. The L2 `dns_txt` path shells out to the system `dig` binary, so
it must not be contacted by tests (see "Testing" below).

## Where things live

| Path | Purpose |
|---|---|
| `src/haap_directory/store.py` | **All SQL lives here.** Schema, transactions, audit-chain append. |
| `src/haap_directory/http_api.py` | stdlib `ThreadingHTTPServer` HTTP surface; `/v1` routes + legacy aliases. |
| `src/haap_directory/service.py` | Business logic / orchestration (validation → store). |
| `src/haap_directory/manifest.py` | Manifest validation (size caps, float/forbidden-field rejection). |
| `src/haap_directory/canonical.py` | Vendored canonical-JSON, byte-identical to `haap`. |
| `src/haap_directory/errors.py` | Stable error-code table (SPEC §4.10). |
| `src/haap_directory/config.py` | `DirectoryConfig` + precedence. |
| `src/haap_directory/audit.py`, `audit_service.py` | L5 hash chain + `/v1/audit/*`. |
| `src/haap_directory/{crypto,identity,keystore,signing,verify,resolver,vouching,reputation,moderation,mirror,rate_limit,telemetry,timeutil,domain}.py` | L0–L6 supporting modules. |
| `haap_dird.py` | Convenience launcher (adds `src/` to `sys.path`). |
| `docs/SPEC.md` | Normative architecture + API contract (self-contained). |
| `docs/OPERATE.md`, `docs/MODERATION.md` | Operator runbook; moderation runbook. |
| `tests/` | pytest suite; `conftest.py` holds shared fixtures. |

## Conventions that will bite you

- **Stdlib-first.** `http.server` + `sqlite3`; the only hard dependency is
  `cryptography` (Ed25519). Do not introduce FastAPI/Pydantic/uvicorn or new
  runtime deps. Validation Pydantic would give for free is done explicitly in
  `manifest.py` and the HTTP layer.
- **Canonical JSON is frozen.** `json.dumps(sort_keys=True, separators=(",", ":"),
  ensure_ascii=False).encode("utf-8")`. Any deviation breaks signature
  verification — do not "improve" it (`docs/SPEC.md §2.3`, `canonical.py`).
- **Error codes are API.** `errors.py:ERROR_STATUS` is add-only: never rename,
  never remove, never repurpose a code. Messages are short and MUST NOT leak
  internals. Codes are reserved ahead of their handlers.
- **Audit chain == mutations.** Every state change appends exactly one audit
  entry **in the same `BEGIN IMMEDIATE` transaction** as the mutation
  (`store.py:_append_audit`). New mutating methods must preserve this invariant.
- **Single connection, single write lock.** SQLite is single-writer; writers
  serialize behind one `threading.RLock`. Reads may read through the same
  connection. Don't add connection pools or async.
- **Time is injected.** All expiry/clock logic reads an injected `Clock`
  (`timeutil.system_clock` default); never call `time.time()` directly in
  store/service logic so tests can advance a `MutableClock`.
- **Wire compatibility.** Legacy routes (`POST /register`,
  `/register/complete`, `/heartbeat`, `GET /search`, `/agents/{fp}`) must keep
  working for the unmodified `haap/registry_client.py`. `/v1/*` is canonical.

## Testing

- Fixtures live in `tests/conftest.py`: real HTTP on an ephemeral
  `127.0.0.1` port, `MutableClock` (no real sleeps), `Agent` kit (signs
  manifests/nonces/payloads the way the wire expects), `StubResolver` for L2.
- L2 DNS/HTTPS is exercised only through an injectable resolver; never hit real
  DNS or network in tests.
- Test naming maps to feature phases (F0–F6, see `README.md` status table):
  `test_registration`, `test_search_heartbeat`, `test_domain_verification`,
  `test_vouching`, `test_reputation`, `test_audit_chain`, `test_checkpoints`,
  `test_ops_federation`, `test_compat_client`, etc.
- The compat test (`test_compat_client.py`) is skipped unless `HAAP_REPO`
  points at a checkout of the companion `haap` package.
- Each rejection case asserts its **stable code** and HTTP status.

## Config precedence

CLI flags > `~/.haap/dird.json` > env `HAAP_DIRD_*` > defaults. Non-secret
operational settings only; the directory signing key is handled in
`keystore.py` and must never be committed.

## When in doubt

Read `docs/SPEC.md` first — it is self-contained and normative (RFC 2119
MUST/SHOULD/MAY). For running/ops questions see `docs/OPERATE.md`; for the
moderation runbook and policy log see `docs/MODERATION.md` (append-only).

<!-- OPENWIKI:START -->

## OpenWiki

This repository has a generated `openwiki/` evidence index. It is optional just-in-time context, not required startup reading.

- Treat source code and tests as authoritative. A brief's unknowns and review items are verification gaps, not automatic requirements.
- Prefer the narrowest quiet validation that proves the changed behavior. Preserve complete failure output.

The scheduled OpenWiki GitHub Actions workflow refreshes the repository wiki. Do not hand-edit generated OpenWiki pages unless explicitly asked; prefer updating source code/docs and letting OpenWiki regenerate.

<!-- OPENWIKI:END -->
