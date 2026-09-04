# HAAP Public Directory (`haap-directory`)

The federated **phone book** of the HAAP (Hermes Agent Alliance Protocol)
ecosystem. HAAP agents register a signed capability manifest, prove they
control their messaging endpoint, keep their entry alive with signed
heartbeats, and become discoverable by capability, geography, language and
free text.

> **Phone book, not a notary — and never a judge.** Identity lives in the
> agents' Ed25519 keys, not in the directory. The directory indexes signed
> manifests and verifies endpoint control; its compromise must never allow
> impersonation. It returns *labelled signals with provenance*, never a
> "safe / trusted" verdict. See [`docs/SPEC.md`](docs/SPEC.md) for the full
> architecture and trust model.

This is the production evolution of the in-memory reference registry that
ships inside the `haap` client package. It is **wire-compatible** with the
unmodified `haap` client (`haap/registry_client.py`) and adds SQLite
persistence, a canonical `/v1` API, an append-only audit chain, rate limiting
and a hardened validation surface.

## Status

The build follows the phased plan in `docs/SPEC.md §7`. Implemented so far:

| Phase | Scope | State |
|---|---|---|
| **F0** | Repo skeleton, persistent SQLite store, `haap-dird` CLI, `/health`, config precedence | ✅ |
| **F1** | L1 proof-of-endpoint registration on SQLite, persistence, upsert/expiry, stable error codes | ✅ |
| **F2** | Search (capability / free-text AND / geo / pagination / trust filters), heartbeat (v1 signed + legacy), expiry prune | ✅ |
| **L5 base** | Append-only, hash-chained audit log written in the same transaction as every state change; `/v1/audit/*` read + verify | ✅ (foundation) |
| **F3** | L2 domain verification (DNS TXT / HTTPS well-known) | ⏳ planned |
| **F4** | L3 vouching + L4 reports / auto-suspend | ⏳ planned |
| **F6** | Federation seams, Docker, OpenAPI polish | ⏳ planned |

The trust block returned with every listing already carries the L2–L4 fields
with honest "no signal yet" defaults, so the wire shape is stable as later
phases fill them in.

## Install & run

Requires Python 3.10+. The only runtime dependency is `cryptography`.

```bash
pip install -e .            # or: pip install -e '.[dev]' for tests
haap-dird --db ./dird.db --host 127.0.0.1 --port 8444 --ttl-hours 24
# or, from a source checkout without installing:
python haap_dird.py --db ./dird.db --port 8444
```

Other CLI actions: `--gen-key` (mint/show the directory signing key),
`--prune` (offline prune of expired entries), `--version`. Configuration
precedence is **CLI flags > `~/.haap/dird.json` > env `HAAP_DIRD_*` >
defaults** (see [`docs/OPERATE.md`](docs/OPERATE.md)).

## API at a glance

Canonical endpoints under `/v1`; legacy aliases keep the `haap` client working.

| Method & path | Purpose |
|---|---|
| `POST /v1/register` | Step 1: verify signed manifest, issue endpoint challenge (202) |
| `POST /v1/register/complete` | Step 2: verify endpoint proof, list the agent (201) |
| `POST /v1/heartbeat` | Signed heartbeat renews the entry's TTL |
| `GET  /v1/search` | Search by `capability`, `q`, `geo`, `limit`/`offset` + trust filters |
| `GET  /v1/agents/{fp}` | Full manifest + trust block |
| `GET  /v1/audit/head`, `GET /v1/audit/log` | Read and verify the transparency chain |
| `GET  /health` | Status, listed count, chain seq, directory fingerprint |
| `POST /register`, `POST /register/complete`, `POST /heartbeat`, `GET /search`, `GET /agents/{fp}` | Legacy aliases (identical semantics) |

Errors use a stable envelope `{"error": {"code", "message", "request_id"}}`
with the code table in `docs/SPEC.md §4.10`.

## Design notes / deviations from the SPEC

- **Stdlib HTTP, not FastAPI.** The SPEC §6.1 *recommends* FastAPI but
  explicitly allows stdlib; the underlying implementation brief mandates
  "stdlib first". Building on `http.server` + `sqlite3` keeps the runtime
  dependency footprint to just `cryptography`, makes legacy wire-compatibility
  trivial (same stack as the reference), and removes a network-install step
  from deployment. Validation that FastAPI/Pydantic would give for free is
  implemented explicitly in `manifest.py` and the HTTP layer (size caps,
  float/forbidden-field rejection, stable error codes).
- **Canonical JSON is vendored** (`canonical.py`) rather than imported from
  `haap`, so the directory has no hard import dependency on the client package
  (SPEC §6.3). It is byte-for-byte identical and covered by the compatibility
  test.
- **One connection + a single write lock** with `BEGIN IMMEDIATE` transactions.
  SQLite is single-writer; this keeps the L5 audit entry in the *same*
  transaction as the state change it records, and is correct and simple at v1
  scale.

## Testing

```bash
python -m pytest -q
# with the companion client available for the compatibility test:
HAAP_REPO=/path/to/haap python -m pytest -q
```

The suite covers the happy path, every rejection case with its stable code,
update-vs-fresh, injected-clock expiry, search semantics, the audit chain
(link + tamper detection), and — when the companion `haap` checkout is present
— the **unmodified** `haap` client registering, searching and heartbeating
against this service.

## License

MIT — see [`LICENSE`](LICENSE).
