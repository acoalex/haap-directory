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

**Live instance:** **https://acoalex.com/haap-directory** — deployed on the
reference VPS (systemd service behind Apache reverse proxy + Cloudflare) and
verified end-to-end with the unmodified `haap` client: registration,
heartbeat, search and audit reads all pass against the public URL.

The build follows the phased plan in `docs/SPEC.md §7`. Implemented so far:

| Phase | Scope | State |
|---|---|---|
| **F0** | Repo skeleton, persistent SQLite store, `haap-dird` CLI, `/health`, config precedence | ✅ |
| **F1** | L1 proof-of-endpoint registration on SQLite, persistence, upsert/expiry, stable error codes | ✅ |
| **F2** | Search (capability / free-text AND / geo / pagination / trust filters), heartbeat (v1 signed + legacy), expiry prune | ✅ |
| **L5 base** | Append-only, hash-chained audit log written in the same transaction as every state change; `/v1/audit/*` read + verify | ✅ (foundation) |
| **F3** | L2 domain verification (DNS TXT / HTTPS well-known) | ✅ |
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

### Using the live instance (as an agent owner)

Your `haap` client can use the reference directory today — no need to run
your own:

```bash
export HAAP_REGISTRY=https://acoalex.com/haap-directory

# register your agent (3-message proof-of-endpoint flow, all automatic):
haap registry register --registry "$HAAP_REGISTRY" \
    --endpoint https://your-agent.example.com:8443/haap/messages

# discover other agents:
haap registry search --registry "$HAAP_REGISTRY" --capability citas-peluqueria
```

Keep the entry alive with heartbeats (renewing the 7-day TTL) from Python:

```python
from haap.registry_client import HeartbeatLoop

# daemon thread renewing the entry every 6 h (default, << TTL):
HeartbeatLoop("https://acoalex.com/haap-directory",
              identity.fingerprint).start()
```

Operators wanting their own instance: see `docs/OPERATE.md` for the
systemd + Apache reverse-proxy layout (`ProxyPass /haap-directory ->
127.0.0.1:8444`), the dedicated `haapdird` service user, SQLite location and
backup notes. **Cloudflare note:** if the domain sits behind Cloudflare,
disable the Browser Integrity Check for the directory path — Python-stdlib
clients (like the `haap` client) are otherwise rejected with error 1010.
This also affects the L2 `https_well_known` verifier: a directory running on a
Cloudflare-fronted host cannot verify a *different* Cloudflare-fronted domain,
because the server-side `urllib` fetch is itself blocked by BIC (error 1010).
Use the **`dns_txt`** method for domains behind Cloudflare (the `dig` check
does not traverse Cloudflare), reserving HTTPS well-known for plain-Apache /
non-CDN hosts. The live instance and the `Peluqueria Euraka` demo agent prove
`acoalex.com` via `dns_txt`.


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
| `POST /v1/verify-domain` | L2: signed request issues a domain challenge (DNS TXT or HTTPS well-known), 30-min single-use token (202) |
| `POST /v1/verify-domain/confirm` | L2: directory re-checks the record server-side, validates endpoint↔domain consistency, marks agent domain-verified (90-day validity) |
| `GET  /v1/verify-domain/status?fingerprint=…` | L2: current verification state (primary) |
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
