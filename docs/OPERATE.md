# Operating a HAAP Directory instance

Operator guide for the `haap-directory` service (SPEC §9). Covers running,
configuration, health, backup/restore and the trust boundaries an operator
must communicate to consumers.

## Run

```bash
haap-dird --db /var/lib/haap/dird.db --host 0.0.0.0 --port 8444 \
    --ttl-hours 24 --max-agents 10000
haap-dird --prune          # offline prune of expired entries, then exit
haap-dird --gen-key        # mint/show the directory key, then exit
```

The service binds a stdlib threading HTTP server. Put a TLS-terminating
reverse proxy / CDN in front for public deployments (the directory speaks
plain HTTP; the endpoint proofs and manifests are signed regardless).

Graceful shutdown: `SIGINT`/`SIGTERM` stop the server, flush and close the
database (the WAL is checkpointed on close).

## Configuration precedence

Highest wins: **CLI flags > `~/.haap/dird.json` > env `HAAP_DIRD_*` >
built-in defaults.**

`~/.haap/dird.json` is a flat JSON object using the same field names as
`DirectoryConfig` (`db_path`, `host`, `port`, `ttl_hours`, `max_agents`,
`challenge_ttl_s`, `max_manifest_bytes`, `rate_search_per_min`,
`rate_register_per_hour`, …). Environment variables are the upper-cased field
name prefixed with `HAAP_DIRD_` (e.g. `HAAP_DIRD_PORT=8444`). A custom config
path may be given with `--config` or `HAAP_DIRD_CONFIG`.

## The directory key

The instance owns one Ed25519 signing key, stored at `--key` (default:
alongside the DB as `<db>.dirkey.json`) with `0600` permissions. Its
fingerprint is the `directory_fingerprint` returned on responses and shown in
`/health` and `haap-dird --gen-key`. It signs challenge nonces and (from L5)
audit checkpoints. **Back it up separately and never commit it.**

## Health & observability

- `GET /health` → `{status, version, agents, suspended, pending_verifications,
  chain_seq, uptime_s, directory_fingerprint, api.completion_route}` — no
  sensitive data. Also serves as the legacy `/health` contract (superset of
  `{status, agents}`).
- Every response carries `X-Request-Id` (accepted from the client or
  generated). Rejections use the stable error envelope
  `{"error": {code, message, request_id}}`; `429`s carry `Retry-After`.
- The append-only audit chain (`/v1/audit/head`, `/v1/audit/log`) is the
  authoritative record of every state change; `chain_seq` in `/health` is the
  current head sequence.

## Persistence, backup & restore

State lives in a single SQLite database in WAL mode. Because the L5 audit
entry is written in the **same transaction** as the state change it records, a
consistent snapshot of the database is a consistent audit chain.

- **Backup:** `sqlite3 dird.db ".backup '/backup/dird-$(date +%F).db'"` (a
  consistent online snapshot), copied to a separate filesystem; keep several
  daily + one monthly.
- **Restore:** stop the service, replace `dird.db` (WAL checkpointed), restart.
  Startup prunes expired entries automatically.

## Trust boundaries (communicate these to consumers)

- The directory verifies signature math, the fingerprint↔key binding, and
  endpoint control at registration time. It does **not** vouch for an agent's
  honesty, quality or reachability-from-you.
- A hostile operator can lie about *listings* but **cannot sign as an agent**:
  consumers MUST re-verify an agent's own `/.well-known/haap.json` against the
  fingerprint before trusting a listing (SPEC §3.7 M3, §8 T-D07).
- The audit chain is *tamper-evident*, not tamper-proof: it detects a rewrite
  only for parties who fetched a checkpoint before the rewrite. Consumers who
  care should poll `/v1/audit/head` and, later, run a mirror.

## Abuse controls

- Per-IP token buckets limit anonymous endpoints (`register`, `search`);
  denied requests get `429` + `Retry-After`. Defaults: register 5/hour,
  search 60/min (configurable).
- Payload caps: manifest ≤ 256 KiB (`MANIFEST_TOO_LARGE`), body ≤ 512 KiB
  (`PAYLOAD_TOO_LARGE`). Listed-agent cap `--max-agents` (`DIRECTORY_FULL`).
- Pending-challenge table is capped; the oldest pending challenge is evicted
  (audited) when full.

## Roadmap for operators

L2 domain verification (F3), L3 vouching + L4 reports/moderation (F4) and
federation/mirroring (F6) are planned. Moderator keys and the moderation
runbook (`docs/MODERATION.md`) arrive with F4.
