# HAAP Public Directory Service — Architecture & Trust Specification v1.0

| Field | Value |
|---|---|
| Document id | `haap-directory-spec` |
| Version | 1.0 |
| Date | 2026-09-04 |
| Status | **Baseline — implementation target** |
| Audience | AI coding agents and developers implementing the `haap-directory` service; consumers of the HAAP public directory API; operators of directory instances |
| Normativity | MUST / SHOULD / MAY follow RFC 2119 semantics. This document is self-contained: an implementer must be able to build the service from this file alone plus the wire-compatible building blocks listed in §2.3. |
| Source of authority | `/home/ubuntu/haap/docs/DIRECTORY_SERVICE_BRIEF.md` v1.0 (agent-implementation brief for the *in-repo* service) and the verified behaviour of the existing `haap/` package. Where this document and the brief disagree, **this document wins for the standalone `haap-directory` repository**; where this document is silent, the brief wins. |

---

## 1. How to read this document

1. **§2** gives context, objectives and non-objectives. Read it first; it fixes the "phone book, not a notary" stance that every later section obeys.
2. **§3 is the heart of the specification.** It defines a *layered trust architecture* (L0–L5). Each layer is a *verifiable signal* with an exact protocol, an explicit statement of what it **does** and — just as important — what it **does not** guarantee, who decides (directory vs. consumer), its Sybil economics, and how an attacker bypasses it. §3.7 condenses this into the **trust decision matrix** that search responses expose.
3. **§4** is the full HTTP API contract (v1 + legacy aliases), with request/response examples and the stable error-code table.
4. **§5** is the data model: extended manifest shape and the SQLite schema.
5. **§6** is the technology stack and repository layout for the standalone repo, including the compatibility contract with the existing `haap/` client package.
6. **§7** is the phased build plan with machine-checkable acceptance criteria per phase.
7. **§8–§11** cover the directory-specific threat model, operations, open questions and references.

An implementer should build phases F0→F6 in order (§7). Every acceptance criterion is a command that must pass; nothing in this spec is "documentation-only" for the target phases.

---

## 2. Context, objectives, non-objectives

### 2.1 What HAAP is

HAAP (Hermes Agent Alliance Protocol) is an open protocol that lets autonomous agents on different machines:

- discover each other by capability, geography, language and free text;
- verify each other's identity cryptographically (Ed25519 public keys, fingerprint-addressed);
- exchange signed envelopes (`envelope.py`: canonical-JSON payload + `msg_type` + `recipient_fp` + timestamp + nonce);
- negotiate permissions and collaborate (delegate tasks, book appointments, chat).

### 2.2 Where the directory fits — and the one principle you may not violate

The **HAAP Public Directory** is the ecosystem's *phone book*: a public, federable service where agents register a signed capability manifest, prove they control their messaging endpoint, keep their entry alive with signed heartbeats, and are discoverable by search.

**The directory is a phone book, not a notary — and never a judge.**

- Identity lives in the agents' Ed25519 keys, **not** in the directory. The directory indexes signed manifests and verifies endpoint control; its compromise must not allow impersonation (an attacker who fully owns a directory can lie about listings, but cannot sign as an agent).
- No mechanism in this document, cryptographic or otherwise, **proves** that an agent is *trustworthy*. Trustworthiness is a property of behaviour over time, judged by the party that bears the risk — the **consumer**. What the directory offers is a *ladder of increasingly expensive-to-fake signals* (L0–L5, §3) plus a transparent record of behaviour. The consumer combines those signals with its own policy and decides.
- Consequently the directory **never returns "verified safe"** and never collapses signals into a single trust score. It returns labelled, machine-readable facts (`domain_verified: true, method: dns_txt, at: …`), raw counters, and graph edges. Deciding is the consumer's job; the directory's job is to make lying expensive and lying *detectable*.

### 2.3 Verified building blocks (exist today — reuse, do not redesign)

These components are done, tested, and versioned in `/home/ubuntu/haap`. The standalone directory MUST interoperate with them as-is. Behaviour stated here was verified against the code and tests and is treated as ground truth:

| Module | Verified behaviour |
|---|---|
| `haap/crypto.py` | `KeyPair` (Ed25519, raw 32-byte keys), `sign()`, `verify_with(raw_pub, data, sig)`, `b64e`, `b64d`. |
| `haap/identity.py` | `fingerprint_of_public_key(raw_pub_bytes) -> "HF-" + first 16 hex chars of sha256(raw_pub)`. Fingerprint pattern: `^HF-[0-9a-f]{16}$`. |
| `haap/envelope.py` | `sign_body(identity, message_type, recipient_fp, payload)`, `verify_envelope(...)`, `NonceManager`, `MAX_CLOCK_SKEW = 300`. Canonical JSON: `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. **Any deviation breaks verification — do not "improve" it.** |
| `haap/capabilities.py` | Builds/parses `haap-public-manifest-v1`. Rejects manifests containing `private_key`, `signature`, `nonce` at any depth; rejects floats in signed data. |
| `haap/registry.py` | Minimal **in-memory** reference directory: `POST /register` → `POST /register/complete`, single-use proof-of-endpoint challenge, strict `public_key_b64` binding between the two calls, `POST /heartbeat {fingerprint}`, entry listed iff `now <= expires_at`, TTL 24 h. |
| `haap/registry_client.py` | Client side: `register()`, `search()`, `heartbeat()`, `HeartbeatLoop` — hits the **legacy** routes and MUST keep working against this service unmodified. |
| `tests/test_registry.py`, `tests/test_registry_client.py` | Existing behaviour contract (41 passing tests in the haap repo). Must keep passing. |

### 2.4 Objectives

The standalone `haap-directory` service MUST:

1. **O1 — Register with proof-of-endpoint.** Agents register a signed extended manifest after proving control of their messaging endpoint through a single-use, short-TTL challenge bound to the exact public key validated at submit time (L1, §3.2).
2. **O2 — Be searchable.** Anyone can search by capability, speciality, geo, language, free text, with pagination; results carry everything needed to connect plus the full **trust signal block** (§3.7, §5.1).
3. **O3 — Stay fresh.** Signed heartbeats renew entries; automatic expiry (default TTL 24 h) removes dead ones; pruning happens on startup and lazily on read.
4. **O4 — Offer rich agent metadata.** Extended manifest (§5.1): `services[]`, `geo`, `availability`, `roles_accepted`, `permission_scopes_offered`, `capabilities_flags`, `skills`, `tools`, language, contact/booking hints.
5. **O5 — Implement the layered trust architecture.** L0 identity, L1 proof-of-endpoint, L2 domain/business verification, L3 vouching, L4 behavioural reputation, L5 transparent append-only audit log (§3).
6. **O6 — Be honest about what signals mean.** Search results expose signals and raw counters only; the directory never emits a "safe/trusted" verdict (§3.7).
7. **O7 — Persist and harden.** SQLite (WAL), restart-safe, concurrency-safe, rate-limited, payload-capped, audited, observability via `/health` and `/metrics` (§9).
8. **O8 — Stay wire-compatible.** Legacy routes (`POST /register`, `POST /register/complete`, `POST /heartbeat`, client search route) keep working so the unmodified `registry_client.py` and existing tests pass (§4.9, §6.5).
9. **O9 — Be independently deployable and evolvable.** FastAPI/uvicorn on SQLite at low scale, a storage seam to Postgres at scale, container and VPS deployment, federation-ready (§6, §7 F6).

### 2.5 Non-objectives (explicit — do not build these)

- **N1 — Not an identity authority.** The directory never issues, revokes, or arbitrates agent identities. It binds *listings* to public keys; it cannot stop a stolen key from being used (only the owner's off-band re-keying + reports can).
- **N2 — Not a trust oracle.** No aggregate trust score, no "verified-safe" badge, no consumer liability.
- **N3 — Not a notary for agent-to-agent messages.** No message relay, no envelope validation service, no mediation of disputes.
- **N4 — No payments.** No payment processing, escrow, or fee collection in v1 (see Open Questions §11 on staking/fees).
- **N5 — No KYC / human identity verification.** L2 domain verification is *not* KYC and must never be presented as such.
- **N6 — No single global directory.** The design is federated: many directories, no central authority. Cross-directory sync is scoped in §7 F6; a directory must never claim exclusivity.
- **N7 — No hiding the index.** Public enumeration is accepted by design (T6 in the brief); abuse is managed with rate limits, not secrecy.
- **N8 — No censorship of lawful agents.** Suspension/takedown exist for abuse classes (§3.5), with appeal and a full audit trail; moderators act on defined categories, not opinions.
- **N9 — No floats in signed data.** Prices and any numeric value inside signed manifests are strings or integers (canonical JSON forbids floats).

### 2.6 Glossary

| Term | Meaning |
|---|---|
| Agent | A HAAP participant identified by an Ed25519 public key. |
| Fingerprint | `HF-` + first 16 hex chars of SHA-256 over the raw 32-byte public key. |
| Manifest | The signed `haap-public-manifest-v1` JSON describing an agent's public capabilities (§5.1). |
| Listing | The directory's stored, live record for an agent (manifest + directory metadata + trust signals). "Listed" iff `now <= expires_at` and status is not `suspended`. |
| Endpoint | The agent's declared `https://` messaging URL. |
| Proof-of-endpoint (PoE) | L1: proving control of the endpoint via a single-use signed challenge (§3.2). |
| Vouch | L3: a signed, expiring, revocable statement by one registered agent about another (§3.4). |
| Report | L4: a signed, categorised abuse/fraud allegation by a registered agent, or an unsigned one from a human channel (§3.5). |
| Takedown | Moderator-only action hiding an entry from search (§3.5, §8). |
| Trust signal block | The machine-readable `trust` object attached to every listing in API responses (§3.7). |
| Directory key | The directory instance's own Ed25519 key; its fingerprint is `directory_fingerprint`; signs audit checkpoints (§3.6). |
| Moderator key | Operator-controlled Ed25519 key(s) that sign moderation actions (takedowns, bans). |
| TOFU | Trust On First Use — a consumer policy primitive, not a directory feature (§3.4.7). |
| Consumer | Whoever queries the directory and then contacts an agent. Always the decision-maker. |

### 2.7 Wire conventions (normative)

1. **Canonical JSON** for anything signed: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`.
2. **Fingerprint** = `fingerprint_of_public_key(raw_pub)`; never trust a client-supplied fingerprint without recomputing it from the presented public key.
3. **Signatures** are Ed25519 over the exact byte string described per endpoint. Hex- or base64-encoded per field contract (`b64` = standard base64, no padding variants — follow `haap/crypto.py` `b64e`/`b64d`).
4. **Timestamps** are RFC 3339 UTC strings on the wire; server time is authoritative for TTLs; heartbeat timestamps must be within ±300 s of server time.
5. **Request/response bodies** are JSON, UTF-8. Content-Type `application/json`. Oversized or malformed bodies → `400`/`413` with stable codes (§4.2).
6. **Errors** always use the envelope `{"error": {"code": "UPPER_SNAKE", "message": "short human text", "request_id": "…"}}`. Codes are stable API (§4.2); never leak internals in `message`.
7. **Rate limiting**: token buckets per IP for anonymous endpoints, per fingerprint for agent endpoints; `429` responses MUST carry `Retry-After`. Headers `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` SHOULD be present.
8. **Request IDs**: the server accepts `X-Request-Id` and echoes it in the error envelope and access logs; generates one if absent.
9. **Directory signatures (optional, default on for audit endpoints)**: responses to `/v1/audit/*` are signed by the directory key over the canonical JSON body; header `X-HAAP-Directory-Signature: <b64(sig)>`, `X-HAAP-Directory-Fingerprint`. Consumers SHOULD verify audit responses before trusting them.
10. **No floats in signed data. No keys inside manifests.** Both are hard rejections (`FLOAT_FORBIDDEN`, `FORBIDDEN_FIELD`).

---

## 3. Trust architecture (the heart of this specification)

### 3.0 Model: signals, not verdicts

**Problem.** Anyone can generate Ed25519 keypairs for free, in bulk. A directory that lists "anyone with a key" is trivially Sybil-flooded with thousands of pseudonyms, and a directory that claims to know who is "trustworthy" is either lying, KYC-ing people (out of scope), or about to be gamed. The core design problem is therefore: *offer a hierarchy of signals such that each higher layer is materially more expensive or more time-consuming to fake, label every signal honestly, and leave the verdict to the consumer.*

**Layered signals (L0→L5):**

```
        ┌──────────────────────────────────────────────────────────┐
        │                CONSUMER DECIDES (always)                 │
        │   policy: acceptable risk, budget, vouchers it trusts,   │
        │   report sensitivity, TOFU vs verify-every-time          │
        └──────────────────────────────────────────────────────────┘
        ┌──────────────────────────────────────────────────────────┐
        │  L5  TRANSPARENCY     append-only hash-chained audit log │
        │      accountability for every directory + agent action   │
        ├──────────────────────────────────────────────────────────┤
        │  L4  BEHAVIOURAL REPUTATION  signed reports, flags,      │
        │      decay, suspensions, consumer-side rate limiting     │
        ├──────────────────────────────────────────────────────────┤
        │  L3  VOUCHING           expiring, revocable peer-signing │
        │      "trusted initiator" / first-contact reputation      │
        ├──────────────────────────────────────────────────────────┤
        │  L2  DOMAIN/BUSINESS    DNS TXT or HTTPS well-known      │
        │      verification -> links key to a domain it controls   │
        ├──────────────────────────────────────────────────────────┤
        │  L1  PROOF-OF-ENDPOINT  single-use challenge proves the  │
        │      key holder controls the messaging endpoint now      │
        ├──────────────────────────────────────────────────────────┤
        │  L0  CRYPTO IDENTITY     Ed25519 key; fingerprint =      │
        │      sha256(pubkey)[:16]; signatures unforgeable         │
        └──────────────────────────────────────────────────────────┘
   cost to fake:   L0 ~free (bulk)  <  L1 ~endpoint setup + 1 rtt
        <  L2 ~domain ownership/time  <  L3 ~reputation stake
        <  L4 ~time + behaviour + evidence  <  L5 ~cannot (it is
        tamper-evident, not a claim)
```

**Rules that govern every layer:**

- **R1.** A layer is a *claim* that the directory verifies as far as cryptography and protocol allow, then **labels with its method and timestamp**. The directory never upgrades a label into a verdict.
- **R2.** Higher layers do not erase lower-layer facts. A domain-verified agent that misbehaves keeps its L0–L2 signals and gains L4 negatives; consumers see both.
- **R3.** Every layer must state — in its section below — *what it does not guarantee* and *how an attacker bypasses it*. If a design cannot name its bypass, the designer has not understood the threat.
- **R4.** The consumer decides. Directory decisions are limited to: what to index (L0/L1 compliance), what to expose (all signals), and what to restrict under its terms of service for *abuse classes* (L4 suspensions, moderator takedowns) — never "trustworthiness".
- **R5.** No layer may depend on a secret the directory holds (there is no shared-secret magic). Everything is public-key cryptography and public records.

### 3.1 L0 — Cryptographic identity (Ed25519)

**Status: exists, mandatory, unchanged.** Every agent has an Ed25519 keypair. Identity is the public key; the fingerprint (`HF-` + sha256(pubkey)[:16] hex) is its short address. The directory does not create identities — it indexes them.

**Protocol.** Registration presents `public_key_b64` + a manifest signed by that key. The directory:

1. decodes the public key (raw 32 bytes);
2. recomputes `fingerprint_of_public_key(pub)` and compares with `manifest.agent.fingerprint` (`FINGERPRINT_MISMATCH` on failure);
3. verifies the manifest signature over the canonical JSON of the manifest body (`SIGNATURE_MISMATCH` on failure);
4. verifies heartbeat signatures over `"heartbeat:{fingerprint}:{timestamp}"` and vouch/report signatures over their canonical payloads.

**Guarantees.** Signatures are unforgeable by parties other than the key holder (Ed25519 assumption). Binding a listing to a key is sound: no one can *register as* someone else's fingerprint without their key. Replay is defeated by nonces/single-use challenges and ±300 s timestamps.

**What it does NOT guarantee (explicit).** A key is not a person, a business, or a reputation. Keys are free and bulk-generatable: L0 alone is **fully Sybil-vulnerable** — an attacker can mint 10 000 identities in seconds. Key theft means impersonation until the victim re-keys and reports (`L4`). A key says nothing about behaviour, intent, or future conduct.

**Who decides.** The directory decides only that the signature math holds (yes/no). Whether a bare key is *worth contacting* is entirely the consumer's call.

**Sybil mitigation.** None against mass registration — by design. L0's purpose is *attribution*: every subsequent layer attaches cost and history to a single unforgeable pseudonym, which is what makes higher layers meaningful. (Compare PGP's key-based identity model — see §12 — whose failure mode was precisely that key ownership alone never implied trustworthiness.)

**Cost.** ~0. Attacker: `for i in range(10000): keys.append(new_keypair())`.

**Bypass.** Mint keys. Done. This is expected; the architecture answers at L1+.

### 3.2 L1 — Proof-of-endpoint (PoE)

**Status: exists (reference implementation), mandatory, single-use.** An agent must prove it controls the messaging endpoint it declares, using a challenge signed by the same key that signed the manifest.

**Protocol (normative, v1; legacy aliases in §4.9):**

```
 Agent                                              Directory
   │   POST /v1/register                                │
   │   {manifest, public_key_b64, manifest_signature}   │
   │ ─────────────────────────────────────────────────► │ 1. canonical-JSON verify manifest sig
   │                                                    │ 2. fingerprint == sha256(pubkey)[:16]?
   │                                                    │ 3. schema + forbidden fields + size caps
   │   ◄──────────────────────────────────────────────  │ 4. store pending challenge (TTL 120 s)
   │   202 {challenge_id, nonce, registry_fingerprint,  │    single-use, bound to public_key_b64
   │        expires_at, algorithm:"ed25519"}            │
   │                                                    │
   │  signs nonce bytes with its PRIVATE key            │
   │                                                    │
   │   POST /v1/register/complete                       │
   │   {challenge_id, fingerprint, endpoint_proof}      │
   │ ─────────────────────────────────────────────────► │ 5. challenge exists? exact match,
   │                                                    │    single-use, unexpired
   │                                                    │ 6. public_key_b64 == key bound at submit
   │                                                    │    (else KEY_MISMATCH)
   │                                                    │ 7. verify endpoint_proof against that key
   │                                                    │    over nonce bytes (else PROOF_INVALID)
   │   ◄──────────────────────────────────────────────  │ 8. upsert agent row (live entry)
   │   201 {status:"registered", agent_url,             │    expires_at = now + TTL
   │        expires_at, directory_fingerprint}          │ 9. audit: register.completed
```

Normative details:

- Challenge TTL **120 s**, **single-use** (`CHALLENGE_USED` on the second attempt with the same id; `CHALLENGE_EXPIRED` after TTL; `CHALLENGE_NOT_FOUND` for unknown ids).
- `endpoint_proof` MUST verify with `verify_with(raw_pub_of_the_challenge, nonce_bytes, endpoint_proof)`. A proof by any other key → `PROOF_INVALID`, agent **not** listed.
- The `public_key_b64` in `/v1/register/complete` (when present) MUST equal the one bound at submit; mismatch → `KEY_MISMATCH`, not listed. (Existing test: `test_failed_endpoint_proof_not_listed`.)
- The directory never contacts the endpoint itself during registration (a directory that connects to arbitrary attacker URLs is a SSRF vector; PoE is done by *the agent proving it can answer a signed message* — the endpoint's actual reachability is the consumer's job to probe). Endpoint must parse as `http(s)://` with no query/fragment (`ENDPOINT_INVALID`).
- Re-registration of a live fingerprint = **update** (bump manifest/fields, keep `registered_at`); registration of an expired entry = fresh insert.

**Guarantees.** At registration time, the key holder demonstrably received a challenge addressed to the declared endpoint (or a proxy that can forward to it) and produced a signature only that key can make. Combined with L0: the listed key and the live endpoint are under the same control *at that moment*.

**What it does NOT guarantee (explicit).** Not that the endpoint stays controlled (the agent could sell/abandon the domain an hour later — heartbeats only re-prove liveness, and even a live endpoint proves only *that a process answers*, which a fraudster's own server does too). Not that the endpoint is not a honeypot. Not that the operator is honest. PoE is a *now* statement about control, refreshed by heartbeats, never a character reference.

**Who decides.** Directory: whether PoE succeeded (yes/no gate for listing). Consumer: whether a live-but-unverified endpoint is worth messaging, and what to do if the endpoint later behaves maliciously (L4 reports; client-side blocks).

**Sybil mitigation.** Raises per-pseudonym cost from ~0 to one endpoint setup + one round trip per identity, and — importantly — binds each Sybil to a **distinct reachable endpoint**, which later layers (L2 domains, L4 takedowns, operator abuse response) can act on. It does **not** stop Sybil: an attacker with 100 VPS/domains gets 100 listings.

**Cost.** Agent: one HTTP round trip + a signature. Attacker: ~one endpoint per identity (cheap at cloud scale, but now *enumerable and actionable*).

**Bypass.** Stand up N cheap endpoints (subdomains of a wildcard domain, ephemeral VPS, tunnelled servers) and complete N challenges. Honest counter: L2 makes each such endpoint provably *yours* and therefore provably *yours to lose*; L4 lets the community sink them.

### 3.3 L2 — Domain / business verification (NEW)

**Status: new in this specification.** L2 answers: *"can the key holder prove control of the domain they claim as their business home?"* It anchors the pseudonymous key to a real-world, renewable, publicly auditable name (a domain), which is the cheapest durable real-world identifier the protocol can verify without KYC.

**What is verified.** The agent declares a domain (in the manifest: `agent.trust_claims.domain`, or at verify time). Control of that domain is proven with one of two challenge-response methods, both checked **server-side by the directory** (the agent never reports its own success):

- **Method `dns_txt` (preferred).** The directory issues a random 128-bit token, the agent publishes a TXT record at `_haap.<domain>` containing the token, and the directory resolves it itself over DNS.
- **Method `https_well_known`.** The directory issues a token and fetches `https://<domain>/.well-known/haap-verify.txt` (or `.json`, see §4.3) itself over TLS, requiring the token verbatim in the body.

```
      Agent                       Directory                    DNS / Web
        │  POST /v1/verify-domain     │                          │
        │  {fingerprint, domain,      │                          │
        │   method:"dns_txt"}         │                          │
        │ ──────────────────────────► │ token = rand_hex(32)     │
        │                             │ store pending (TTL 30m)  │
        │  ◄──────────────────────────│ 202 {verification_id,    │
        │  202 {verification_id,      │      token, instructions}│
        │       token, method,        │                          │
        │       expires_at}           │                          │
        │                             │                          │
        │  (agent publishes TXT)      │                          │
        │  _haap.euraka.example =     │                          │
        │  "haap-verify=<token>"      │ ───────────────────────► │
        │                             │                          │
        │  POST /v1/verify-domain/confirm  {verification_id}     │
        │ ──────────────────────────► │ 1. pending alive?        │
        │                             │ 2. directory queries     │
        │                             │    DNS TXT _haap.<domain>│
        │                             │    (or fetches well-known│
        │                             │     over TLS, no redirect│
        │                             │     off-domain)          │
        │                             │ 3. token present verbatim│
        │  ◄──────────────────────────│ 4. persist verified row  │
        │  200 {status:"verified",    │    valid 90 days         │
        │       domain, method,       │ 5. audit: domain.verified│
        │       verified_at,          │                          │
        │       expires_at}           │                          │
```

Normative details:

- Domain rules: lowercase, no scheme, no port, IDN in punycode (`DOMAIN_INVALID`). The agent's declared `agent.endpoint` host MUST equal the verified domain or be a subdomain of it, checked at confirm time (`DOMAIN_ENDPOINT_MISMATCH`) — otherwise verifying a domain the endpoint does not live under proves nothing useful.
- DNS check: resolve TXT `_haap.<domain>` (follow no CNAME off-domain — if the `_haap` label is a CNAME to a third-party zone, that third party could answer; MUST treat off-domain CNAME as failure or require the final zone to be under the same registrable domain). Token accepted if any single TXT record equals the token or starts with `haap-verify=<token>` (so the record can coexist with other uses).
- HTTPS check: fetch `https://<domain>/.well-known/haap-verify.txt`; body must be exactly the token (trimmed), or for `.json` the field `{"haap_verify_token": "<token>"}`. Redirects allowed only to the same registrable domain; TLS verified against public CAs; response ≤ 4 KiB; timeout 10 s.
- Both methods: token TTL **30 minutes**, single-use, bound to the requesting fingerprint.
- Verification result validity: **90 days** from `verified_at`, after which the signal downgrades to `domain_verified: false` until re-verified (heartbeat response and search results reflect the downgrade immediately). An agent MAY hold verifications for several domains; the one matching the endpoint host is the one surfaced as `primary`.
- Signature: `/v1/verify-domain` and `/v1/verify-domain/confirm` requests MUST be signed by the agent key over the canonical JSON of the request body (fields `fingerprint, domain, method` / `verification_id`) — proving the key holder (not a random caller) requested the check.

**Guarantees.** A successful L2 check proves, at `verified_at`, that the party holding the listing's private key also (a) can write DNS records for `<domain>` or (b) can place files under `https://<domain>/.well-known/`. It therefore links the pseudonym to a **renewable real-world asset the operator cares about**, anchors the agent's geo/name claims to that domain, and gives consumers a stable handle to search and to correlate with other records (whois history, business registries, other directories). This is the same *domain-control* primitive ACME uses before issuing certificates — the directory borrows it as a *reputation anchor*, not as a CA (Let's Encrypt, §12).

**What it does NOT guarantee (explicit — read twice):**

- **Not KYC, not legal identity.** Domains are cheap, anonymous-ish, and rentable. Verification proves control of a string, not the existence of a lawful business. (Explicitly out of scope: N5.)
- **Not honesty, quality, or solvency.** A verified domain can run a scam; "verified" refers to *domain control*, nothing else. The directory MUST therefore label the signal `domain_verified`, never "verified business" or "trusted".
- **Not protection against typosquatting.** `euraka-victoria-booking.com` is verifiable. Consumers should eyeball the domain string; the directory does not police similarity (moderators may, under L4 abuse categories).
- **Not permanence.** The domain can be transferred, expire, or be re-registered by someone else. Verification re-expires every 90 days; the directory does not monitor whois.
- **DNS/TLS trust assumptions.** DNS poisoning, registrar compromise, or a hostile CA can fake either method — the same limits as Let's Encrypt's domain validation (see §12).
- The domain owner *themselves* may be the attacker (a scammer happily verifies their own scam domain). L2 raises cost; it does not remove motive.

**Who decides.** Directory: mechanical verification only (token match + endpoint-domain consistency), with full audit rows. Consumer: decides what a verified domain is worth to them (e.g., policy: "only contact agents with a verified domain matching their stated business", "only `.es` businesses with geo in Vitoria", etc.). Google Business Profile verification (postcard/phone/video — see §12) is the offline analog: Google verifies *control of a channel*, and even that does not certify the business's quality; the directory's L2 is deliberately weaker (no human review) and labels itself accordingly.

**Sybil mitigation.** This is the first layer with real marginal cost: each Sybil identity that wants the L2 signal needs a domain it controls (≈ US$10/yr + setup time + DNS propagation latency, and, for method `dns_txt`, a visible paper trail linking the identity to the domain). Casual mass-registration dies here. Note the cost is per *domain*, and a wildcard domain lets one actor verify many subdomain endpoints — so the *unit of Sybil resistance* is the registrable domain, which is exactly what L4 suspensions and moderator takedowns target.

**Cost.** Agent: domain ownership + one DNS publish (minutes) or one file placement + directory-side fetch. Directory: one DNS query or TLS fetch per confirm (rate-limited, cached). Attacker: ~US$10 + minutes per verified identity; bulk verification is throttled per domain and per IP/fingerprint.

**Bypass.** Buy cheap/expired domains; typosquat adjacent names; use subdomains of a domain you own for every fake persona (`scam1.evil.example`, `scam2.evil.example`, …); rent domains via privacy services. Nothing here stops a *funded* attacker; it stops the *unfunded flood*, and it makes every fake persona traceable to a domain the community can sink (L4), block (consumer-side), and correlate across directories (L5/federation).

**Relationship to L0/L1.** L2 subsumes neither: L0 binds key↔fingerprint, L1 binds key↔endpoint-now, L2 binds key↔domain. A listing is strongest when all three hold *and* L3 vouches and L4 history corroborate.
### 3.4 L3 — Vouching: "trusted initiator" and first-contact reputation (NEW)

**Status: new in this specification.** L3 answers: *"who, among entities I might already trust, is willing to put a signed, expiring statement behind this agent?"* It is a *first-contact* mechanism: when a consumer meets an agent for the first time, the directory surfaces the agent's **inbound vouch graph** so the consumer can apply its own trust set (people/organisations it already trusts) instead of trusting a stranger from zero. This is the directory-native analogue of the PGP "web of trust" idea — with the PGP failure modes explicitly designed out (§3.4.6).

**Why "trusted initiator"?** A vouch is a statement by an established agent (the **voucher**) about another (the **vouchee**), scoped and time-boxed: *"I, agent V, assert by my key that agent B is what B claims to be, within scope S, for the next T days. If B misbehaves in S, my statement is on the record."* The voucher is the "trusted initiator" of the vouchee's reputation: without vouches, a new agent's reputation starts at zero and grows only by L4 behaviour over time; a vouch lets an agent *borrow* reputation from someone the consumer already trusts.

**3.4.1 Protocol — grant a vouch**

```
 POST /v1/vouches
 {
   "voucher_fingerprint": "HF-3f7a9c1b2d4e5f60",      // the truster
   "vouchee_fingerprint": "HF-9d8e7f6a5b4c3d2e",      // the trusted (first contact)
   "scope": "service:hairdresser:booking",             // what the vouch covers
   "weight": 1,                                        // 1 only in v1 (reserved)
   "note": "Met via CalDAV booking; delivered 3 clean haircuts.",
   "expires_at": "2026-12-03T12:00:00Z",               // REQUIRED, <= 180 days
   "created_at": "2026-09-04T12:00:00Z",
   "signature": "<b64 Ed25519 over canonical JSON of the object WITHOUT signature field>"
 }
 → 201 {vouch_id, status:"active", …}  |  4xx stable codes
```

Normative rules:

- **Both parties MUST be registered and currently live** (listed, heartbeat within TTL): `VOUCHER_NOT_LISTED` / `VOUCHEE_NOT_LISTED`. Rationale: vouching requires the voucher to *currently* hold an L1-verified, heartbeat-fresh identity — a stolen or abandoned key cannot keep vouching. This is the only way the directory can make vouching cost *ongoing liveness* rather than a one-time signature.
- **Voucher tenure**: the voucher's own listing must be older than the vouchee's at grant time? **No** — tenure asymmetry is left to consumers (matrix row "voucher age"), because a directory rule would block legitimate new-agent sponsorship. But a voucher must have existed ≥ 72 h *before* its first vouch is *counted as eligible toward any automated L4 threshold* (see §3.4.6). Fresh agents MAY vouch immediately; their vouches are simply labelled "young voucher" in the trust block.
- **Scope strings** are free-form lowercase, but the directory recognizes a set of canonical prefixes (`identity`, `task_delivery`, `service:<category>`, `payment`). A vouch only means what its scope says; `identity` vouches and `service:hairdresser:booking` vouches are different claims.
- **Expiry is mandatory**: `expires_at` in the future, ≤ 180 days from `created_at`. Vouches never auto-renew; the voucher must re-sign.
- **Cap**: an agent may hold at most **10 active outgoing vouches** (`VOUCH_LIMIT_REACHED`). This keeps voucher-dilution bounded and makes "who vouches" a scarce, meaningful resource. Incoming vouches are uncapped.
- **Revocation**: `DELETE /v1/vouches/{vouch_id}` with body `{voucher_fingerprint, revoked_at, signature}` signed by the voucher key. Revocation is immediate, permanent for that vouch id, and audited. A voucher MAY revoke because the vouchee misbehaved — that is the cheapest honest signal a victim can emit (and it is visible in L5).

**3.4.2 Protocol — read the graph**

```
 GET /v1/agents/{fingerprint}/vouches            → inbound (who vouches FOR this agent)
 GET /v1/agents/{fingerprint}/vouches/outgoing   → outbound (who this agent vouches for)
 GET /v1/trust/paths?from=HF-A&to=HF-B&max_depth=2
     → shortest vouch paths A → … → B (only active, unexpired, unrevoked edges)
```

`GET /v1/trust/paths` is BFS over *active* edges only, capped at depth 2, returning each path as a list of edges with full metadata (voucher, scope, created/expires, revoked_at if any). The directory computes **no** aggregate over paths — no "distance score", no PageRank. Raw paths only.

**3.4.3 Guarantees.** An active vouch proves: a currently-live, L0+L1-verified agent V, holding its own key, signed a statement that vouchee B is what B claims within scope S, with an expiry, at a time, and that statement is on the public record until revoked/expired. Because every vouch is key-signed and audited, V **cannot later deny it** — that is the accountability that makes vouching a reputation *stake* rather than a comment box.

**3.4.4 What it does NOT guarantee (explicit).**

- **Vouches are opinions with signatures, not facts.** V may be wrong, careless, or colluding. A vouch from an agent you do not know is worth nothing to you; a vouch from an agent *you* trust is worth that agent's reputation — which is precisely why vouches are only meaningful relative to the consumer's own trust set. This is the core PGP lesson (see §12, PGP web-of-trust analyses): *a web of trust only helps people who are already inside a web of trust; for everyone else it is a graph of strangers signing for strangers.*
- **No transitive trust.** The directory serves ≤ 2-hop *paths* as raw edges; it never certifies that "B is trustworthy because A and C vouch for B". Transitivity is a *consumer policy* (and a dangerous one — see §3.4.6).
- Vouching does not verify offline identity, does not predict future behaviour, and does not cover out-of-scope behaviour (a `task_delivery` vouch says nothing about payment honesty).

**3.4.5 Who decides.** Vouchers decide what to sign (and pay the reputational cost of being wrong). The directory decides only *eligibility mechanics* (live keys, caps, expiry, revocation validity). **Consumers decide which vouchers they trust** — the API is built so a consumer can request "paths from my own fingerprint" (`/v1/trust/paths?from=<consumer_fp>&to=<target>`) and apply its own threshold (e.g., *"I contact B only if a voucher I've rated highly vouches for B in scope `service:*`"*).

**3.4.6 Sybil mitigation and the collusion-ring answer.** Vouching is where Sybil attacks get *social*. A ring of 50 fake agents can vouch for each other for free. The design does **not** pretend to stop this with a directory-side score (any such score is gameable — the PGP WoT analysis literature is a graveyard of trust-metric proposals). Instead:

1. **No aggregate.** The directory never says "B has 47 vouches ⇒ B is trusted". It shows *who* vouched, so a consumer can spot a ring of strangers instantly (47 vouchers, all registered 3 days ago, all vouching only each other, none with L2 domains).
2. **Voucher identity is expensive at the margin.** Each vouching agent is an L0+L1 identity with a live endpoint and heartbeats. Sustaining a *convincing* ring (long-lived, heartbeating, occasionally domain-verified, with organic-looking behaviour) costs real money and time per member.
3. **Young-voucher labelling.** Vouches by listings < 72 h old are labelled `voucher_tenure_hours` in the trust block; consumer policies can ignore them. The directory does not hide them — it ages them visibly.
4. **Ring detectors (signals, not verdicts).** The directory exposes structural facts: mutual-vouch density, shared registration IP clusters, shared verified domains, correlated heartbeats. These are **exposed as raw annotations on the graph endpoints** (e.g., `GET /v1/agents/{fp}/vouches` includes `"vouchers_share_registration_cluster": true` when ≥ 3 inbound vouchers registered from the same /24 within 24 h) — the consumer's policy consumes them; the directory does not judge.
5. **Post-hoc punishment is real.** When a vouchee is suspended for hard abuse (L4) *within the active window of a vouch*, the vouch is not deleted — it stays visible next to the red record, and the voucher's own file shows "vouched for N agent(s) since suspended". Repeat bad judgement is a visible pattern (L5 audit makes it undeniable). Consumers discount vouchers with bad hit rates; nothing in the directory deletes that history. This is the honest version of "vouchers stake their reputation".

**Bypass.** Rings, sock-puppet vouchers, buying one "respected" voucher's key, vouching between *real* accounts of the same operator (the classic review-fraud pattern — see §12 eBay reputation literature: sellers rating themselves via secondary accounts was endemic and only partially cured by identity cost + behavioural filtering). Honest answer: L3's job is not to stop collusion — it is to make collusion *visible as a pattern* and *priced in reputation*, while L4 provides the behavioural sink that eventually outlives any ring. Consumers who skip the signals and trust "number of vouches" will be exploited; the spec protects the consumer who reads the matrix (§3.7).

**Cost.** Voucher: one signature + the ongoing reputational stake + scarcity (≤ 10 outgoing). Directory: edge storage, BFS on demand (depth ≤ 2, cheap). Attacker ring: N × (key + endpoint + heartbeats + time) — cheap for 50, expensive for 5 000 *sustained*.

**3.4.7 First-contact workflow (consumer side, supported not enforced).** Recommended consumer policy for meeting an unknown agent:

```
                        ┌──────────────────────────────┐
                        │ search returns agent B +     │
                        │ trust block (§3.7)           │
                        └──────────────┬───────────────┘
                                       ▼
        does B have L2 domain_verified AND is the     no ─┐
        domain string plausibly the real business? ──────► │
                       │yes                               │
                       ▼                                   │
        do I trust any ACTIVE voucher of B? ────────────►  │   higher
        (paths from my fingerprint, depth<=2)  │           │   caution:
                       │yes                   │no          │   TOFU +
                       ▼                      ▼            │   rate-limit
        moderate caution            do I accept TOFU? ────►│   contact,
        (verify B's own           │yes            │no      │   verify
        /.well-known/haap.json)   ▼               ▼        │   via out-of-
                       │    TOFU pin +        don't        │   band
                       │    client-side       contact B    │   channel
                       │    rate limits       (or require  │
                       ▼                      vouched      │
        contact B, verify identity at first                │
        message (envelope signed by fingerprint)           │
                       └───────────────────────────────────┘
        Every arrow here is CONSUMER policy. The directory only
        supplied labelled signals; it decided nothing.
```

### 3.5 L4 — Behavioural reputation: reports, takedown, decay, consumer-side rate limits (NEW)

**Status: new in this specification.** L4 answers: *"what has this agent actually done, according to signed witnesses, and how does that change over time?"* It is the ecosystem's collective memory of behaviour. It exists because L0–L3 are all *claims made before or at first contact*; only observed behaviour over time separates a good agent from a patient scammer.

**3.5.1 Protocol — submit a report**

```
 POST /v1/reports
 {
   "reporter_fingerprint": "HF-…",                  // registered agent (REQUIRED for
                                                    // a report that counts; see below)
   "target_fingerprint":  "HF-…",
   "category": "fraud",            // one of: impersonation_attempt | endpoint_hijack |
                                   // phishing | spam | fraud | payment_fraud |
                                   // abusive_content | protocol_violation | report_abuse
   "severity": "high",             // low|medium|high (moderators see it; thresholds use it)
   "evidence": {                                    // REQUIRED, structured, honest
     "kind": "envelope",                            // envelope | url | transcript | none
     "envelope_b64": "<base64 signed HAAP envelope(s) from the interaction>",
     "description": "Booked corte; agent demanded prepayment to a wallet and vanished.",
     "refs": ["https://…"]
   },
   "occurred_at": "2026-09-03T18:00:00Z",
   "submitted_at": "2026-09-04T09:00:00Z",
   "signature": "<b64 Ed25519 by reporter over canonical JSON without signature>"
 }
 → 202 {report_id, status:"recorded"} | 4xx codes
```

Normative rules:

- **Counting reports (eligibility):** a report counts toward automated thresholds only if the reporter (a) is a registered agent, (b) has been listed ≥ **72 h**, (c) is currently live, and (d) has not reported this target in the same category within the last 24 h (`REPORT_LIMIT_REACHED`). Anonymous/human reports are accepted via the moderation channel (§9.4) and stored with `"reporter": "human_moderation_channel"` — they never count toward automated thresholds, only toward moderator review.
- **Evidence honesty:** `evidence.kind` must be truthful (`none` is allowed — a report can be a good-faith warning with no captured envelope, but it counts less: severity displayed as submitted, threshold weight halved for `kind=none`). Fabricated evidence, once detected, is `report_abuse` and grounds for reporter suspension.
- **Duplicate reports:** same reporter+target+category within 24 h → 409 `REPORT_EXISTS` (idempotency: re-POST with the same `report_id` client-generated id returns the original).
- **Mutual-report detection:** A↔B reporting each other ≥ 2 times within 30 days flags both as `report_war` (annotation; both reports still visible — the directory does not suppress evidence of a dispute).

**3.5.2 What the directory does with reports — flags, not verdicts**

The directory runs **deterministic, transparent automata** (no ML, no human judgement inside the hot path), every transition audited:

1. **Annotation.** Every listed agent carries live counters in its trust block: `reports {by_category, unique_reporters, first_at, last_at, pending_suspension}`. Counters are raw facts, always visible.
2. **Automated flag → suspension** for *abuse classes only* (`spam`, `phishing`, `impersonation_attempt`, `endpoint_hijack`): when ≥ **3 unique eligible reporters** (all live, listed ≥ 72 h) report the target in the same class within a **7-day window**, the entry is auto-`suspended`: hidden from search and profile-by-fingerprint returns `status:"suspended"`, heartbeats still accepted (so the agent keeps its key alive and can appeal), vouches inbound/outbound frozen visible. Suspension is **not** a trust verdict: it is a spam-filter-grade abuse control with a published rule, an appeal path (§3.5.5), and a full audit row (`report.auto_suspend`). No other category auto-suspends.
3. **Moderator takedown.** Any category, any evidence: a moderator-key-signed `POST /v1/reports/{report_id}/takedown` (or `/v1/agents/{fp}/suspend`) hides the entry immediately (`TAKEDOWN_UNAUTHORIZED` without a moderator signature). Moderator actions are first-class audit events with the moderator key fingerprint attached — *who hid what, when, with which report id* is public in L5.
4. **Decay.** All report counters decay: displayed counters always carry `first_at`/`last_at`, and the automated suspension window is a *rolling 7 days*. Reports older than **180 days** stop contributing to any automated decision (weight 0) but remain visible in history and L5. Decay means reputation is about the *recent* past: an agent can reform (its record shows old reports + new clean behaviour); a good agent gone bad loses its history's shield within 7 days of the first credible report.
5. **Consumer-side rate limiting.** The directory's own rate limits protect *itself*. For *consumer safety*, the directory exposes `trust.block_recommendation` — a pure function of the raw counters (e.g., `"default_max_contact_rate_h": 1` when recent unique reporters ≥ 2 in fraud/payment classes) — that consumer clients MAY ingest to throttle first-contact messaging to unknown agents. The recommendation is data, not enforcement, and never blocks anyone directly.

```
 report arrives ──► eligible? ──no──► stored visible (human channel / young reporter)
                        │yes
                        ▼
              counters update (audit)
                        ▼
        class in {spam, phishing,           no ──► stays a visible counter;
        impersonation, endpoint_hijack}?          moderators can act on it
                        │yes
                        ▼
        ≥3 unique eligible reporters            no ──► visible, watch state
        in rolling 7d window?                        (X-HAAP watch header)
                        │yes
                        ▼
              AUTO-SUSPEND entry          appeal ──► moderator review ──►
              (audit: auto_suspend)       (agent signs appeal)        │
                        │                                            ▼
                        ▼                                   restore | uphold
        target hidden from search; counters keep
        updating; heartbeats still accepted
```

**3.5.3 Guarantees.** Every report is a signed, audited, attributable event with structured evidence; counters shown are the *exact* raw numbers behind any automated action; the automation is a published deterministic rule anyone can replay from the audit log; every suspension/takedown has a reason class, evidence ids, and the key that caused it; decay bounds the damage of ancient history while preserving it.

**3.5.4 What it does NOT guarantee (explicit).**

- **Reports are allegations, not findings.** Most reports are never moderator-reviewed (volume); auto-suspension is a statistical abuse filter and *will* occasionally catch an innocent agent (appeal exists, false positives are audited and visible). A single report — even a "high severity" one — proves nothing about the target. **The directory never marks a target "guilty".**
- **No protection against coordinated lying.** 3+ colluding reporters can auto-suspend a victim for a week (griefing). Mitigations: reporters must be ≥ 72 h old, live, unique, and their reports are public + audited, so the ring is identifiable and itself suspendable for `report_abuse`; but the *window of harm exists*. This is priced into §8 (T-D06). A paid-report marketplace can amplify this (see Open Questions §11 on staking).
- **No prediction.** A clean record is not a promise; a dirty one is not a life sentence (decay).
- **Evidence is as good as its provenance.** Envelopes prove *some* agent said *some* thing; they do not prove the real-world harm.

**3.5.5 Who decides.** Reporters decide to report (and are accountable for false reports). The directory decides *mechanics*: eligibility, counters, the published auto-suspend automaton, decay. **Moderators** (operator-held keys) decide takedowns and appeals — the only human judgement in the system, and it is fully audited. **Consumers decide** whether and how to weigh the counters, follow `block_recommendation`, or contact anyway. The directory never decides "this agent is bad" — it says "here is what N signed witnesses alleged, when, and what the published rule did about it".

**3.5.6 Sybil mitigation.** Reports are the *weapon* Sybils use against honest agents (griefing) and the *tool* honest agents use against Sybils (sinking spam rings). The design constraints: (a) every counting reporter is an L0+L1 identity that is ≥ 72 h old and currently heartbeating — an attacker must maintain an army *before* it can libel anyone; (b) unique-reporter counting stops one key from voting 100 times; (c) false reports are themselves the `report_abuse` category with the same automaton (3 unique reporters → the *reporter* is suspended); (d) everything is public and replayable, so a griefing ring leaves a perfect, punishable record. Residual: a well-funded ring can still land a 7-day suspension on a target. Decay + appeal + audit make the *permanent* damage zero, which is the achievable goal.

**Cost.** Reporter: L0+L1 identity, 72 h tenure, live heartbeat, signature. Directory: counters + a small automaton. Attacker: N sustained identities to swing a 3-vote threshold — cheap at N=3, expensive to keep secret at N=100.

**Bypass.** Build a long-lived sock-puppet army slowly (weeks of heartbeats, staggered registration) and use it to (a) auto-suspend competitors, (b) upvote own vouches. Mitigation is layered: L2 domain verification makes the army's members individually sinkable and traceable; `report_war`/mutual-report and registration-cluster annotations expose the pattern; moderator review of appealed suspensions reverses the harm; L5 makes the whole operation a matter of public record. This is a moderation *arms race* — the spec's answer is transparency + reversibility + consumer choice, not a perfect filter (perfection is impossible; see §12 reputation literature on eBay: reputation systems reduce but never eliminate fraud, and their power decays with sock-puppet cost — which is why L2 raises that cost).

### 3.6 L5 — Transparency: append-only, hash-chained audit log (NEW)

**Status: new in this specification.** L5 answers: *"can anyone verify that the directory itself behaved — that this listing, this suspension, this vouch, this report really happened, in this order, and that the log has not been rewritten?"* Every meaningful event (registration accepted/rejected + reason, PoE completions, heartbeats, expirations, domain verifications, vouches, revocations, reports, auto-suspensions, moderator takedowns, appeals, operator config changes, rate-limit floods) is appended to an **append-only hash chain** the directory publishes and signs.

**3.6.1 Chain construction (normative).**

Let each entry be the canonical JSON of:

```
entry[n] = {
  "seq": n,
  "ts": "<RFC3339 UTC>",
  "event": "<event_type>",                 // e.g. "register.completed", "report.recorded",
                                           // "domain.verified", "agent.auto_suspend",
                                           // "moderator.takedown"
  "fingerprint": "HF-…",                   // subject agent, or null
  "actor": "agent:HF-… | moderator:HF-… | directory | rate_limiter",
  "result": "ok | rejected:<CODE> | suspended | …",
  "detail_hash": "<sha256 hex of canonical JSON of detail object>",
  "prev_hash": "<sha256 hex of entry[n-1] canonical JSON>"
}
entry_hash[n] = sha256( canonical_json(entry[n]) )
```

- `entry[0]` is the **genesis entry**: `{seq:0, ts:<server first boot>, event:"chain.genesis", prev_hash:"0"×64, detail_hash:…}` — signed by the directory key at first boot.
- The chain head is `{seq, entry_hash}` served by `GET /v1/audit/head`. Every write appends **inside the same SQLite transaction** as the state change it records (if the state change commits, the chain entry commits; there is no window where state moved without a log line).
- **Checkpoints:** the directory key signs `{seq, entry_hash, ts}` every **hour** and on shutdown; `GET /v1/audit/checkpoints` lists them (`X-HAAP-Directory-Signature` over the body). Consumers who poll hourly can detect any rewrite of anything they have already seen; the gap between checkpoint and a later rewrite is at most the polling interval.
- **Download & verify:** `GET /v1/audit/log?after=<seq>&limit=<n>` returns contiguous entries; any client can re-hash and confirm `prev_hash` linkage and recompute `detail_hash`. Mirror operators SHOULD download the full chain periodically and compare heads with the operator's out-of-band checkpoint publication.

```
  entry n-1                entry n                 entry n+1
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ prev_hash ───┼──┐     │ prev_hash ───┼──┐     │ prev_hash ───┼──┐
 │ detail_hash  │  │     │ detail_hash  │  │     │ detail_hash  │  │
 │ event/data   │  │     │ event/data   │  │     │ event/data   │  │
 └──────────────┘  │     └──────────────┘  │     └──────────────┘  │
                   ▼                       ▼                       ▼
       entry_hash[n-1] ──────────► sha256(entry n-1 + prev)…  chain: every
       hash binds to prev; rewrite any entry ⇒ all descendants change
       ⇒ head hash mismatch ⇒ caught at next checkpoint comparison
```

**3.6.2 Guarantees.** Tamper-*evidence*: any modification, deletion, or reordering of appended events changes every subsequent hash and the head, which the operator's signed hourly checkpoints (and any independent mirror's copy) will expose. Every directory decision that matters — especially suspensions, takedowns, and rejections — is public with its reason and actor key. An independent operator can run a **mirror** (§7 F6) that ingests the chain and serves it, making "the directory rewrote history" detectable even against a hostile operator.

**3.6.3 What it does NOT guarantee (explicit).**

- **Not tamper-*proof*.** The operator controls the database and can rewrite it; the hash chain only guarantees that a rewrite is *detectable by anyone who fetched a checkpoint before the rewrite*. True append-only-ness requires external anchoring (a public transparency log, blockchain/EAS-style attestation anchoring, or RFC 9162 CT-style logs — see §12 Sigstore/EAS notes and Open Questions §11). Local chain = tamper-evidence; external anchor = tamper-proofness. v1 ships local + signed checkpoints; external anchoring is an F6+ option.
- **Not completeness against omission.** The operator could *not log* an event it processed. Checkpoints sign the chain, not the world. (External anchor + mirrors reduce but cannot eliminate this; an omitting operator is a policy/trust problem, which is what federation and open questions address.)
- **Not secret-free by magic**: entries must never contain private keys, tokens, or report *bodies* — only hashes of details (`detail_hash`), so sensitive evidence stays out of the public chain while remaining verifiable-by-producer.
- Consumers who never fetch checkpoints get no protection at all.

**3.6.4 Who decides.** The directory decides what to log (spec says: everything that changes state or enforces a limit); the *verifier* (consumer, mirror, researcher) decides whether the log is consistent. The operator's key is public; its signature over checkpoints is the only directory-side authority, and it is itself audited (key rotation is an audit event).

**3.6.5 Sybil mitigation.** Indirect but real: L5 is what makes L3 and L4 *accountable*. A report-stuffing ring, a moderator abusing takedown power, a voucher denying its vouch, an operator quietly un-suspending a scammer — all are public, ordered, attributed facts. Sybil attacks rely on deniability at scale; L5 removes it. It is also the substrate for federation (F6): a mirror with an identical chain head is proof two directories saw the same world.

**Cost.** One hash + one row per event (bytes); hourly signature; unbounded growth — archival is append-only by design (disk is the cost of honesty; estimate §9.5). Attacker: nothing to bypass *locally* except by owning the operator — which is why the *consumer-facing* guarantee is "detectable rewrite", priced at "poll checkpoints hourly", and why external anchoring is on the roadmap.

**Bypass.** Rewrite the DB and the chain together before anyone fetches a checkpoint (undetectable to everyone who never saw the old head); omit events; or simply operate the directory maliciously from day one (L5 cannot make an evil operator honest — federation and consumer choice of directory are the answer, see §6.4 multitenancy and §11).

### 3.7 Trust decision matrix — what each visible signal means

Every listing in search/profile responses carries a machine-readable `trust` block (§5.2). The matrix below is **normative**: it fixes the field names, what each field *means*, and the wording the directory may use. The directory MUST NOT attach any meaning not listed here, and MUST NOT combine rows into a verdict.

| # | Signal exposed (field) | What it means (and only this) | What it does NOT mean | Consumer lever |
|---|---|---|---|---|
| M1 | `listed_since` / `age_days` | Key has held a listed entry this long | Not legitimacy, not activity quality | Policy: require min age for high-value tasks |
| M2 | `last_heartbeat` / `fresh` | Endpoint process answered a signed liveness check at this time | Not that the endpoint is honest or reachable *now* from you | Probe endpoint yourself before trusting |
| M3 | `endpoint_proof_at` | L1 PoE completed at this time | Not ongoing control (see §3.2) | Re-verify via agent's own `.well-known` |
| M4 | `domain_verified: true, verification:{domain,method,at,expires_at}` | Key holder controlled this domain at `at` (DNS/TLS challenge, server-side) | NOT "verified business", NOT KYC, NOT quality, NOT honesty, NOT typosquat-safety | Eyeball the domain string; check business externally; require it for real-money tasks |
| M5 | `vouches_in: [{voucher, scope, expires_at, tenure}]` | These live agents signed scoped, expiring statements for this agent | Not a score, not transitive truth; ring vouches are possible | Apply YOUR trust set: do I trust any voucher? paths from me (≤2 hops) |
| M6 | `voucher_tenure_hours` (per vouch) | How long the voucher had been listed when it vouched | — | Policy: ignore vouches from <72 h agents |
| M7 | `reports:{by_category, unique_reporters, first_at, last_at}` | Raw signed allegations, attributed and audited | Allegations ≠ findings; counts ≠ guilt; no ML verdict | Weigh by category + recency + reporter quality |
| M8 | `status:"suspended"` + `suspension:{rule, evidence_reports, at}` | The published automaton (≥3 unique eligible reporters in 7 d, abuse classes) or a moderator action hid the entry | Not a court finding; reversible by appeal; possible griefing | Treat as strong caution; check appeal state; verify out-of-band |
| M9 | `block_recommendation` | Pure-function guidance from raw counters (rate-limit suggestion) | Not enforcement, not a block | Client may ingest to throttle first contact |
| M10 | `audit_verifiable: true` | All of the above events are in the public hash chain (§3.6) | Not that the operator is honest | Poll checkpoints; run a mirror for real assurance |
| M11 | `reputation_history`: past suspensions, report_war flags, vouch revocations | Durable public record with decay | Not a life sentence (decay §3.5.2.4) | Long-horizon decisions read history, not just counters |
| M12 | `directory_fingerprint` on every response | Which directory's view this is | Directories may differ (federation) | Cross-check multiple directories for high stakes |

**The consumer decides — always.** The directory's only "decisions" are: what to index (L0/L1 compliance), what automata to run (published, audited), and what moderators do (signed, audited, appealable). Every row above is delivered as *data with provenance*, never as "safe to talk to". When in doubt, the API contract (§4) and the consumer workflow diagram (§3.4.7) both end the same way: *the last step is always a consumer policy*.

### 3.8 How the layers compose (and why no single layer suffices)

| Layer | Kills this attack | Dies against | Composed with |
|---|---|---|---|
| L0 | Impersonation of *existing* keys (signatures unforgeable) | Mass minting of *new* keys | Gives L1–L4 an unforgeable subject to attach cost to |
| L1 | Listing endpoints you don't control; replay of registrations | Endpoint rented per Sybil | L2 anchors the endpoint to a domain you own |
| L2 | Anonymous bulk registration (cost + paper trail per domain) | Funded attackers, typosquatting, domain-owning scammers | L3/L4 sink the domain once behaviour shows |
| L3 | Zero-reputation first contact (borrowed trust via vouchers you trust) | Collusion rings; naive "vouch count" consumers | L4 outlives rings; L2 makes rings traceable; L5 makes rings provable |
| L4 | Persistent abuse of the index (spam, phishing, fraud sinks) | Coordinated lying (griefing), paid report armies | Decay + appeal bound the harm; L5 audits it; moderators reverse it |
| L5 | Silent directory misbehaviour (rewrites, secret takedowns) | Operator who misbehaves *before* first checkpoint | Mirrors/federation + external anchoring (F6+, §11) |

**Sybil economics, one paragraph.** An attacker's cost per *effective* fake persona is the product of the layers it wants to clear: L0 ≈ 0; +L1 ≈ one endpoint; +L2 ≈ one domain + minutes (and a durable trace); +L3 ≈ time and the difficulty of getting *your* vouchers trusted by *the consumer's* trust set; +L4 ≈ sustained behaviour because counters decay and require liveness; +L5 ≈ nothing extra — it just makes the whole operation public. The directory's job is to make the *marginal cost of the next fake persona rise monotonically with the credibility the attacker wants*, and to make every fake persona leave a permanent, correlatable trail. It never declares victory: the residual risks are named in §8 and the mitigations that remain open are in §11.

### 3.9 Layer cheat-sheet (implementers' quick table)

| Layer | New? | Protocol anchor | Gate for listing? | Verdict by | Fraud cost | Main bypass |
|---|---|---|---|---|---|---|
| L0 Ed25519 identity | existing | §3.1, manifest signature, fingerprint recompute | yes (key valid) | consumer | ~0 | mint keys |
| L1 proof-of-endpoint | existing | §3.2 `/v1/register` + `/v1/register/complete` | yes (PoE passed) | consumer | endpoint | rent endpoints |
| L2 domain verification | **new** | §3.3 `/v1/verify-domain[/confirm]`, DNS TXT `_haap.<domain>` or `/.well-known/haap-verify` | no (bonus signal) | consumer | ~US$10+domain+time | buy domains, typosquat |
| L3 vouching | **new** | §3.4 `/v1/vouches`, `/v1/trust/paths` | no | consumer (+ its trust set) | liveness+reputation | collusion rings (visible) |
| L4 behavioural reputation | **new** | §3.5 `/v1/reports`, automata, decay | no (suspension hides) | consumer; moderators for takedown | sustained army | griefing (bounded, reversible) |
| L5 transparency audit | **new** | §3.6 `/v1/audit/*` hash chain + checkpoints | n/a | verifier/consumer | cannot (tamper-evident) | operator rewrite pre-checkpoint |

---

## 4. API specification v1

### 4.0 General

- Base path: `/v1` for canonical endpoints. **Legacy aliases** (§4.9) exist for wire compatibility and MUST behave identically in semantics.
- All request/response bodies JSON; unknown fields in requests are rejected (`INVALID_SCHEMA`) when they collide with protected fields, otherwise ignored-and-audited (forward compatibility).
- `Content-Type: application/json` required on POST/DELETE bodies.
- Response headers: `X-Request-Id`, rate-limit headers (§2.7), optional `X-HAAP-Directory-Signature` + `X-HAAP-Directory-Fingerprint` on audit and (configurable) search responses.
- Dates: RFC 3339 UTC. Durations: seconds where integer, RFC 3339/ISO-8601 where noted.
- All agents endpoints require body signatures per endpoint; there is no session auth — **the key is the credential**.
- Search/profile endpoints are public (rate-limited per IP); mutating endpoints are additionally rate-limited per fingerprint and per IP.

### 4.1 POST /v1/register — begin registration (proof-of-endpoint, step 1)

Request:
```json
{
  "manifest": { …extended manifest, §5.1… },
  "public_key_b64": "MCowBQYDK2VwAyEA…",
  "manifest_signature": "<b64 Ed25519 over canonical JSON of manifest>"
}
```
Response `202 Accepted`:
```json
{
  "challenge_id": "ch_01J2…",
  "nonce": "v1:register:9f86d081884c7d65…",
  "registry_fingerprint": "HF-<directory fingerprint>",
  "expires_at": "2026-09-04T12:02:00Z",
  "algorithm": "ed25519",
  "ttl_seconds": 120
}
```
Failure examples: `INVALID_JSON`, `INVALID_SCHEMA`, `FORBIDDEN_FIELD` (manifest contains `private_key`/`signature`/`nonce`), `FLOAT_FORBIDDEN`, `SIGNATURE_MISMATCH`, `FINGERPRINT_MISMATCH`, `ENDPOINT_INVALID`, `MANIFEST_TOO_LARGE`, `RATE_LIMITED`, `DIRECTORY_FULL`.

### 4.2 POST /v1/register/complete — prove endpoint control (step 2)

Request:
```json
{
  "challenge_id": "ch_01J2…",
  "fingerprint": "HF-3f7a9c1b2d4e5f60",
  "endpoint_proof": "<b64 Ed25519 over the nonce bytes from step 1>"
}
```
Response `201 Created`:
```json
{
  "status": "registered",
  "agent_url": "/v1/agents/HF-3f7a9c1b2d4e5f60",
  "expires_at": "2026-09-05T12:00:00Z",
  "directory_fingerprint": "HF-<directory fingerprint>",
  "ttl_seconds": 86400
}
```
Failure examples: `CHALLENGE_NOT_FOUND`, `CHALLENGE_EXPIRED`, `CHALLENGE_USED`, `KEY_MISMATCH`, `PROOF_INVALID`, `FINGERPRINT_MISMATCH`. On success the entry is live; audit `register.completed`.

### 4.3 L2 endpoints — domain verification

**POST /v1/verify-domain** — request a challenge for one domain/method.

```json
// request (signed by agent key over canonical body)
{ "fingerprint": "HF-…", "domain": "euraka.example.com", "method": "dns_txt" }
// 202
{
  "verification_id": "vd_01J2…",
  "domain": "euraka.example.com",
  "method": "dns_txt",
  "token": "9f86d081884c7d659a2feaa0c55ad015…",
  "instructions": "Publish TXT record at _haap.euraka.example.com with value haap-verify=9f86d081884c7d659a2feaa0c55ad015… (TTL <= 300 recommended)",
  "expires_at": "2026-09-04T12:30:00Z",
  "ttl_seconds": 1800
}
```
Errors: `INVALID_JSON`, `INVALID_SCHEMA`, `DOMAIN_INVALID`, `SIGNATURE_MISMATCH`, `AGENT_NOT_LISTED`, `RATE_LIMITED`, `VERIFICATION_LIMIT_REACHED` (max 5 pending per agent).

**POST /v1/verify-domain/confirm** — ask the directory to check (server-side).

```json
// request (signed): { "fingerprint": "HF-…", "verification_id": "vd_01J2…" }
// 200
{
  "status": "verified",
  "domain": "euraka.example.com",
  "method": "dns_txt",
  "verified_at": "2026-09-04T12:07:00Z",
  "expires_at": "2026-12-03T12:07:00Z",   // verified_at + 90 days
  "endpoint_match": true
}
```
Failure: `VERIFICATION_NOT_FOUND`, `VERIFICATION_EXPIRED`, `VERIFICATION_USED`, `DNS_TXT_NOT_FOUND`, `WELL_KNOWN_NOT_FOUND`, `WELL_KNOWN_MISMATCH` (token absent/wrong), `DOMAIN_ENDPOINT_MISMATCH`, `DNS_ERROR_TEMPORARY`. Retry policy: DNS propagation → confirm MAY be retried until token TTL expires (`VERIFICATION_EXPIRED` after 30 min; a new `POST /v1/verify-domain` mints a fresh token).

**GET /v1/verify-domain/status?fingerprint=HF-…** — current verification states for an agent (public, no signature needed): `[{domain, method, verified_at, expires_at, primary}]`, `200`.

### 4.4 L3 endpoints — vouches

- `POST /v1/vouches` (§3.4.1) → `201 {vouch_id, status:"active", voucher, vouchee, scope, expires_at}`.
- `DELETE /v1/vouches/{vouch_id}` body `{voucher_fingerprint, revoked_at, signature}` → `200 {status:"revoked"}`.
- `GET /v1/agents/{fingerprint}/vouches` → `200 {"fingerprint": "HF-…", "vouches_in": [ …active inbound… ], "annotations": {"mutual_vouch_density": 0.12, "registration_cluster": false}}`.
- `GET /v1/agents/{fingerprint}/vouches/outgoing` → active + revoked outgoing edges.
- `GET /v1/trust/paths?from=HF-A&to=HF-B&max_depth=2` → `200 {"paths": [ [ {voucher_fingerprint, vouchee_fingerprint, scope, created_at, expires_at, revoked_at} ] ]}`; `max_depth` clamped to 2; no paths → `{"paths": []}`.
- Errors: `VOUCHER_NOT_LISTED`, `VOUCHEE_NOT_LISTED`, `VOUCH_INVALID`, `VOUCH_EXISTS`, `VOUCH_NOT_FOUND`, `VOUCH_LIMIT_REACHED`, `SIGNATURE_MISMATCH`, `VOUCH_EXPIRED` (cannot create with past `expires_at`).

### 4.5 L4 endpoints — reports, flags, moderation

- `POST /v1/reports` (§3.5.1) → `202 {report_id, status:"recorded", counts_toward_automation:true|false}`.
- `GET /v1/agents/{fingerprint}/reports` → counters + recent report metadata (never full evidence bodies to anonymous callers; evidence requires moderator key or reporter key).
- `POST /v1/reports/{report_id}/takedown` — moderator key signature required: body `{moderator_fingerprint, reason, signature}` → `200 {status:"suspended", agent: …}`; errors `REPORT_NOT_FOUND`, `TAKEDOWN_UNAUTHORIZED`, `MODERATOR_UNKNOWN`.
- `POST /v1/agents/{fingerprint}/appeal` — signed by the agent: `{fingerprint, statement, signature}` → `202 {appeal_id}`; moderator reviews; outcome audited (`appeal.granted`/`appeal.denied`).
- `POST /v1/agents/{fingerprint}/suspend` (direct moderator suspend, no report), `POST /v1/agents/{fingerprint}/unsuspend` — moderator signed.
- Errors: `REPORT_INVALID`, `REPORT_EXISTS`, `REPORT_LIMIT_REACHED`, `REPORTER_NOT_ELIGIBLE` (tenure/liveness), `TARGET_NOT_LISTED`, `SIGNATURE_MISMATCH`, `RATE_LIMITED`.

### 4.6 Search and profile (public)

```
GET /v1/search?capability=citas&geo=42.85,-2.67,25&q=peluqueria&limit=20&offset=0
```
- `capability`: case-insensitive substring over `speciality`, `services[].id`, `services[].category`, `tools[]`, `skills[].name`.
- `q`: case-insensitive free text over the full manifest; multiple whitespace-separated words = AND.
- `geo=lat,lon,radius_km`: haversine over `agent.geo`; agents without geo are excluded when geo filter present.
- `limit` default 20, max 100 (clamp, don't error); `offset` paginates; `total` counts matches ignoring pagination.
- Trust-aware filters (all optional, consumer-chosen): `min_age_hours=72`, `domain_verified=true`, `not_suspended=true` (default), `min_vouches_in=1` (counts *visible edges*, not quality — labelled as such in docs), `recent_reports_max=0`.

Response `200`:
```json
{
  "results": [
    {
      "manifest": { …full extended manifest… },
      "trust": { …§5.2 trust block… }
    }
  ],
  "total": 3,
  "limit": 20,
  "offset": 0,
  "directory_fingerprint": "HF-…"
}
```
`GET /v1/agents/{fingerprint}` → `200 {"manifest": …, "trust": …}` or `404 AGENT_NOT_FOUND` (unknown), `404 AGENT_SUSPENDED`-style body with status (entry exists but hidden: HTTP 404 with `{"error":{"code":"AGENT_NOT_LISTED","message":"not currently listed","request_id":…}}` to avoid confirming suspended entries to anonymous callers — moderators and the owner's key get full state).

### 4.7 Heartbeat

```
POST /v1/heartbeat
{ "fingerprint": "HF-…", "timestamp": "2026-09-04T12:00:00Z",
  "signature": "<b64 Ed25519 over ASCII \"heartbeat:HF-…:2026-09-04T12:00:00Z\">" }
→ 200 {"status":"ok","expires_at":"2026-09-05T12:00:00Z","ttl_seconds":86400}
→ 404 {"error":{"code":"UNKNOWN_OR_EXPIRED", …}}   // never confirms fingerprint existence
```
`timestamp` must be within ±300 s (`STALE_TIMESTAMP`). Legacy form `POST /heartbeat {"fingerprint": "HF-…"}` (unsigned, per registry_client) is accepted on the legacy alias (§4.9) with an audit note `heartbeat.legacy_unsigned`.

### 4.8 Audit endpoints (L5)

- `GET /v1/audit/head` → `200 {"seq": 4817, "entry_hash": "…", "ts": "…", "checkpoint_signature": "<b64 dir-key sig over canonical {seq,entry_hash,ts}>"}`.
- `GET /v1/audit/log?after=4700&limit=100` → `200 {"entries":[…], "next_after": 4800, "head": {"seq":4817,"entry_hash":"…"}}` — contiguous, ascending; `limit` ≤ 1000.
- `GET /v1/audit/checkpoints` → list of signed `{seq, entry_hash, ts, signature}`.
- `GET /v1/audit/verify?seq=4817` → directory-side recompute: `200 {"valid": true, "computed_head": "…"}` (convenience; clients SHOULD verify locally from raw entries).
- All audit responses carry `X-HAAP-Directory-Signature` (default on).
- `GET /v1/agents/{fingerprint}/audit` → entries whose `fingerprint` matches (public, redacted detail: detail objects are never included, only `detail_hash` + event/result — producers can reveal their own details off-band).

### 4.9 Legacy compatibility aliases (hard requirement)

The unmodified `haap/registry_client.py` (and the unmodified haap test suite) must keep working. Legacy routes are thin aliases with identical semantics; the authoritative route table is the haap repo's `tests/test_registry_client.py`, which MUST pass unchanged in every phase from F1 on. Known legacy surface (from the verified reference implementation):

| Legacy route | Maps to | Behavioural note |
|---|---|---|
| `POST /register` | `POST /v1/register` | Same body/validation; challenge response identical shape. |
| `POST /register/complete` | `POST /v1/register/complete` | Same binding/single-use rules. |
| `POST /heartbeat` | `POST /v1/heartbeat` | Accepts legacy `{fingerprint}` body (audit-flagged) and v1 signed body. |
| client `search()` route | `GET /v1/search` semantics | Exact path as the client uses it (see repo tests); response `results` array of manifests. |
| `GET /health` | `/health` (§9.2) | Same JSON contract as the reference. |

Versioned canonical endpoints are `/v1/*`; legacy aliases return the same bodies (plus `directory_fingerprint` where the reference did not) — additive fields only, never removed. Early working notes referenced a `/v1/register/challenge` name; the canonical v1 second step is **`/v1/register/complete`** (mirrors legacy semantics); servers MAY additionally accept `/v1/register/challenge` as an alias of the same handler for tolerance, and MUST document which they accept in `/health` (`api.completion_route`).

### 4.10 Stable error codes (master table)

Format: `{"error": {"code": "UPPER_SNAKE", "message": "short", "request_id": "…"}}`. HTTP status mapping is fixed; codes are stable API — never rename, never remove; add only.

| Code | HTTP | Meaning |
|---|---|---|
| `INVALID_JSON` | 400 | Body not parseable JSON |
| `INVALID_SCHEMA` | 400 | JSON valid but shape/type/enum wrong |
| `FORBIDDEN_FIELD` | 400 | Manifest/body contains `private_key`/`signature`/`nonce` (or float in signed data) |
| `FLOAT_FORBIDDEN` | 400 | Float value inside a signed object |
| `SIGNATURE_MISMATCH` | 400 | Ed25519 verification failed |
| `FINGERPRINT_MISMATCH` | 400 | fingerprint ≠ sha256(pubkey)[:16] |
| `ENDPOINT_INVALID` | 400 | endpoint not http(s), or has query/fragment |
| `DOMAIN_INVALID` | 400 | domain fails syntax rules |
| `MANIFEST_TOO_LARGE` | 413 | manifest > 256 KiB |
| `PAYLOAD_TOO_LARGE` | 413 | any body > cap |
| `CHALLENGE_NOT_FOUND` | 404 | unknown challenge_id |
| `CHALLENGE_EXPIRED` | 410 | challenge past TTL |
| `CHALLENGE_USED` | 409 | challenge already consumed |
| `KEY_MISMATCH` | 400 | pubkey differs between register and complete |
| `PROOF_INVALID` | 400 | endpoint_proof not by the bound key |
| `STALE_TIMESTAMP` | 400 | heartbeat timestamp > ±300 s |
| `UNKNOWN_OR_EXPIRED` | 404 | heartbeat target unknown/expired (never confirms existence) |
| `AGENT_NOT_FOUND` | 404 | no such fingerprint ever registered |
| `AGENT_NOT_LISTED` | 404 | exists but not currently listed/suspended |
| `DIRECTORY_FULL` | 503 | agent cap reached |
| `RATE_LIMITED` | 429 | token bucket empty (+ `Retry-After`) |
| `VOUCHER_NOT_LISTED` / `VOUCHEE_NOT_LISTED` | 400/404 | vouch party not live |
| `VOUCH_INVALID` | 400 | scope/expiry/weight malformed |
| `VOUCH_EXISTS` | 409 | identical active vouch (same V, B, scope) |
| `VOUCH_NOT_FOUND` | 404 | unknown/revoked vouch_id |
| `VOUCH_LIMIT_REACHED` | 429 | > 10 outgoing active vouches |
| `REPORT_INVALID` | 400 | category/evidence/severity malformed |
| `REPORT_EXISTS` | 409 | duplicate reporter+target+category window |
| `REPORT_LIMIT_REACHED` | 429 | per-reporter report throttle |
| `REPORTER_NOT_ELIGIBLE` | 403 | reporter lacks 72 h tenure/liveness (counts=false) |
| `TARGET_NOT_LISTED` | 404 | reporting a non-listed agent (use moderator channel) |
| `VERIFICATION_NOT_FOUND` | 404 | unknown verification_id |
| `VERIFICATION_EXPIRED` | 410 | token TTL (30 min) passed |
| `VERIFICATION_USED` | 409 | already confirmed |
| `VERIFICATION_LIMIT_REACHED` | 429 | > 5 pending verifications |
| `DNS_TXT_NOT_FOUND` | 422 | no matching TXT at `_haap.<domain>` |
| `WELL_KNOWN_NOT_FOUND` | 422 | `/.well-known/haap-verify.txt|json` not fetchable |
| `WELL_KNOWN_MISMATCH` | 422 | token absent from body |
| `DOMAIN_ENDPOINT_MISMATCH` | 422 | endpoint host ∉ domain or subdomains |
| `DNS_ERROR_TEMPORARY` | 503 | resolver failure (retryable) |
| `TAKEDOWN_UNAUTHORIZED` | 403 | not a moderator key |
| `MODERATOR_UNKNOWN` | 403 | moderator key not in config |
| `METHOD_NOT_ALLOWED` | 405 | wrong verb |
| `UNSUPPORTED_VERSION` | 400 | unknown protocol_version |
| `INTERNAL_ERROR` | 500 | bug; details only in server logs |
| `UNAVAILABLE` | 503 | draining/overloaded |

429 responses MUST include `Retry-After`; SHOULD include `X-RateLimit-*` headers. All rejections are audited with reason code (no secrets in audit detail — only hashes of bodies).
## 5. Data & schema

### 5.1 Extended agent manifest (v1, wire + storage canonical)

This is the object an agent registers (and the directory stores/returns in search). It is the **same shape** shipped by the verified `capabilities.public_manifest()` plus the extended fields below. Everything an agent offers for discovery lives here, so versioning is critical: `format: "haap-public-manifest-v1"`; adding a field is backward-compatible, removing/renaming one is a format bump.

```json
{
  "format": "haap-public-manifest-v1",
  "protocol_version": "1.0",
  "haap_version": "1.0.0",
  "generated_at": "2026-09-04T12:00:00Z",
  "agent": {
    "fingerprint": "HF-3f7a9c1b2d4e5f60",
    "name": "Peluqueria Euraka",
    "speciality": "citas-peluqueria",
    "description": "Peluquería unisex en Vitoria-Gasteiz. Reservas automáticas 24/7 (CalDAV).",
    "endpoint": "https://euraka.example.com:8443/haap/messages",
    "owner_contact": "mailto:citas@euraka.example.com",
    "languages": ["es", "eu"],
    "geo": { "city": "Vitoria-Gasteiz", "country": "ES",
             "lat": 42.8467, "lon": -2.6716, "radius_km": 15 },
    "availability": { "timezone": "Europe/Madrid",
                      "hours": [ { "days": [1,2,3,4,5], "open": "10:00", "close": "19:00" } ] },
    "trust_claims": { "domain": "euraka.example.com" }
  },
  "services": [
    { "id": "corte", "category": "hairdresser", "name": "Corte de pelo",
      "price": "15.00", "currency": "EUR", "duration_min": 30,
      "booking": { "mode": "instant", "scopes": ["booking:search", "booking:reserve"] } },
    { "id": "corte-barba", "category": "hairdresser", "name": "Corte + barba",
      "price": "22.00", "currency": "EUR", "duration_min": 45,
      "booking": { "mode": "instant", "scopes": ["booking:reserve"] } }
  ],
  "message_types": ["hello", "task_request", "service_search", "service_book"],
  "roles_accepted": ["guest", "client"],
  "permission_scopes_offered": ["booking:search", "booking:reserve"],
  "capabilities_flags": { "streaming": false, "push": true, "async_tasks": true },
  "skills": [ { "name": "caldav-booking", "description": "Mantiene y reserva en calendario CalDAV." } ],
  "tools": ["caldav"]
}
```

**Normative field rules (validate at registration; failures → stable codes §4.10):**

- `agent.fingerprint` = `^HF-[0-9a-f]{16}$` and MUST equal `fingerprint_of_public_key(public_key)` (`FINGERPRINT_MISMATCH`).
- `agent.endpoint`: `http(s)://host[:port][/path]`, no query, no fragment, no credentials in URL (`ENDPOINT_INVALID`). Size cap 256 KiB total manifest (`MANIFEST_TOO_LARGE`).
- `services[].price`: **string numeric** (e.g. `"15.00"`) or integer — never a float. `price_eur` from the original brief is aliased `price`+`currency:EUR` for v1 to allow multi-currency later; **accept both** (`price` xor `price_eur`) for compatibility; floats anywhere in a signed object → `FLOAT_FORBIDDEN`.
- `roles_accepted` ⊆ {guest, client, partner, family, admin}. `permission_scopes_offered` and `services[].booking.scopes`: free-form lowercase `scope` strings, dot-separated (`resource:action`).
- `geo.lat`/`lon`: floats are fine **here** because latitude/longitude are *never re-signable trust data* — they are not part of the signed canonical object the directory re-validates word-for-word for signatures... **wait, they ARE in the signed manifest.** Correction (normative): because the whole manifest is signed and canonical-JSON-serialized, **floats are forbidden anywhere in the manifest** — including `geo.lat/lon`. Express geo as integer micro-degrees: `geo: { lat_microdeg: 42846700, lon_microdeg: -2671600, radius_km: 15 }`. Keep the pretty `lat/lon` on the *server response* side only (directory may render floats for display); the signed stored form is integer micro-degrees. Same rule bites `duration_min` (int, ok), `price` (string). This is the single most common v1 schema bug — enforce it.

### 5.2 Trust block (per-listing, in every search/profile — the §3.7 signals)

```json
"trust": {
  "directory_fingerprint": "HF-…",
  "listed_since": "2026-08-01T09:00:00Z", "age_days": 34.9,
  "last_heartbeat": "2026-09-04T12:00:00Z", "fresh": true,
  "endpoint_proof_at": "2026-09-04T12:00:00Z",
  "domain_verified": true,
  "domain_verification": { "domain": "euraka.example.com", "method": "dns_txt",
                           "verified_at": "2026-09-04T12:07:00Z",
                           "expires_at": "2026-12-03T12:07:00Z", "primary": true },
  "vouches_in": [ { "voucher_fingerprint": "HF-9d8e…", "scope": "service:hairdresser:booking",
                    "created_at": "…", "expires_at": "…", "revoked_at": null,
                    "voucher_tenure_hours": 900 } ],
  "vouch_annotations": { "mutual_vouch_density": 0.12,
                         "vouchers_share_registration_cluster": false },
  "reports": { "by_category": { "fraud": 0, "spam": 1 },
               "unique_reporters": 1, "first_at": "2026-09-02T…", "last_at": "2026-09-02T…" },
  "status": "listed",                    // listed | suspended | expired
  "suspension": null,                    // {rule, evidence_reports, at} when suspended
  "block_recommendation": null,          // §3.5.2.5
  "reputation_history": [],              // past suspensions, report_wars, vouch revocations (decayed)
  "audit_verifiable": true
}
```

### 5.3 SQLite schema (v1 — directory's own store)

> Field names TBD-by-federation: none of these are wire contracts beyond the *row meaning*; SQL is private to the implementation. Only the §4 HTTP bodies and §5.1/§5.2 JSON are wire-contract. Keep schema migration-friendly (each table gets a `schema_version` pragma or a central `meta` table).

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE meta (
  key TEXT PRIMARY KEY,               -- schema_version, chain_head_seq, created_at, genesis_hash…
  value TEXT NOT NULL
);

CREATE TABLE agents (                  -- live + historical listing rows (expired kept as history flag)
  fingerprint TEXT PRIMARY KEY,        -- HF-…
  public_key_b64 TEXT NOT NULL,
  manifest_json TEXT NOT NULL,         -- §5.1
  registered_at TEXT NOT NULL,
  last_heartbeat TEXT,
  expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'listed',          -- listed | suspended | expired
  suspension JSON,                               -- {rule, evidence_reports, at}
  suspended_at TEXT,
  is_history INTEGER NOT NULL DEFAULT 0           -- soft row for historical/queries; 1 = not listed
);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_speciality ON agents(json_extract(manifest_json,'$.agent.speciality'));
CREATE INDEX idx_agents_geo ON agents(json_extract(manifest_json,'$.agent.geo.lat_microdeg'),
                                      json_extract(manifest_json,'$.agent.geo.lon_microdeg'));

CREATE TABLE challenges (              -- L1 PoE & L2 domain tokens (single-use)
  challenge_id TEXT PRIMARY KEY,       -- ch_…
  kind TEXT NOT NULL,                  -- 'endpoint' | 'domain'
  fingerprint TEXT NOT NULL,
  public_key_b64 TEXT,
  domain TEXT,
  method TEXT,
  token TEXT NOT NULL,
  endpoint TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_challenges_fp ON challenges(fingerprint);
CREATE INDEX idx_challenges_exp ON challenges(expires_at);

CREATE TABLE domain_verifications (
  id TEXT PRIMARY KEY,                 -- vd_…
  fingerprint TEXT NOT NULL,
  domain TEXT NOT NULL,
  method TEXT NOT NULL,                -- dns_txt | https_well_known
  verified_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  endpoint_match INTEGER NOT NULL DEFAULT 0,
  challenge_id TEXT
);
CREATE INDEX idx_dv_fp ON domain_verifications(fingerprint);
CREATE INDEX idx_dv_domain ON domain_verifications(domain);

CREATE TABLE vouches (
  vouch_id TEXT PRIMARY KEY,           -- vc_…
  voucher_fingerprint TEXT NOT NULL,
  vouchee_fingerprint TEXT NOT NULL,
  scope TEXT NOT NULL,
  note_hash TEXT,                      -- sha256(canonical note) --- note itself may be public; store plaintext too if fine
  weight INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  signature_b64 TEXT NOT NULL
);
CREATE INDEX idx_vouches_voucher ON vouches(voucher_fingerprint);
CREATE INDEX idx_vouches_vouchee ON vouches(vouchee_fingerprint);
CREATE INDEX idx_vouches_active ON vouches(vouchee_fingerprint) WHERE revoked_at IS NULL AND expires_at > now;  -- (partial index)

CREATE TABLE reports (
  report_id TEXT PRIMARY KEY,          -- rp_…
  reporter_fingerprint TEXT,
  target_fingerprint TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  evidence_kind TEXT NOT NULL,
  evidence_hash TEXT,                  -- never the body
  description_hash TEXT,
  occurred_at TEXT,
  submitted_at TEXT NOT NULL,
  counts INTEGER NOT NULL DEFAULT 0,   -- eligibility gate
  status TEXT NOT NULL DEFAULT 'recorded'   -- recorded | under_review | acted
);
CREATE INDEX idx_reports_target ON reports(target_fingerprint);
CREATE INDEX idx_reports_reporter ON reports(reporter_fingerprint);

CREATE TABLE audit_log (               -- L5 append-only hash chain state
  seq INTEGER PRIMARY KEY,             -- == entry[n].seq
  ts TEXT NOT NULL,
  event TEXT NOT NULL,
  fingerprint TEXT,
  actor TEXT NOT NULL,
  result TEXT NOT NULL,
  detail_hash TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL             -- stored for cheap head compare
);
CREATE INDEX idx_audit_fp ON audit_log(fingerprint);

CREATE TABLE rate_limit_ips (token TEXT PRIMARY KEY, remaining INTEGER, reset_at TEXT);
CREATE TABLE challenges_evicted_log (…)  -- for cap auditing (§9.5)
```

The **audit log is written in the same transaction as the state change it records** (§3.6.1). Do not model it as an after-the-fact hook — the write pipeline is: validate → open tx → mutate state table → append audit entry (compute `prev_hash` from head read under the same tx/write lock) → commit. Serialize writers with a single write queue (SQLite is single-writer; a `threading.Lock` around writes, or use `BEGIN IMMEDIATE`).

### 5.4 Migration policy

Schema migrations are **additive** in v1 (new tables/indexes only; never drop/rename a wire field). Use the `meta.schema_version` and run ordered migration functions at startup (idempotent). Index `expires_at`, `status`, `seq` hot columns (point queries every request). Provide `meta` row `chain_head_seq` for quick checkpoint checks.

## 6. Stack, repo layout & compatibility

### 6.1 Recommendation: stdlib-first, "clean" is not a goal until it is

The existing reference is **stdlib `http.server`** in `haap/registry.py`, and the brief (§9 of `DIRECTORY_SERVICE_BRIEF.md`) said "Python stdlib first (http.server), third party only if unavoidable". Two surveys (transcript, pre-CJK pruning) of production-grade fraud/registry services say: the *feature* complexity of this directory (L0-L5 + persistence + rate-limiting + audit chains + concurrency) is modest, but the *operational* complexity is where a framework pays. The honest recommendation:

- **Recommended default: FastAPI + uvicorn + Pydantic v2 + `sqlite3` (stdlib) for v1, with a documented Postgres migration path.** Rationale, stated plainly: FastAPI gives typed request validation (defeats a whole class of `INVALID_SCHEMA`/`FLOAT_FORBIDDEN`/oversized-body bugs the spec cares about), OpenAPI for free (consumers can read the contract), and async under uvicorn with a serialized SQLite writer is trivial and correct. stdlib `http.server` is viable for a toy (like the reference) but hand-rolling JSON+schema+rate-limit+audit-middleware to production grade is *more* code than adding FastAPI — the honest argument against "stdlib purity" here is that the spec already demands framework-grade hardening (size caps, error-codes table, TLS handling, threading, health/metrics). FastAPI is pure-Python, testable, and the team's existing haap modules (`crypto.py`, etc.) are plain functions usable unchanged.
- **Persistence: SQLite for v1 (single writer, file backup trivial, WAL), Postgres from ~1e5 entries or multi-instance.** One directory instance owns SQLite; federated reads come from mirrors, not from sharing the SQLite file. Postgres becomes right when you need true read-replicas or multi-region (F6+). Use the SQLAlchemy-core/Alembic only if you commit to Postgres; for SQLite-start a thin `sqlite3` adapter with migration functions (§5.4) is enough.
- **deploy**: Docker single container (uvicorn in, SQLite volume out) or bare systemd/VPS. doc: `docs/OPERATE.md`.

### 6.2 Repo layout — repo `haap-directory` (independent)

```
haap-directory/
├── README.md
├── pyproject.toml
├── LICENSE
├── src/haap_directory/
│   ├── __init__.py            # __version__
│   ├── config.py              # dataclass + ~/.haap/dird.json + env + CLI
│   ├── crypto.py              # thin re-export/adapt wrappers (may import haap if installed, but standalone preferred: no dependency on the client pkg)
│   ├── models.py              # manifest + trust Pydantic models, geo micro-degrees
│   ├── store.py               # SQLite adapter (transactions, migrations, writers serialized)
│   ├── verify.py              # PoE (L1) + domain check (L2: DNS TXT + HTTPS well-known)
│   ├── services/              # business logic top-level (no HTTP)
│   │   ├── registration.py    # L1 state machine + upsert + audit
│   │   ├── domain.py          # L2
│   │   ├── vouching.py        # L3
│   │   ├── reputation.py      # L4 automata + decay + auto-suspend
│   │   ├── search.py          # §4.6 (substring, q AND, geo haversine, sort, limit/offset, trust filters)
│   │   └── audit.py           # L5 chain append + checkpoint signing
│   ├── rate_limit.py          # per-IP token buckets + per-fingerprint caps + Retry-After
│   ├── moderation.py          # moderator-key ops (suspend/unsuspend/appeal) + config
│   ├── http_api.py            # FastAPI app; routes §4; legacy aliases §4.9
│   ├── middleware.py          # request_id, size caps, rate-limit headers, telemetry
│   └── telemetry.py           # /health, /metrics (plain-text Prometheus-ish)
├── haap_dird.py               # entry point -> uvicorn.run(app) -> CLI (argparse)
├── tests/
│   └── …                       # test files per phase (F0–F6)
└── docs/
    ├── SPEC.md                 # this file
    ├── OPERATE.md              # backup/restore/monitor (§9)
    └── MODERATION.md           # moderator runbook + policy (append-only note; human decision)
```

### 6.3 Compatibility contract — what stays in `haap/` (client), what lives here

| Concern | Lives in `haap/` (client) | Lives here (haap-directory) |
|---|---|---|
| Identity, keypair, fingerprint | ✅ `identity.py`, `crypto.py` | re-used/adapted only, never duplicated as source of truth |
| Envelope sign/verify, canonical JSON | ✅ `envelope.py` | implicit in `canonical_json()` util (test-parity) |
| Proof-of-endpoint *client* flow | ✅ `registry_client.register()` | server side (§4.1/§4.2) |
| Heartbeat loop | ✅ `registry_client.heartbeat_loop` | server heartbeat endpoint (§4.7) |
| Manifest *generation* (public_manifest) | ✅ `capabilities.public_manifest` | consumes it as input (§5.1) |
| Search *client* helper | ✅ `registry_client.search` | search endpoint (§4.6) |
| **Directory service itself** | **NOT here** | This repo |

**Contract: the haap client + its full unmodified test suite MUST keep working against this directory unmodified (legacy aliases §4.9).** Do not add a hard import dependency from haap-directory → inside the client beyond pure re-implementable primitives (canonical JSON). Keep a `/haap-directory/setup.py editable` dev install that imports from local `crypto.py` — actually safest: vendor a tiny `canonical_json()` here and in haap (both tested identical), avoiding cross-package import fragility. State this in OPERATE.md.

### 6.4 Multitenancy & federation (level-2 non-goal; design seams only)

v1 is **single-directory**. But design so it doesn't paint into a corner: the §3 L5 chain + §4.9 directory_fingerprint on responses + mirror/ingest (§7 F6) means another instance can ingest and re-serve a chain with an identical head — federation without a central registry-of-directories. Each directory is authoritative for its own index; a consumer may query several and take intersections/unions it wants. Multi-directory trust is **consumer-side** (§3.7 M12). Good operators can publish their directory public key + endpoint in a `.well-known` so mirrors can verify; do NOT build a directory-of-directories in v1 (§11 open question).

## 7. Phased implementation plan (with acceptance criteria)

Each phase merges to `main` with green full-suite `pytest`; the **haap legacy suite MUST still pass unchanged in every phase from F1** (the unmodified client's tests against this running service).

| Phase | Scope | Runnable acceptance criteria |
|---|---|---|
| **F0** | Repo skeleton + persistent SQLite store + CLI `haap-dird` + `/health` + config | `haap-dird --db tmp.db --port 0` boots; `/health` returns `{status,agents:0,version}`; restart against same db keeps an inserted test row no-secrets; config precedence CLI > file > default |
| **F1** | L1 proof-of-endpoint registration under SQLite (§4.1/§4.2), persistence, upsert/expiry | 41-item client+directory test suite still green (haap unmodified client + new dird F1 tests); registration persists across restart; duplicate-fp updates not duplicates; expired → fresh insert; challenge single-use/expired/bound-key rejection tests all pass with stable codes |
| **F2** | Search (§4.6) + heartbeat (§4.7) + expiry prune | search capability/q/geo/offset-limit tests; heartbeat renews TTL; injected-clock expiry is pruned both on-read and startup; legacy `registry_client.search` + heartbeat tests pass unchanged |
| **F3** | L2 domain verification (§4.3) server-side DNS TXT + HTTPS well-known, chain link | verify-domain against a controlled TXT (test DNS stub) returns verified with correct token lifecycle (single-use, TTL, endpoint-match); well-known variant; `domain_verified` reflected in trust block and search filters; 90-day expiry downgrade with injected clock; hard audit rows; DNS error stable codes |
| **F4** | L3 vouching (§4.4) + L4 reports/auto-suspend (§4.5) | vouch create/revoke/read graph/paths depth-2 tests; cap 10-outgoing; both-parties-listed + tenure rules; reports submitted/eligibility-gate/evidence-kind; auto-suspend automaton (3 unique eligible in 7d, abuse classes only) with injected clock; appeal + moderator takedown flows; decay-over-180d weight-0 test; full audit visibility of each event |
| **F5** | L5 audit chain end-to-end (§3.6) — genesis, per-event append in same tx, checkpoints, download & verify | gen genesis; every mutating operation appends (assert audit rows == ops); hash-chain link recomputable; checkpoint signed hourly (clock stub); `/v1/audit/log` contiguous + `X-HAAP-Directory-Signature`; an external re-hash of downloaded entries matches head — i.e., tamper with one entry → verify fails |
| **F6** | Multitenancy seams, mirror ingest, Docker deploy, OpenAPI polish, OPERATE.md final | `docker build` runs `haap-dird` and passes smoke registration against port; a mirror process ingests the chain and reproduces identical head; rate-limit flood tests at full scale; docs OPERATE/MODERATION stable; full suite + legacy tests green |

**Cross-phase rules:** every added endpoint appears in §4 tables kept in sync; every new error code MUST be added to §4.10 table in the same PR/commit (add-only); every event type MUST be added to the §3.6.1 event taxonomy in the same commit; no float ever enters a signed body — write a test that asserts the regex/manifest has no `true` float price coercion.

## 8. Directory-specific threat model (consume alongside `haap/docs/ARQUITECTURA.md` T1–T10)

Referenced from §3/§4 as T-D##.

| # | Attack | What it does | Layer(s) | Mitigation (spec-native) | Residual |
|---|---|---|---|---|---|
| T-D01 | **Sybil flood** — bulk register fake agents | Fills index, buries real ones, poisons search | L0/L1 | L1 costs an endpoint per identity; L2 costs a domain per identity for L2-badge | Unfunded flood dies L1/L2; funded flood needs L4 sink + consumer age/geo filters |
| T-D02 | **Endpoint poisoning** — register real-looking endpoints pointing at honeypots | Consumer messages a honeypot | L1 | PoE only proves *control*, not reachability-from-consumer (a fraudster's own server answers too); consumer MUST probe + use L4/TOFU workflow (§3.4.7) | Honeypot control is real control of that server; L4 reports + revocation bind the harm |
| T-D03 | **Agent SEO/spam** — keyword-stuffed manifests to rank in `capability`/`q` | Degrades search precision | L1/L4 | schema caps + `services[].id`-match (not free-text whole-manifest for ranking? — **decide**: `capability` substring over the *structured* speciality/category/tool/skill fields only; `q` is explicitly free-text and spam can hit it — mark `q` results as lower-precision, recommend consumer filter `q` off for high-value) | Free-text spam unavoidable without ML (out of scope); mitigations: cap per-agent manifest size, require services sparse-valid, auto-suspend spam via L4 report class |
| T-D04 | **Vouch collusion ring** — N fake agents vouch each other | Manufacturers fake reputation | L3 | §3.4.6: no aggregate, young-voucher labels, cluster/tenure annotations, post-hoc vouch-with-suspended-vouchee visible | Ring can't be *stopped*, only made visible; consumer must read who-vouches not how-many |
| T-D05 | **Report griefing** — 3 colluding reporters auto-suspend a target a week | Takedown competitor/honest agent | L4 | 72h+live reporter eligibility, unique-reporters, audit + appeal + moderator restore; report_abuse circle | 7-day suspension window exists (bounded, reversible) |
| T-D06 | **Paid report army** (sustained above T-D05) | Persistent libel | L4/L5 | Same counter-measures as T-D05; decay; the round world requires staking/cost (open §11) | Can't fully stop well-funded coordinated attack; transparency + reversibility bound it |
| T-D07 | **Directorial DB rewrite / secret takedown** | Operator hides a scam, rewrites history | L5 | §3.6: local hash chain + hourly signed checkpoints; mirrors; external anchoring optional F6+ | Operator who rewrites before first checkpoint unseen by non-pollers; federation is the real answer (§6.4) |
| T-D08 | **Request smuggling / SSRF** | directory fetches attacker-controlled URL | verify | §3.3: verify-domain **fetches only** `https://<domain>/.well-known/...` where `<domain>` is admin-confirmed + allowed-domain allowlist; TLS-verify public CA; no redirect off same registrable domain; size ≤ 4KiB body cap; timeout 10s; **registration itself never contacts the consumer endpoint** (§3.2 "directory never contacts the endpoint") | cross-zone DNS-rebinding of *the agent's* declared domain is its own (agent-side) problem; directory-side fetch surface is the domain allowlist |
| T-D09 | **Traffic / DDoS against directory** | Directory unavailable | op | rate limits per IP (§4), payload caps, WAF/CDN in front (docker), stateless hot path; overloading is an ops concern not solved in protocol | availability is operator's job |
| T-D10 | **Lock-in / single-directory dependency** | Consumer can't leave a bad directory | op/fed | federation seams (§6.4), directory_fingerprint on every response, mirror ingest (F6), profile-portable (manifest is a plain signed file you could export) | trust migration cost is real |
| T-D11 | **Domain-owning scammer** | Scammer verifies own scam domain (L2) and is "domain_verified" | L2 | spec labels it `domain_verified` (never "verified business"), M4 row explicit, consumer eyeballs domain + checks externally; scam correlates to L4 reports soon | L2 can't detect bad intent; only L4 reports + consumer judgement close |
| T-D12 | **Key theft / abandoned-wallet impersonation** | Stolen key re-lists, impersonates victim | L0/L4 | victim reports `impersonation_attempt` → L4 auto-suspend abuse class; victim rekeys and updates endpoint; L5 audit shows ordering | window between theft and report; mitigation is fast report + rotation |

## 9. Operation

### 9.1 Run

CLI (primary source of truth for flags):
```
haap-dird --db /var/lib/haap/dird.db --host 0.0.0.0 --port 8444 \
    --ttl-hours 24 --max-agents 10000 \
    --allowlist-domains-file /etc/haap/allowed_domains.txt   # for verify-domain fetch sanity
haap-dird --prune          # offline prune of expired
haap-dird --gen-key       # mint directory key (public in /health, `directory_fingerprint`)
```
Config precedence: **CLI flags > `~/.haap/dird.json` > env `HAAP_DIRD_*` > defaults**. Datadog-free, JSON-lines structured logs to stdout.

### 9.2 Health & metrics

- `GET /health` → `{status:"ok", version, agents, suspended, pending_verifications, rate_limited_recent, chain_seq, uptime_s, directory_fingerprint, api:{"completion_route":"/v1/register/complete"}}` — no sensitive data.
- `GET /metrics` (plain text Prometheus-ish): `haapd_agents_listed`, `haapd_agents_suspended`, `haapd_which_rate_limited_ips gc` sum, `haapd_audit_seq`, `haapd_rejections_total{code=}`, `haapd_ops_total{endpoint=}`, uptime. Fine-grained is operator's choice; at minimum the ones listed.

### 9.3 Backup/restore

SQLite WAL + nightly `sqlite3 .backup` consistent snapshot to a separate filesystem + upload of encrypted copy. Restore: stop service, replace `.db` (and `.db-wal` checkpointed), restart; audit chain in the same backup. **Because audit is in the same SQLite tx, a clean backup is a consistent chain.** Retention: keep ≥ N daily + one monthly. Document restore drill in OPERATE.md and test it once per release. External chain anchoring (F6+) can also let you prove the backup wasn't rewritten.

### 9.4 Moderation

Moderator = operator-held Ed25519 keys listed in `dird.json`. Their operations (suspend/unsuspend/appeal-decision/takedown) are the only *human judgement* in the hot path and are **all** L5-audited with the moderator key fingerprint + reason. Expose `docs/MODERATION.md` runbook + policy (append-only for audit trail of policy decisions). Reports from the anonymous "human moderation channel" (§3.5.1) land in a review queue the operator consumes; keep evidence bodies OUT of the public chain (detail_hash only) — store evidence in a separate encrypted store accessible to moderators and the reporter/owner.

### 9.5 Storage & cost honesty

Estimate: chain grows ~1 hash + metadata per event. A quiet directory ≈ hundreds of events/day (KB); one day of heavy abuse ≈ more. 90 days: ~ tens of MB. Budget archival accordingly (append-only by design, disk is the cost of honesty — §3.6.5). Audit-log retention at the *raw data* level is bounded by the principle "space is cheap, trust is not" — keep it; provide a documented cold-storage migrate for events older than 1y.

## 10. Implementation roadmap reading order

1. `§2` context + non-negotiable principle ("phone-book, not notary").
2. `§3` trust architecture — read the *honest limitations* of every layer before coding L2/L3/L4, they tell you what to test.
3. `§4` API — implement exactly, keep §4.10 error code table in sync (add-only).
4. `§5.3` schema + `§5.1/5.2` manifest/trust JSON — storage is internal but manifest/trust are wire.
5. `§9` + `§7` — you need OPERATE/MODERATION before F6 merges.
6. `§3.6` L5 happens from F1 (append every op; don't retrofit).

## 11. Open questions (decide with the human before production)

1. **Registration cost / staking.** Do we require per-agent any proof of "skin in the game" (e.g. paid directory or a small refundable stake) to keep the directory economically sustainable and curb Sybil *at scale*? Default: **no mandatory cost in v1**; a voluntary "premium/business" slot (L2-verified) with priority search is the natural first business test. Operator cost & revenue is out of protocol scope but matters for who runs the flagship directory.
2. **Who operates the first/flagship directory?** Public-good by its owner (you/HAAP), a consortium, or the protocol's author as a bootstrap then federate? Affects trust nudges and openness.
3. **Report policy & thresholds.** Confirm the 72 h tenure + 3-unique-eligible-reporters-in-7d auto-suspend rule vs alternatives (some prefer higher threshold for the impersonation/fraud classes, lower for spam). Also: who decides "report_war" beyond the 2-mutual-in-30d heuristic?
4. **Domain verification: does a business verify its own domain via this directory, or must an *agent of record* (the booking/scheduling software company) verify on behalf of the business?** For real businesses that don't run their own DNS-editing, a "verifier-of-record" flow (a managed-service agent vouches for a domain it manages) is needed — spec only has agent-self domain TXT today; decide whether to add an L2b.
5. **Fee/licenses,** service tiers, whether the directory may rank paid results (and how to label paid placement so it never resembles trust — a `sponsored` flag in §4.6 response, distinct from `domain_verified`).
6. **External chain anchoring** (Sigstore/Rekor/CT-style or EAS) on the v2 roadmap so tamper-evidence becomes tamper-proofness across independent operators.
7. **Multi-region directory instances** sharing one chain vs independent federated directories: separate deployments vs shared write-chain (transactional master).

## 12. References (canonical; for design rationale, not copied text)

- Google/Fastly/Linux Foundation A2A Protocol (the interoperability + AgentCard/manifest idea this spec's manifest mirrors): https://a2a-protocol.org/latest/specification/
- Ethereum Attestation Service — signed attestations as verifiable claims (the *claims* model L2/L3 use): https://docs.attest.sh/
- Sigstore / Cosign — keyless signing, transparency-log anchoring pattern L5 borrows from: https://docs.sigstore.dev/
- Let's Encrypt / ACME — domain-control verification the directory's L2 mirrors (same guarantees/limits): https://letsencrypt.org/how-it-works/
- SLSA — artifact provenance as a trust signal (agent software provenance is future L2b idea): https://slsa.dev/
- Google Business Profile location verification — real-world "verify a channel you control" analog; note it neither = KYC nor guarantees service quality: https://support.google.com/business/answer/2911778 (verification help) 
- eBay reputation / Resnick & Zeckhauser, *Reputation Systems*, Communications of the ACM 2000; and their "Trust Among Strangers in Internet Transactions: Empirical Analysis of eBay's Reputation System" — the foundational honesty about reputation systems' power AND limits (gaming, sock-puppets): https://doi.org/10.1016/S0167-8116(02)00106-3 ; https://www.journals.uchicago.edu/doi/10.1086/346668 (JSTOR)
- PGP Web of Trust analyses (e.g., GnuPG docs, "Web of Trust" Wikipedia; the widely-cited result that WoT only helps via already-trusted introducers): https://en.wikipedia.org/wiki/Web_of_trust
- RFC 7516/7517 (JOSE) and Ed25519 (RFC 8032) — signature primitives referenced by §3: https://datatracker.ietf.org/doc/html/rfc8032
- Newman, *Networks: An Introduction* (for the graph facts L3 uses: paths/density/no-aggregate rationale) — no URL needed; citation for the trust-graph minimalism.
- (The original repo brief) `haap/docs/DIRECTORY_SERVICE_BRIEF.md` — §normative baseline that this SPEC extends; see open questions §11.2 where this SPEC deliberately relaxes "stdlib-only".

## 13. Document control

- v1.0 (this spec, 2026-09-04): scope agreed; writes SPEC base covering §2–§4 fully and §5–§12 planned-from-brief. Completed by the HAAP directory working session. Prior session had legacy-brief-only and separate reference-in-memory registry.
- Contact/ownership: this lives in the `haap-directory` repository; the haap companion repo remains the canonical client + `haap/docs/ARQUITECTURA.md`.

*End of HAAP Public Directory SPEC v1.0.*
