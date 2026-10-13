# soulsociety — encrypted, user-owned soul sync for harnesses

Status: design, 2026-10-13. Scope: hosting + sync + MCP access for KAI-style "souls".
Out of scope here: KAI creature/body, trust-ladder semantics (owned by soul-mcp), chain anchoring (parked, v2).

## 1. Goals / non-goals

Goals

- A user can keep one soul across many devices and harnesses, with the server never able to read it.
- Any MCP-speaking harness (Claude Code, Hermes, KAI body, future agents) can be granted scoped access.
- Append-only, replay-deterministic, per-device logs: no merges, no conflicts, full history.
- Boring, auditable crypto (libsodium / age primitives), no custom schemes.
- Runs on Supabase at $0 for a hobbyist, scales to a product without re-architecture.

Non-goals

- Server-side reasoning over souls. The server is storage + accounts + relay.
- Real-time multi-writer collaboration. One soul, one owner, many devices, each with its own log.
- Hiding metadata from the host (sizes, timestamps, device count are visible).

## 2. Threat model

Protect against: host compromise, rogue admin, subpoena of the host, token theft by a harness, a lost/stolen device.
Do not (cannot) protect against: a compromised client with an unlocked key, a user who loses passphrase AND recovery code.

Consequences

- All soul content is ciphertext at rest and in transit through the host.
- Harness tokens are scoped and revocable; append-only by default; cannot delete or rewrite history.
- A revoked device loses the ability to decrypt future events (data-key rotation on revoke).

## 3. Data model

A **soul** = `companion.md` (identity doc, versioned snapshots) + N **device logs** (append-only JSONL events).
All derived state (XP, level, mood, trust, commitments) = deterministic replay of the union of logs ordered by (ts, device_id, seq). Same rule as KAI v1; the host changes nothing about replay.

Server tables (Supabase / Postgres):

```sql
create table souls (
  id uuid primary key default gen_random_uuid(),
  owner uuid not null references auth.users(id) on delete cascade,
  name text not null,               -- host-visible label only; the soul's real name is in the encrypted soul.created event
  created_at timestamptz not null default now(),
  -- data key wrapped by the owner's root key (for recovery / new-device bootstrap via owner)
  wrapped_dk_owner bytea not null
);

create table devices (
  id uuid primary key default gen_random_uuid(),
  soul_id uuid not null references souls(id) on delete cascade,
  label text not null,
  pubkey bytea not null,            -- X25519 device public key
  wrapped_dk bytea,                 -- soul data key sealed to this device's pubkey (null until approved)
  approved_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create table events (
  soul_id uuid not null references souls(id) on delete cascade,
  device_id uuid not null references devices(id),
  seq bigint not null,              -- per-device monotonic, client-assigned
  dk_version int not null,          -- which data key encrypted this
  nonce bytea not null,
  ciphertext bytea not null,        -- XChaCha20-Poly1305(JSON event)
  created_at timestamptz not null default now(),
  primary key (device_id, seq)
);
create index on events (soul_id, created_at);

create table snapshots (                -- encrypted companion.md + optional replay checkpoint
  soul_id uuid not null references souls(id) on delete cascade,
  device_id uuid not null references devices(id),
  through jsonb not null,           -- {device_id: seq} vector this snapshot covers
  dk_version int not null,
  nonce bytea not null,
  ciphertext bytea not null,
  created_at timestamptz not null default now(),
  primary key (soul_id, created_at)
);

create table harness_grants (
  id uuid primary key default gen_random_uuid(),
  soul_id uuid not null references souls(id) on delete cascade,
  label text not null,              -- "claude-code on laptop", "hermes @ desktop"
  scopes text[] not null,           -- {'events:read','events:append','snapshots:read'}
  token_hash bytea not null,        -- sha256 of the bearer token; token shown once
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);
```

RLS: every table `enable row level security`; policy = `soul_id in (select id from souls where owner = auth.uid())`.
Harness access goes through an edge function / gateway that validates `harness_grants` and uses the service role, never a user JWT.

Event envelope (plaintext, before encryption):

```json
{ "v": 1, "ts": "2026-10-13T09:12:31.004Z", "type": "task.completed", "data": {...} }
```

`seq` is assigned client-side from the device's local log; the server rejects a (device_id, seq) that already exists (idempotent retry) and rejects gaps (seq must be last+1).

## 4. Keys

- **Root key** `RK` = Argon2id(passphrase, salt, m=256MiB, t=3). Never leaves the client. Salt stored on server with the account.
- **Data key** `DK` (32B random) per soul, versioned. Encrypts every event/snapshot with XChaCha20-Poly1305, nonce random 24B.
- **Device keypair** X25519 per device, private key in OS keystore (DPAPI / Keychain / secret-service) or a passphrase-encrypted file.
- `wrapped_dk_owner` = secretbox(DK, RK). `devices.wrapped_dk` = sealed_box(DK, device_pubkey).
- **Recovery code**: 26-char base32 random, derives a second wrapping key; a second `wrapped_dk_recovery` column (add to `souls`). Shown once at soul creation.

Flows

- _New device_: generates keypair, registers (soul_id, pubkey, label) → pending. An approved device (or the owner with RK) sees the request, seals DK to the new pubkey, writes `wrapped_dk`, sets `approved_at`. New device can now decrypt.
- _Revoke device_: set `revoked_at`; generate DK v+1; re-seal to all remaining devices; new events use v+1. Old events stay readable (they're history) but the revoked device can't read anything new. No re-encryption of history.
- _Passphrase change_: re-wrap `wrapped_dk_owner` only.
- _Lost everything_: recovery code → DK → re-enrol a device. Lost both → soul is ciphertext forever. Say this in the UI in plain words.

## 5. Sync protocol (client ↔ host)

HTTPS JSON over Supabase (PostgREST + 2 edge functions). All payloads ciphertext.

- `GET /souls/:id/heads` → `{device_id: last_seq}` for every device.
- `GET /souls/:id/events?since={device_id: seq,...}` → events after each head, ordered by created_at; paginated.
- `POST /souls/:id/events` body: `[{device_id, seq, dk_version, nonce, ciphertext}]` → 201 or 409 on gap/duplicate.
- `POST /souls/:id/snapshots` (optional, for fast cold start; replay is still the source of truth).
- Realtime: subscribe to `events` for the soul via Supabase Realtime so other devices get appends in seconds.

Client keeps its local JSONL exactly as KAI v1 does. Sync = push my log tail, pull others' tails, rebuild SQLite cache. Offline works; the server is a relay.

## 6. soul-mcp (client-side, keys live here)

Unchanged from the KAI design; gains a `sync` module. Tools (stable surface):

- `soul.state()` → derived state (level, xp, mood, trust, commitments) from replay
- `soul.append(event)` → validates against schema + capability gate, appends locally, pushes
- `soul.history(filter)`
- `soul.capability.request(cap)` / trust ladder as spec'd in KAI v1
- `soul.sync.status()` / `soul.sync.now()`

Harness connects over stdio (local) or local HTTP with a bearer from `harness_grants`. Gating is enforced in soul-mcp, not in the harness, so a harness can't self-escalate.

## 7. Remote access (hosted harnesses)

Two modes, user-visible, chosen per grant:

**ZK relay (default).** A gateway (Cloudflare Worker, Durable Object per soul, or a Supabase edge function) exposes remote MCP over streamable HTTP with OAuth 2.1 + PKCE. It forwards ciphertext only. The _harness_ must run a soul-mcp client with a key, i.e. the harness host is treated as a device: it enrols, gets approved, holds a sealed DK. Good for your own desktop/laptop harnesses; wrong for a vendor-hosted agent you don't control.

**Custodial session (opt-in).** For thin clients / hosted agents. The user unlocks DK on a trusted device and hands the gateway a _session key_: DK sealed to the gateway's ephemeral keypair, TTL ≤ 24h, held in memory in the Durable Object, never persisted. The gateway runs soul-mcp for that session. Threat model shifts: the gateway operator can read the soul while the session lives. Label it that way. Future upgrade path: run the custodial soul-mcp in a TEE with remote attestation (AWS Nitro / Azure CVM) so even the operator can't.

## 8. Accounts & billing

Supabase Auth with passkeys (WebAuthn) primary, email magic link fallback. One owner per soul; souls are not shared (sharing a soul = sharing a self; if ever needed, it's a new product decision).
Free tier: 1 soul, 3 devices, 50 MB. Paid: more souls/devices, longer snapshot retention, custodial mode. Stripe via Supabase's standard wrapper when needed. Nothing here is blocking for v1.

## 9. Build order

1. `soul-sync` CLI (TypeScript, libsodium-wrappers, argon2): create soul, enrol/approve device, append, pull, verify replay. Local JSONL in/out. Supabase schema + RLS from §3. **This proves the key model.**
2. soul-mcp gains the sync module; KAI body + Claude Code `embody` work across two machines.
3. harness_grants + local HTTP bearer auth in soul-mcp.
4. Gateway (ZK relay) on Cloudflare Workers using the remote-MCP OAuth template. Only if a non-local harness needs it.
5. Custodial sessions. Only if a hosted agent needs it.
6. Chain anchor (parked v2): one cron that posts the log-head hash. Hooks in at §5 without changing anything above.

## 10. Open questions

- Event schema registry: versioned JSON Schemas in the repo; replay must handle every historical version forever.
- Snapshot trust: snapshots are a cache, but a malicious device could write a wrong one. Mitigation: snapshots carry the replay hash; peers verify on load; mismatch → full replay.
- Metadata leakage: event timing reveals activity patterns. Acceptable for v1; padding/batching later.
- Multi-soul per user: schema supports it; UI for v1 shows one.
- Device key storage on Linux headless boxes: passphrase-encrypted file is the realistic answer; document it.

## 11. Website (soulsociety.*) — requirement captured 2026-10-13

Not built yet. The public site must be SEO-compliant from day one: server-rendered or statically generated HTML (no client-only app shell), one canonical URL per page, titles/meta descriptions/Open Graph per page, semantic headings, sitemap.xml + robots.txt, structured data (Organization, SoftwareApplication, FAQ), fast Core Web Vitals (no heavy JS on landing pages), accessible markup, and docs pages generated from the repo READMEs so content stays current. Suggested stack: Astro (static, zero-JS by default) with the docs under /docs and the app/console as a separate route or subdomain.
