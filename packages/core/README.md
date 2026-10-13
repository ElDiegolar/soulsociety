# @soulsociety/core

Client-side core for soulsociety: crypto, local logs, deterministic replay, the host `Store` interface, and `SoulClient`, which ties them together. Nothing in this package ever hands a key to a `Store`. Entry point: `src/index.ts`.

## SoulClient lifecycle

One `SoulClient` = one `(soul, device)`. Construct it through the static factories, all of which take `SoulClientOptions { store, keystore, dataDir, devicePassphrase, argon2? }`:

| step     | call                                                                                                                                   | effect                                                                                                                                                                                                                                               |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| create   | `SoulClient.create(opts, { ownerId, name, ownerPassphrase, deviceLabel })`                                                             | New DK, salt, RK, recovery code; writes soul + first approved device to the store; appends `soul.created`, `device.enrolled`; pushes. Returns `{ client, result: { soulId, deviceId, recoveryCode } }`. Show the recovery code once, never store it. |
| open     | `SoulClient.open(opts, soulId, deviceId)`                                                                                              | Loads secrets from the keystore and the local `DeviceLog`.                                                                                                                                                                                           |
| enrol    | `SoulClient.enrol(opts, soulId, deviceLabel)`                                                                                          | New X25519 keypair, pending device record, empty `dataKeys`. `client.isActive` is `false`.                                                                                                                                                           |
| approve  | `client.approveDevice(pendingId)` or `SoulClient.approveWithOwnerSecret(store, soulId, pendingId, { passphrase } \| { recoveryCode })` | Seals every DK version the approver holds to the pending device's pubkey. The owner wrap only holds the latest version; older versions must come from an approved device.                                                                            |
| activate | `client.activate()`                                                                                                                    | Fetches `sealedDks`, opens them, persists; appends `device.enrolled` on first activation. Idempotent; returns `true` when at least one DK is held.                                                                                                   |
| write    | `client.append(event)`                                                                                                                 | Validates (`validateEvent`) and appends to the local JSONL log (fsync). Requires an active device.                                                                                                                                                   |
| sync     | `client.push()`, `client.pull()`, `client.sync()`                                                                                      | Push encrypts the local tail under the newest DK and sends it; pull fetches peers' tails by per-device head, decrypts, writes `PeerLog`s.                                                                                                            |
| read     | `client.allEntries()`, `client.state()`                                                                                                | Union of own + peer logs; `state()` is `replay()` over them.                                                                                                                                                                                         |
| snapshot | `client.putSnapshot()`, `client.verifiedSnapshot()`                                                                                    | Encrypted state cache bound to its replay hash; a loaded snapshot is only returned if a local replay produces the same hash.                                                                                                                         |
| revoke   | `client.revokeDevice(deviceId, ownerPassphrase, recoveryCode?)`                                                                        | Proves the passphrase, marks the device revoked, mints DK v+1, re-seals to the remaining approved devices, re-wraps owner (and optionally recovery) copies, appends `device.revoked` + `key.rotated`. Returns the new version.                       |
| grants   | `client.createGrant(label, scopes?, ttlDays?)`, `client.revokeGrant(id)`, `authenticateGrant(store, token, needed)`                    | Harness bearer tokens (`ss_...`); only `sha256(token)` is stored.                                                                                                                                                                                    |

## Store implementations

`Store` (in `store.ts`) is the host-side interface: souls, devices, events, snapshots, grants. It only ever carries ciphertext, public keys and wrapped/sealed keys. Error type `StoreError` with codes `conflict | gap | not_found | forbidden | io`. `appendEvents` must be atomic and reject a duplicate or gapped `(deviceId, seq)`.

| class           | module        | use                                                                                                                                                                                                                                                                 |
| --------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MemoryStore`   | `store.ts`    | Tests and ephemeral sessions.                                                                                                                                                                                                                                       |
| `FileHostStore` | `filehost.ts` | `MemoryStore` persisted to one JSON file with an advisory lock, so two processes on one machine can act as two devices. `FileHostStore.open(path)`. Not for production.                                                                                             |
| `SupabaseStore` | `supabase.ts` | Production. `new SupabaseStore({ url, key, accessToken?, client? })`. User mode (anon key + owner JWT, RLS scopes rows) or service mode (service-role key, gateway only, after a grant has been validated). Uses the RPCs from `supabase/migrations/0001_init.sql`. |

The Postgres integration test (`test/pg.integration.test.ts`, run with `npm run test:integration`, `SOUL_PG_URL`) applies the migration to a real Postgres and drives `SupabaseStore` semantics against it; `scripts/pg-up.sh` starts a local container.

Keystores (`keystore.ts`): `FileKeystore(dir, argon2)` writes `<dir>/<soulId>/<deviceId>.keys.json` (0600), secretboxed under Argon2id(device passphrase). `MemoryKeystore` for tests and custodial sessions.

## Logs

`DeviceLog` (`log.ts`): one JSONL file per `(soul, device)`, plaintext (the local disk is the trust boundary). `seq` starts at 1 and increases by exactly 1; each line is fsynced before `append()` resolves; a truncated trailing line is dropped on open. `PeerLog` is the read-only mirror of another device's log, filled by `pull()`.

## Replay rules

`replay(entries, from = emptyState())` in `replay.ts`:

- Order is `(event.ts, deviceId, seq)`; `ts` is the writer's clock, ties break by device id then seq, so two devices never produce an ambiguous order.
- Reducers are pure; `reduce()` clones state. Unknown event types are counted in `counts` and otherwise ignored, so a newer client can write events an older one skips without diverging on the fields it knows.
- `replayHash` is a chained SHA-256 over the canonical form of each ordered entry (`{d, s, t, y, a}` with sorted-key data), not over the state object, so the hash is schema-independent and the same on every machine.
- XP comes only from `task.completed` with `witnessed: true` (+10) and `draft.approved` (+15). Levels: `LEVELS = [0, 100, 300, 700, 1500]`.
- Trust: `trust.offered` sets `{ level, status: 'offered' }`; `trust.accepted` moves an offered capability to `accepted`; two `trust.failed` set `revoked`.
- Commitments: `commitment.made` opens; `kept` / `broken` close an open one once.
- Observations: `observation` appends `{ kind, text, confidence, source?, count, firstSeen, lastSeen }` to `state.observations`, deduplicated by trimmed `text` (repeats bump `count`, `lastSeen` and raise `confidence`); the list is capped at `MAX_OBSERVATIONS`, evicting the lowest `confidence * count`. `observation.retracted` removes by text and is meant to be appended by the human, not a harness.

## Event schema

Envelope (`schema.ts`), plaintext before encryption:

```json
{ "v": 1, "ts": "2026-10-13T09:12:31.004Z", "type": "task.completed", "data": {} }
```

`v` is the literal `1`; `type` matches `^[a-z][a-z0-9_.-]*$` (max 64); `ts` is ISO-8601 with offset. Known types and their `data` shapes are in `KnownEvents` (soul.created/renamed, device.enrolled/revoked, key.rotated, task.completed, draft.approved, trust.offered/accepted/failed, commitment.made/kept/broken, observation, observation.retracted, note). Unknown types are accepted with any object `data`. Schemas are versioned forever: add a new literal, never change an existing one, because replay must read every version ever written.

`validateEvent(input)` throws `SchemaError` on a bad envelope or bad data for a known type; `makeEvent(type, data, ts?)` builds and validates a known event.

**Forbidden inputs.** `FORBIDDEN_DATA_KEYS = ['engagement', 'sessionMinutes', 'streak', 'opens', 'timeInApp', 'appOpens']` may never appear as keys in `data`. `validateEvent` rejects them at append time (and again when decrypting pulled events), so engagement-style metrics can never influence derived state. Only witnessed work earns XP.

## Crypto

All libsodium (`crypto.ts`): Argon2id for `RK` and the recovery key (`ARGON2_DEFAULT`: opslimit 3, 256 MiB; `ARGON2_TEST` for tests), XChaCha20-Poly1305 secretbox for key wraps, sealed boxes (X25519) for per-device DK sealing, XChaCha20-Poly1305-IETF with AAD `bindingAad({ soulId, deviceId, seq, dkVersion })` for events, SHA-256 for token and replay hashes. Recovery codes are 26 chars of Crockford base32 (`newRecoveryCode`, `normaliseRecoveryCode`).
