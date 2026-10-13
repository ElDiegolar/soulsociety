# @soulsociety/mcp

`soul-mcp`: a stdio MCP server over one soul on this device. The device keypair and data key are loaded in this process and never leave it; the harness sees derived state and ciphertext-free event JSON, nothing else.

```sh
npm run build
claude mcp add soul -e SOULSOCIETY_DEVICE_PASSPHRASE=... -- node /path/to/soulsociety/packages/mcp/dist/main.js
```

The device must already be created or enrolled + activated with `soul-sync` in the same `SOULSOCIETY_HOME`; the server exits with `device is not activated for this soul` otherwise.

## Environment

| variable                                                | required                      | meaning                                                                                                                                                                                                     |
| ------------------------------------------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SOULSOCIETY_DEVICE_PASSPHRASE`                         | yes                           | Unlocks the device keyfile. Required because stdio has no TTY.                                                                                                                                              |
| `SOULSOCIETY_HOME`                                      | no (default `~/.soulsociety`) | Directory with `config.json` (`backend`, `dataDir`, `hostFile`, `supabaseUrl`, `supabaseKey`, `current: { soulId, deviceId }`).                                                                             |
| `SOULSOCIETY_GRANT`                                     | no                            | A harness token from `soul-sync grant`. If set, tools are limited to the grant's scopes and the grant must belong to the served soul and be unexpired/unrevoked. Without it, all five scopes are available. |
| `SOULSOCIETY_AUTOSYNC`                                  | no (default `1`)              | `1`: sync before `soul_state`, push after appends. `0`: only sync when asked.                                                                                                                               |
| `SUPABASE_URL`, `SUPABASE_KEY`, `SUPABASE_ACCESS_TOKEN` | with `backend: supabase`      | Override `supabaseUrl` / `supabaseKey` in config; the access token is the owner's JWT.                                                                                                                      |

## Tools

| tool                      | input                                                                                                             | scope             | returns                                                                                        |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------- | ----------------- | ---------------------------------------------------------------------------------------------- |
| `soul_state`              | `{ sync?: boolean }`                                                                                              | `state:read`      | Replayed `SoulState` plus `allowedAppendTypes` for this harness.                               |
| `soul_history`            | `{ typePrefix?: string, limit?: 1..500 }`                                                                         | `events:read`     | Most recent `limit` (default 100) entries in replay order, optionally filtered by type prefix. |
| `soul_append`             | `{ type: string, data?: object }`                                                                                 | `events:append`   | `{ seq, deviceId }`, or an error listing the allowed types.                                    |
| `soul_request_capability` | `{ capability: string, reason: string(≤500) }`                                                                    | `events:append`   | Appends a `note` `[capability request] <cap>: <reason>`; returns the known capability names.   |
| `soul_observe`            | `{ kind: preference\|pattern\|fact\|goal\|dislike, text: string(≤500), confidence?: 0..1, source?: string(≤80) }` | `events:append`   | `{ seq }` after appending an `observation` (default confidence 0.5).                           |
| `soul_sync`               | `{}`                                                                                                              | `events:read`     | `{ pushed, pulled }`.                                                                          |
| `soul_snapshot`           | `{}`                                                                                                              | `snapshots:write` | `{ replayHash, eventCount }` after uploading an encrypted snapshot.                            |

Resource: `soul://state` (JSON, `state:read`).

## Gating

Two independent gates apply to every call:

1. **Scope** (from `SOULSOCIETY_GRANT`, or all scopes when unset). A missing scope throws `grant lacks scope <s>`.
2. **Trust ladder** (only for `soul_append`). The allowed event types are computed from the soul's replayed state at call time. The ladder is state, not configuration, so a harness cannot edit it; offering and accepting capabilities (`trust.offered`, `trust.accepted`) happens through the CLI or a body, never through this server.

| condition                                                                                        | harness may append                       |
| ------------------------------------------------------------------------------------------------ | ---------------------------------------- |
| always                                                                                           | `note`, `commitment.made`, `observation` |
| `trust.witness_tasks.status === 'accepted'`                                                      | `task.completed`                         |
| `trust.approve_drafts.status === 'accepted'`                                                     | `draft.approved`                         |
| `trust.manage_commitments.status === 'accepted'`                                                 | `commitment.kept`, `commitment.broken`   |
| anything else (`soul.*`, `device.*`, `key.*`, `trust.*`, `observation.retracted`, unknown types) | refused; use `soul_request_capability`   |

A capability is `accepted` after `trust.offered` then `trust.accepted`; two `trust.failed` events set it to `revoked`, which locks its types again. Appended events still pass `validateEvent` (envelope, known-type data shape, forbidden input keys), so a permitted type with bad data is rejected too.
