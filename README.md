# soulsociety

Encrypted, user-owned "soul" sync for AI harnesses. A soul is an identity document plus a set of append-only, per-device event logs; everything a companion or agent derives about itself (XP, level, trust, commitments) is a deterministic replay of the union of those logs. soulsociety lets one user keep one soul across many devices and harnesses (Claude Code, Hermes, a KAI body, anything that speaks MCP) with a host that is storage, accounts and relay only: it never reasons over souls and it never holds a key. See [DESIGN.md](DESIGN.md) for the full design.

**Zero-knowledge guarantee.** Every event and snapshot is encrypted on the device with a per-soul data key that only approved devices (and the owner, via passphrase or recovery code) can unwrap; the host stores and relays ciphertext and can verify nothing about its contents. The host does see metadata (sizes, timestamps, device count, event timing) and that is a stated non-goal to hide.

## Repo layout

```
DESIGN.md                      the design doc; the README defers to it
packages/core                  @soulsociety/core: crypto, logs, replay, Store interface, SoulClient
packages/cli                   @soulsociety/cli: `soul-sync` command
packages/mcp                   @soulsociety/mcp: `soul-mcp` stdio MCP server (keys live here)
packages/gateway               ZK relay gateway (ciphertext forwarding, harness-grant auth)
skills/soul-companion          Claude Code skill: how a harness should use the soul_* tools
supabase/migrations/0001_init.sql  tables, RLS, append-only triggers, RPCs
scripts/pg-up.sh, pg-down.sh   local Postgres for the integration tests
.github/workflows/ci.yml       build, typecheck, lint, unit + Postgres integration tests
```

Toolchain: Node 22, npm workspaces, TypeScript, vitest, ESLint (flat config) + Prettier.

```sh
npm ci
npm run build          # tsc for every package
npm run typecheck
npm run lint           # eslint .
npm run format:check   # prettier --check .
npm test               # core unit tests (no network)
npm run test:integration   # needs Postgres; scripts/pg-up.sh starts one, SOUL_PG_URL overrides the URL
```

## Quickstart with the `file` backend

The `file` backend is the host simulated as one JSON file on local disk (`FileHostStore`). It is not for production, but it exercises the whole key model offline, including multi-device: two "devices" are two `SOULSOCIETY_HOME` directories pointing at the same host file.

`soul-sync` reads `$SOULSOCIETY_HOME/config.json` (default `~/.soulsociety/config.json`). Shape, from `packages/cli/src/main.ts`:

```json
{
  "backend": "file",
  "dataDir": "/path/to/home/data",
  "hostFile": "/path/to/home/host.json",
  "supabaseUrl": "...",
  "supabaseKey": "...",
  "current": { "soulId": "...", "deviceId": "..." }
}
```

`backend`, `dataDir`, `supabaseUrl`, `supabaseKey` are settable with `soul-sync config`; `hostFile` has no flag and is edited in the file. `current` is written by `create` / `enrol`.

Build once, then alias the CLI:

```sh
npm ci && npm run build
alias soul-sync="node $PWD/packages/cli/dist/main.js"
```

### Device A: create a soul

```sh
export SOULSOCIETY_HOME=/tmp/soul-a
soul-sync config --backend file
soul-sync create --name kai --label laptop
```

You are asked for an owner passphrase (derives the root key; never stored) and a device passphrase (encrypts this device's keyfile under `dataDir/keys`). The command prints the soul id, the device id, and:

```
RECOVERY CODE — write it down now, it is not stored anywhere:
```

**If you lose the owner passphrase and the recovery code, the soul is ciphertext forever. Nobody, including the host, can get it back.**

Append something and look at state:

```sh
soul-sync append task.completed '{"taskId":"t1","title":"first task","witnessed":true}'
soul-sync demo-event note
soul-sync state
soul-sync devices
```

### Device B: enrol a second device against the same host file

```sh
export SOULSOCIETY_HOME=/tmp/soul-b
soul-sync config --backend file
```

Now point B's `hostFile` at A's host file (the one flag-less key):

```sh
node -e '
const fs=require("fs"),p=process.env.SOULSOCIETY_HOME+"/config.json";
const c=JSON.parse(fs.readFileSync(p,"utf8")); c.hostFile="/tmp/soul-a/host.json";
fs.writeFileSync(p,JSON.stringify(c,null,2));'
soul-sync enrol --soul <soulId from A> --label desktop
```

`enrol` registers a pending device with a fresh X25519 keypair and prints the three ways to finish. Approve from A, either with A's device key or with the owner secret:

```sh
export SOULSOCIETY_HOME=/tmp/soul-a
soul-sync approve <deviceId from B>              # uses A's unsealed data key
# or: soul-sync approve --owner <deviceId>       # owner passphrase
# or: soul-sync approve --recovery <deviceId>    # recovery code
```

Then on B:

```sh
export SOULSOCIETY_HOME=/tmp/soul-b
soul-sync activate        # unseals the data key sealed to B's pubkey
soul-sync sync            # pushes B's log, pulls A's
soul-sync state --sync    # same replayHash as A
```

Both devices now hold the data key; each writes only its own log.

Non-interactive use: `SOULSOCIETY_DEVICE_PASSPHRASE`, `SOULSOCIETY_OWNER_PASSPHRASE` and `SOULSOCIETY_RECOVERY_CODE` replace the corresponding prompts (the device one is required for the MCP server, which has no TTY). Piping several answers on stdin in one go is not reliable; use the env vars for scripts.

Other commands: `revoke <deviceId>` (rotates the data key; see Security), `snapshot`, `grant <label>` / `grants [--revoke <id>]`, `append --no-push`.

## Supabase setup

1. Create a Supabase project and apply the schema: `supabase db push` with this repo's `supabase/migrations/`, or `psql "$DATABASE_URL" -f supabase/migrations/0001_init.sql`. The migration creates `souls`, `devices`, `events`, `snapshots`, `harness_grants`, enables RLS on all of them (owner = `auth.uid()`), forbids UPDATE/DELETE on `events` by trigger, and installs the RPCs the client uses (`soul_heads`, `events_append`, `events_since`, `device_approve`, `soul_rotate_keys`, `grant_by_token_hash`).
2. Export credentials. `SUPABASE_URL` and `SUPABASE_KEY` are the project URL and anon key; `SUPABASE_ACCESS_TOKEN` is the signed-in owner's JWT (RLS scopes every row to that user). Env vars override `supabaseUrl` / `supabaseKey` in config.json.

   ```sh
   export SUPABASE_URL=https://<project>.supabase.co
   export SUPABASE_KEY=<anon key>
   export SUPABASE_ACCESS_TOKEN=<user JWT>
   soul-sync config --backend supabase
   # or persist url/key: soul-sync config --backend supabase --supabase-url ... --supabase-key ...
   ```

3. Create the soul with the owner's Supabase user id (the `souls.owner` column references `auth.users`; the default `--owner local` only works on the file backend):

   ```sh
   soul-sync create --name kai --owner <auth.users.id>
   ```

Everything else (`enrol`, `approve`, `sync`, ...) is identical. Only ciphertext, public keys, wrapped keys and metadata ever reach Supabase.

## MCP server for Claude Code

`soul-mcp` is a stdio MCP server over the current soul/device in `SOULSOCIETY_HOME`. Keys stay in the process; the harness never sees them. It needs the device passphrase in the environment because stdio has no TTY:

```sh
npm run build
claude mcp add soul -e SOULSOCIETY_DEVICE_PASSPHRASE=... -- node /path/to/soulsociety/packages/mcp/dist/main.js
```

Optional env: `SOULSOCIETY_HOME` (which config/device to serve), `SOULSOCIETY_GRANT` (a harness token; restricts tools to its scopes), `SOULSOCIETY_AUTOSYNC` (`1` default: sync before reads, push after appends). Supabase env vars apply as for the CLI.

Tools (plus a `soul://state` resource):

| tool                      | scope needed      | what it does                                                                                            |
| ------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------- |
| `soul_state`              | `state:read`      | Replayed state, plus `allowedAppendTypes` for this harness                                              |
| `soul_history`            | `events:read`     | Events in replay order; `typePrefix`, `limit` (≤500, default 100)                                       |
| `soul_append`             | `events:append`   | Append one event if its type passes the trust-ladder gate                                               |
| `soul_request_capability` | `events:append`   | Records a `note` asking the human to offer a capability                                                 |
| `soul_observe`            | `events:append`   | Records an `observation` about the user (`kind`, `text`, `confidence`, `source`); replay dedups by text |
| `soul_sync`               | `events:read`     | Push local, pull peers                                                                                  |
| `soul_snapshot`           | `snapshots:write` | Upload an encrypted, replay-hash-verifiable snapshot                                                    |

**Trust-ladder gating.** The set of event types a harness may append is derived from the soul's own replayed state, not from configuration, so a harness cannot edit it. `note`, `commitment.made` and `observation` are always allowed (retracting an observation, `observation.retracted`, is human-only). Each capability, once a `trust.offered` event has been answered by `trust.accepted` (both appended by a human through the CLI or a body, never by the harness), unlocks its event types:

| capability (status `accepted`) | unlocks                                |
| ------------------------------ | -------------------------------------- |
| `witness_tasks`                | `task.completed`                       |
| `approve_drafts`               | `draft.approved`                       |
| `manage_commitments`           | `commitment.kept`, `commitment.broken` |

Two `trust.failed` events demote a capability to `revoked` and the types lock again. Anything else (`soul.*`, `device.*`, `key.*`, `trust.*`, unknown types) is refused with the current allowed list; the harness can only ask via `soul_request_capability`.

## Grants

A grant is a bearer token for a harness, minted from an active device and shown once; the host stores only `sha256(token)`:

```sh
soul-sync grant "claude-code on laptop" --scopes events:read,events:append,state:read --ttl-days 30
soul-sync grants                 # list
soul-sync grants --revoke <id>   # revoke
```

Scopes: `events:read`, `events:append`, `snapshots:read`, `snapshots:write`, `state:read`. Default for `grant` is `events:read,events:append,state:read`. Tokens are `ss_` + 32 random bytes base64url; `authenticateGrant()` in core rejects revoked, expired, or under-scoped tokens. Locally, `SOULSOCIETY_GRANT` makes `soul-mcp` enforce a grant's scopes on its own tools. Remotely, the gateway in `packages/gateway` validates grants with the service role (`grant_by_token_hash`) and forwards ciphertext only; a grant never carries a key, so a stolen token yields nothing readable without an approved device.

## Security model

Primitives are libsodium only (see `packages/core/src/crypto.ts`):

- Root key `RK` = Argon2id(owner passphrase, salt), opslimit 3, 256 MiB. Never leaves the client; the salt lives with the soul.
- Data key `DK` = 32 random bytes per soul, versioned. Every event is XChaCha20-Poly1305 with AAD binding `(soul, device, seq, dkVersion)`, so the host cannot move, re-tag or reorder ciphertext without the AEAD failing.
- `wrapped_dk_owner` = secretbox(DK, RK); `wrapped_dk_recovery` = secretbox(DK, Argon2id(recovery code)); each device holds `sealed_dks[version]` = sealed_box(DK, device X25519 pubkey).
- Device private key and unsealed DKs sit in a passphrase-encrypted keyfile (`FileKeystore`, 0600). That is the realistic answer for headless Linux/WSL; an OS keychain implementation of the same `Keystore` interface can be substituted.
- Revoke = mark the device revoked, generate DK v+1, re-seal it to every remaining approved device, re-wrap owner/recovery copies. History stays readable (it is history); the revoked device never gets v+1. No re-encryption of the past.
- The server rejects duplicate or gapped `(device_id, seq)`, and UPDATE/DELETE on `events` is blocked by trigger, so history is append-only even for the owner.

Protects against: host compromise, a rogue admin, subpoena of the host, token theft by a harness, a lost or stolen device.

**What we do not protect against** (DESIGN §2):

- a compromised client with an unlocked key;
- a user who loses the passphrase **and** the recovery code;
- metadata leakage to the host: sizes, timestamps, device count, and event timing (activity patterns) are visible;
- a device that writes a wrong snapshot (mitigated: snapshots carry the replay hash, peers verify and fall back to full replay);
- the custodial-session mode described in DESIGN §7, if you opt in: the gateway operator can read the soul for the life of the session.

**Recovery code: it is shown once at creation and never stored. If you lose both the owner passphrase and the recovery code, the soul is gone. There is no reset.**

## License

MIT, see [LICENSE](LICENSE).
