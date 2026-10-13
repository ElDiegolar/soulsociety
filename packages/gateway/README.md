# @soulsociety/gateway

The ZK relay from DESIGN §7. A small Hono app that lets a _device-mode_ harness (one that holds its
own sealed data key) push and pull ciphertext without ever touching Supabase credentials. The
gateway validates a harness grant token, checks the soul and scope, and forwards to a `Store`
constructed with the service-role key. It never sees plaintext and cannot create souls, mint grants,
approve/revoke devices or rotate keys: those stay on the owner's authenticated Supabase path.

## Routes

All soul routes require `Authorization: Bearer ss_...` (a grant minted by `SoulClient.createGrant`)
whose grant belongs to `:soulId`. Bytes travel as `{"$b": "<base64>"}` (see `toWire`/`fromWire` in core).

| Method | Path                                           | Scope             | Returns                                      |
| ------ | ---------------------------------------------- | ----------------- | -------------------------------------------- |
| GET    | `/healthz`                                     | none              | `{ok:true}`                                  |
| GET    | `/v1/souls/:soulId/heads`                      | `events:read`     | `{deviceId: seq}`                            |
| POST   | `/v1/souls/:soulId/events`                     | `events:append`   | 204; 409 conflict, 422 gap, 403 forbidden    |
| GET    | `/v1/souls/:soulId/events?since=<json>&limit=` | `events:read`     | `[EventRecord]`                              |
| GET    | `/v1/souls/:soulId/devices`                    | `events:read`     | `[DeviceRecord]` (sealed DKs are ciphertext) |
| GET    | `/v1/souls/:soulId/devices/:id`                | `events:read`     | `DeviceRecord` or 404                        |
| POST   | `/v1/souls/:soulId/snapshots`                  | `snapshots:write` | 204                                          |
| GET    | `/v1/souls/:soulId/snapshots/latest`           | `snapshots:read`  | `SnapshotRecord` or `null`                   |

Errors are `{error, message}` with `error` one of `unauthenticated` (401), `forbidden` (403),
`not_found` (404), `conflict` (409), `payload_too_large` (413), `gap` (422), `rate_limited` (429),
`bad_request` (400), `io` (500). `HttpStore` in core maps these back to `StoreError` codes.

Built-in limits: 600 requests/min per token (in-memory sliding window) and a 1 MiB body cap.

## Run on Node

```sh
npm run build
SUPABASE_URL=https://xyz.supabase.co \
SUPABASE_SERVICE_ROLE_KEY=... \
PORT=8787 \
node packages/gateway/dist/node.js
```

The service-role key lives only in this process. Harnesses point an `HttpStore` at the gateway:

```ts
import { HttpStore, SoulClient } from '@soulsociety/core';
const store = new HttpStore({ baseUrl: 'https://relay.example.com', token: 'ss_...', soulId });
const client = await SoulClient.open({ store, keystore, dataDir, devicePassphrase }, soulId, deviceId);
await client.sync();
```

## Cloudflare Workers (not set up yet)

`src/app.ts` is runtime-agnostic: `createApp({ store })` returns a Hono app whose `fetch` can be
exported as the Worker handler. The deploy path is `wrangler` with a `src/worker.ts` that builds a
`SupabaseStore` from `env.SUPABASE_URL` / `env.SUPABASE_SERVICE_ROLE_KEY` secrets. Two caveats:
`@soulsociety/core` currently uses `Buffer` and `node:crypto`, so the Worker needs the
`nodejs_compat` flag; and the in-memory rate limiter is per isolate, so a Durable Object (or the
Workers rate-limit binding) is the right place for it once there is more than one isolate.

## Tests

```sh
npm run test -w @soulsociety/gateway   # needs `npm run build -w @soulsociety/core` first
```
