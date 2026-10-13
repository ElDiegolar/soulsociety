/**
 * ZK relay gateway (DESIGN §7): a pure Hono app that forwards ciphertext between device-mode
 * harnesses and the Store. Portable: no Node-only APIs here, so the same app runs on
 * @hono/node-server (src/node.ts) and on Cloudflare Workers.
 *
 * Every route under /v1/souls/:soulId requires a harness grant (`Authorization: Bearer ss_...`)
 * that belongs to *that* soul and carries the needed scope. Owner operations (soul creation,
 * grants, device approval/revocation, key rotation) are deliberately not exposed.
 */
import { Hono, type Context, type MiddlewareHandler } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import {
  authenticateGrant,
  fromWire,
  toWire,
  StoreError,
  type EventRecord,
  type Scope,
  type SnapshotRecord,
  type Store,
} from '@soulsociety/core';

export interface GatewayOptions {
  store: Store;
  /** Sliding-window per-token limit. Default 600 requests / 60 s. */
  rateLimit?: { max: number; windowMs: number } | false;
  /** Request body cap in bytes. Default 1 MiB. */
  maxBodyBytes?: number;
}

type Auth = { soulId: string; scopes: Scope[]; token: string };
type Env = { Variables: { auth: Auth } };

const STATUS: Record<StoreError['code'], number> = { conflict: 409, gap: 422, not_found: 404, forbidden: 403, io: 500 };

function fail(c: Context, status: 400 | 401 | 403 | 404 | 409 | 413 | 422 | 429 | 500, error: string, message: string) {
  return c.json({ error, message }, status);
}

// ---------------- rate limiting ----------------

/** Per-key sliding window kept in memory. Good enough for one process / one isolate. */
export class SlidingWindow {
  private readonly hits = new Map<string, number[]>();
  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}

  /** Returns 0 if allowed, else the ms to wait before the next slot opens. */
  hit(key: string, now = Date.now()): number {
    const cutoff = now - this.windowMs;
    let list = this.hits.get(key);
    if (list) {
      let i = 0;
      while (i < list.length && list[i]! <= cutoff) i++;
      if (i) list.splice(0, i);
    } else {
      list = [];
      this.hits.set(key, list);
    }
    if (list.length >= this.max) return list[0]! + this.windowMs - now;
    list.push(now);
    if (this.hits.size > 10_000) this.sweep(cutoff);
    return 0;
  }

  private sweep(cutoff: number): void {
    for (const [k, v] of this.hits) if (!v.length || v[v.length - 1]! <= cutoff) this.hits.delete(k);
  }
}

// ---------------- auth ----------------

function bearer(c: Context): string | null {
  const h = c.req.header('authorization') ?? '';
  const m = /^Bearer\s+(\S+)$/i.exec(h);
  return m ? m[1]! : null;
}

function requireScope(store: Store, limiter: SlidingWindow | null, ...needed: Scope[]): MiddlewareHandler<Env> {
  return async (c, next) => {
    const token = bearer(c);
    if (!token) return fail(c, 401, 'unauthenticated', 'missing bearer token');
    if (limiter) {
      const wait = limiter.hit(token);
      if (wait > 0) {
        c.header('Retry-After', String(Math.ceil(wait / 1000)));
        return fail(c, 429, 'rate_limited', 'too many requests');
      }
    }
    const grant = await authenticateGrant(store, token, []);
    if (!grant) return fail(c, 401, 'unauthenticated', 'invalid, expired or revoked token');
    if (grant.soulId !== c.req.param('soulId')) return fail(c, 403, 'forbidden', 'token is not valid for this soul');
    for (const s of needed) if (!grant.scopes.includes(s)) return fail(c, 403, 'forbidden', `missing scope ${s}`);
    c.set('auth', { ...grant, token });
    await next();
  };
}

// ---------------- validation ----------------

const isStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0;
const isBytes = (v: unknown): v is Uint8Array => v instanceof Uint8Array && v.length > 0;

function parseEvents(raw: unknown, soulId: string): EventRecord[] {
  const arr = fromWire(raw);
  if (!Array.isArray(arr)) throw new Bad('body must be an array of events');
  if (arr.length > 1000) throw new Bad('too many events in one batch (max 1000)');
  return arr.map((e, i) => {
    const o = (e ?? {}) as Record<string, unknown>;
    if (
      !isStr(o.soulId) ||
      !isStr(o.deviceId) ||
      !isInt(o.seq) ||
      o.seq < 1 ||
      !isInt(o.dkVersion) ||
      !isBytes(o.nonce) ||
      !isBytes(o.ciphertext)
    ) {
      throw new Bad(`event[${i}] is malformed`);
    }
    if (o.soulId !== soulId) throw new Forbidden(`event[${i}] belongs to another soul`);
    return {
      soulId: o.soulId,
      deviceId: o.deviceId,
      seq: o.seq,
      dkVersion: o.dkVersion,
      nonce: o.nonce,
      ciphertext: o.ciphertext,
      createdAt: '',
    };
  });
}

function parseSnapshot(raw: unknown, soulId: string): Omit<SnapshotRecord, 'createdAt'> {
  const o = (fromWire(raw) ?? {}) as Record<string, unknown>;
  if (
    !isStr(o.soulId) ||
    !isStr(o.deviceId) ||
    !isStr(o.replayHash) ||
    !isInt(o.dkVersion) ||
    !isBytes(o.nonce) ||
    !isBytes(o.ciphertext)
  ) {
    throw new Bad('snapshot is malformed');
  }
  if (!o.through || typeof o.through !== 'object' || Array.isArray(o.through) || !Object.values(o.through as object).every(isInt)) {
    throw new Bad('snapshot.through must be {deviceId: seq}');
  }
  if (o.soulId !== soulId) throw new Forbidden('snapshot belongs to another soul');
  return {
    soulId: o.soulId,
    deviceId: o.deviceId,
    through: o.through as Record<string, number>,
    replayHash: o.replayHash,
    dkVersion: o.dkVersion,
    nonce: o.nonce,
    ciphertext: o.ciphertext,
  };
}

function parseSince(s: string | undefined): Record<string, number> {
  if (s === undefined || s === '') return {};
  let v: unknown;
  try {
    v = JSON.parse(s);
  } catch {
    throw new Bad('since must be JSON');
  }
  if (!v || typeof v !== 'object' || Array.isArray(v) || !Object.values(v).every(isInt)) throw new Bad('since must be {deviceId: seq}');
  return v as Record<string, number>;
}

function parseLimit(s: string | undefined): number | undefined {
  if (s === undefined || s === '') return undefined;
  const n = Number(s);
  if (!Number.isInteger(n) || n < 1) throw new Bad('limit must be a positive integer');
  return Math.min(n, 1000);
}

class Bad extends Error {}
class Forbidden extends Error {}

// ---------------- app ----------------

export function createApp(opts: GatewayOptions): Hono<Env> {
  const { store } = opts;
  const rl = opts.rateLimit === false ? null : (opts.rateLimit ?? { max: 600, windowMs: 60_000 });
  const limiter = rl ? new SlidingWindow(rl.max, rl.windowMs) : null;
  const maxBody = opts.maxBodyBytes ?? 1024 * 1024;

  const app = new Hono<Env>();

  app.use('*', bodyLimit({ maxSize: maxBody, onError: (c) => fail(c, 413, 'payload_too_large', `body exceeds ${maxBody} bytes`) }));

  app.onError((err, c) => {
    if (err instanceof StoreError) return fail(c, STATUS[err.code] as 403 | 404 | 409 | 422 | 500, err.code, err.message);
    if (err instanceof Bad) return fail(c, 400, 'bad_request', err.message);
    if (err instanceof Forbidden) return fail(c, 403, 'forbidden', err.message);
    if (err instanceof SyntaxError) return fail(c, 400, 'bad_request', 'invalid JSON body');
    console.error('gateway error', err);
    return fail(c, 500, 'io', 'internal error');
  });
  app.notFound((c) => fail(c, 404, 'not_found', 'no such route'));

  app.get('/healthz', (c) => c.json({ ok: true }));

  const souls = new Hono<Env>();
  const read = requireScope(store, limiter, 'events:read');

  souls.get('/heads', read, async (c) => c.json(await store.heads(c.get('auth').soulId)));

  souls.post('/events', requireScope(store, limiter, 'events:append'), async (c) => {
    const events = parseEvents(await c.req.json(), c.get('auth').soulId);
    await store.appendEvents(events);
    return c.body(null, 204);
  });

  souls.get('/events', read, async (c) => {
    const soulId = c.get('auth').soulId;
    const since = parseSince(c.req.query('since'));
    const limit = parseLimit(c.req.query('limit'));
    return c.json(toWire(await store.eventsSince(soulId, since, limit)));
  });

  souls.get('/devices', read, async (c) => c.json(toWire(await store.listDevices(c.get('auth').soulId))));

  souls.get('/devices/:id', read, async (c) => {
    const d = await store.getDevice(c.req.param('id'));
    if (!d || d.soulId !== c.get('auth').soulId) return fail(c, 404, 'not_found', 'device not found in this soul');
    return c.json(toWire(d));
  });

  souls.post('/snapshots', requireScope(store, limiter, 'snapshots:write'), async (c) => {
    await store.putSnapshot(parseSnapshot(await c.req.json(), c.get('auth').soulId));
    return c.body(null, 204);
  });

  souls.get('/snapshots/latest', requireScope(store, limiter, 'snapshots:read'), async (c) => {
    return c.json(toWire(await store.latestSnapshot(c.get('auth').soulId)));
  });

  app.route('/v1/souls/:soulId', souls);
  return app;
}

export type GatewayApp = ReturnType<typeof createApp>;
