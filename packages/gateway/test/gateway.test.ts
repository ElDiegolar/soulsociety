import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ARGON2_TEST,
  HttpStore,
  MemoryKeystore,
  MemoryStore,
  SoulClient,
  StoreError,
  makeEvent,
  toWire,
  type EventRecord,
  type Scope,
} from '@soulsociety/core';
import { createApp, SlidingWindow, type GatewayApp } from '../src/app.js';

const BASE = 'http://gateway.test';

let tmp: string;
let store: MemoryStore;
let app: GatewayApp;

beforeEach(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'ss-gateway-'));
  store = new MemoryStore();
  app = createApp({ store });
});
afterEach(async () => {
  await fs.rm(tmp, { recursive: true, force: true });
});

const fetchImpl: typeof fetch = async (input, init) => app.request(input as string | Request, init);

function opts(s: MemoryStore | HttpStore, sub: string) {
  return { store: s, keystore: new MemoryKeystore(), dataDir: path.join(tmp, sub), argon2: ARGON2_TEST, devicePassphrase: '' };
}

async function makeSoul(sub: string, name = 'kai') {
  return SoulClient.create(opts(store, sub), { ownerId: 'u1', name, ownerPassphrase: 'owner-pw', deviceLabel: `laptop-${sub}` });
}

function req(pathname: string, token: string | null, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (token) headers.set('authorization', `Bearer ${token}`);
  if (init.body) headers.set('content-type', 'application/json');
  return app.request(`${BASE}${pathname}`, { ...init, headers });
}

const ALL: Scope[] = ['events:read', 'events:append', 'snapshots:read', 'snapshots:write', 'state:read'];

describe('gateway auth', () => {
  it('healthz is open', async () => {
    const r = await app.request(`${BASE}/healthz`);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ ok: true });
  });

  it('401 without a token, with a garbage token, and with a revoked token', async () => {
    const { client: a } = await makeSoul('a');
    expect((await req(`/v1/souls/${a.soulId}/heads`, null)).status).toBe(401);
    expect((await req(`/v1/souls/${a.soulId}/heads`, 'ss_nope')).status).toBe(401);
    expect((await req(`/v1/souls/${a.soulId}/heads`, 'not-even-prefixed')).status).toBe(401);
    const g = await a.createGrant('h', ALL);
    await a.revokeGrant(g.id);
    expect((await req(`/v1/souls/${a.soulId}/heads`, g.token)).status).toBe(401);
  });

  it('403 with the wrong scope', async () => {
    const { client: a } = await makeSoul('a');
    const readOnly = await a.createGrant('ro', ['events:read']);
    const ev = store.events.get(a.soulId)![0]!;
    const next: EventRecord = { ...ev, seq: 3 };
    const r = await req(`/v1/souls/${a.soulId}/events`, readOnly.token, { method: 'POST', body: JSON.stringify(toWire([next])) });
    expect(r.status).toBe(403);
    expect(await r.json()).toMatchObject({ error: 'forbidden' });
    expect((await req(`/v1/souls/${a.soulId}/snapshots/latest`, readOnly.token)).status).toBe(403);
    expect((await req(`/v1/souls/${a.soulId}/heads`, readOnly.token)).status).toBe(200);
  });

  it('soul isolation: a grant for soul A cannot touch soul B', async () => {
    const { client: a } = await makeSoul('a', 'alpha');
    const { client: b } = await makeSoul('b', 'beta');
    const ga = await a.createGrant('h', ALL);
    for (const p of ['/heads', '/events?since=%7B%7D', '/devices', `/devices/${b.deviceId}`, '/snapshots/latest']) {
      const r = await req(`/v1/souls/${b.soulId}${p}`, ga.token);
      expect(r.status, p).toBe(403);
    }
    // cannot append events for B by hitting A's route with B's records
    const evB = store.events.get(b.soulId)![0]!;
    const r = await req(`/v1/souls/${a.soulId}/events`, ga.token, { method: 'POST', body: JSON.stringify(toWire([{ ...evB, seq: 3 }])) });
    expect(r.status).toBe(403);
    // cannot read B's device via A's route
    expect((await req(`/v1/souls/${a.soulId}/devices/${b.deviceId}`, ga.token)).status).toBe(404);
    expect((await store.heads(b.soulId))[b.deviceId]).toBe(2);
  });
});

describe('gateway events', () => {
  it('heads, events and devices round-trip through the wire codec', async () => {
    const { client: a } = await makeSoul('a');
    const g = await a.createGrant('h', ALL);
    const heads = await (await req(`/v1/souls/${a.soulId}/heads`, g.token)).json();
    expect(heads).toEqual({ [a.deviceId]: 2 });

    const evs = await (await req(`/v1/souls/${a.soulId}/events?since=${encodeURIComponent('{}')}&limit=1`, g.token)).json();
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({ soulId: a.soulId, deviceId: a.deviceId, seq: 1 });
    expect(evs[0].ciphertext).toEqual({ $b: expect.any(String) });

    const devs = await (await req(`/v1/souls/${a.soulId}/devices`, g.token)).json();
    expect(devs).toHaveLength(1);
    expect(devs[0].sealedDks['1']).toEqual({ $b: expect.any(String) });

    const dev = await (await req(`/v1/souls/${a.soulId}/devices/${a.deviceId}`, g.token)).json();
    expect(dev.id).toBe(a.deviceId);
    expect((await req(`/v1/souls/${a.soulId}/devices/00000000-0000-0000-0000-000000000000`, g.token)).status).toBe(404);
  });

  it('a gap returns 422, a duplicate 409, malformed 400', async () => {
    const { client: a } = await makeSoul('a');
    const g = await a.createGrant('h', ALL);
    const ev = store.events.get(a.soulId)![0]!;
    const post = (body: unknown) => req(`/v1/souls/${a.soulId}/events`, g.token, { method: 'POST', body: JSON.stringify(toWire(body)) });

    const gap = await post([{ ...ev, seq: 4 }]);
    expect(gap.status).toBe(422);
    expect(await gap.json()).toMatchObject({ error: 'gap' });

    const dup = await post([{ ...ev, seq: 1 }]);
    expect(dup.status).toBe(409);
    expect(await dup.json()).toMatchObject({ error: 'conflict' });

    expect((await post({ not: 'an array' })).status).toBe(400);
    expect((await post([{ soulId: a.soulId }])).status).toBe(400);
    expect((await req(`/v1/souls/${a.soulId}/events?since=notjson`, g.token)).status).toBe(400);

    const ok = await post([{ ...ev, seq: 3 }]);
    expect(ok.status).toBe(204);
    expect((await store.heads(a.soulId))[a.deviceId]).toBe(3);
  });

  it('rejects bodies over the cap with 413', async () => {
    const small = createApp({ store, maxBodyBytes: 64 });
    const { client: a } = await makeSoul('a');
    const g = await a.createGrant('h', ALL);
    const r = await small.request(`${BASE}/v1/souls/${a.soulId}/events`, {
      method: 'POST',
      headers: { authorization: `Bearer ${g.token}`, 'content-type': 'application/json' },
      body: JSON.stringify(toWire([store.events.get(a.soulId)![0]!])),
    });
    expect(r.status).toBe(413);
  });

  it('rate limits per token with a sliding window', async () => {
    const limited = createApp({ store, rateLimit: { max: 3, windowMs: 60_000 } });
    const { client: a } = await makeSoul('a');
    const g1 = await a.createGrant('one', ALL);
    const g2 = await a.createGrant('two', ALL);
    const hit = (t: string) => limited.request(`${BASE}/v1/souls/${a.soulId}/heads`, { headers: { authorization: `Bearer ${t}` } });
    for (let i = 0; i < 3; i++) expect((await hit(g1.token)).status).toBe(200);
    const r = await hit(g1.token);
    expect(r.status).toBe(429);
    expect(r.headers.get('retry-after')).toMatch(/^\d+$/);
    expect((await hit(g2.token)).status).toBe(200); // other token unaffected

    const w = new SlidingWindow(2, 1000);
    expect(w.hit('k', 0)).toBe(0);
    expect(w.hit('k', 1)).toBe(0);
    expect(w.hit('k', 2)).toBeGreaterThan(0);
    expect(w.hit('k', 1001)).toBe(0); // first hit slid out of the window
  });
});

describe('HttpStore + SoulClient through the gateway', () => {
  it('a second device syncs via HttpStore and replays to the same hash; snapshots round-trip', async () => {
    // Owner side: direct store. Create the soul and enrol a second device (owner operations).
    const { client: a, result } = await makeSoul('a');
    const b = await SoulClient.enrol(opts(store, 'b'), result.soulId, 'harness-host');
    await a.approveDevice(b.deviceId);
    const grant = await a.createGrant('harness', ALL);

    // Harness side: same device secrets, but every Store call goes over HTTP with the grant.
    const bKeystore = (b as unknown as { opts: { keystore: MemoryKeystore } }).opts.keystore;
    const http = new HttpStore({ baseUrl: BASE, token: grant.token, soulId: result.soulId, fetchImpl });
    const bh = await SoulClient.open({ ...opts(http, 'b'), keystore: bKeystore }, result.soulId, b.deviceId);
    expect(await bh.activate()).toBe(true); // getDevice over HTTP, opens sealed DK

    await a.append(makeEvent('task.completed', { taskId: 't1', title: 'first', witnessed: true }));
    await a.sync();
    expect((await bh.sync()).pulled).toBe(3); // soul.created, device.enrolled(a), task.completed
    await bh.append(makeEvent('note', { text: 'from the relay' }));
    await bh.sync();
    await a.sync();

    const sa = await a.state();
    const sb = await bh.state();
    expect(sa.replayHash).toBe(sb.replayHash);
    expect(sa.counts['note']).toBe(1);
    expect(Object.keys(sa.devices).sort()).toEqual([a.deviceId, b.deviceId].sort());

    // Snapshots via HTTP, verified on both sides.
    const snap = await bh.putSnapshot();
    expect(snap.replayHash).toBe(sa.replayHash);
    expect((await a.verifiedSnapshot())?.replayHash).toBe(sa.replayHash);
    expect((await bh.verifiedSnapshot())?.replayHash).toBe(sa.replayHash);
    expect((await store.latestSnapshot(result.soulId))?.deviceId).toBe(b.deviceId);

    // Second push is a no-op (heads are consistent).
    expect(await bh.push()).toBe(0);
  });

  it('HttpStore maps gateway errors to StoreError codes and refuses owner operations locally', async () => {
    const { client: a } = await makeSoul('a');
    const g = await a.createGrant('h', ALL);
    const http = new HttpStore({ baseUrl: BASE, token: g.token, soulId: a.soulId, fetchImpl });
    const ev = store.events.get(a.soulId)![0]!;
    await expect(http.appendEvents([{ ...ev, seq: 5 }])).rejects.toMatchObject({ code: 'gap' });
    await expect(http.appendEvents([{ ...ev, seq: 1 }])).rejects.toMatchObject({ code: 'conflict' });
    await expect(http.heads('some-other-soul')).rejects.toMatchObject({ code: 'forbidden' });
    expect(await http.getDevice('missing')).toBeNull();

    const bad = new HttpStore({ baseUrl: BASE, token: 'ss_invalid', soulId: a.soulId, fetchImpl });
    await expect(bad.heads(a.soulId)).rejects.toMatchObject({ code: 'forbidden' });

    const down = new HttpStore({
      baseUrl: BASE,
      token: g.token,
      soulId: a.soulId,
      fetchImpl: () => Promise.reject(new Error('ECONNREFUSED')),
    });
    await expect(down.heads(a.soulId)).rejects.toMatchObject({ code: 'io' });

    await expect(http.createGrant()).rejects.toBeInstanceOf(StoreError);
    await expect(http.getSoul()).rejects.toMatchObject({ code: 'forbidden' });
  });
});
