import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ARGON2_TEST, CryptoError } from '../src/crypto.js';
import { FileKeystore, MemoryKeystore } from '../src/keystore.js';
import { MemoryStore, StoreError } from '../src/store.js';
import { SoulClient, authenticateGrant } from '../src/soul.js';
import { makeEvent } from '../src/schema.js';
import { DeviceLog } from '../src/log.js';

let tmp: string;
beforeEach(async () => {
  tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'soulsociety-'));
});
afterEach(async () => {
  await fs.rm(tmp, { recursive: true, force: true });
});

function opts(store: MemoryStore, sub: string, keystore = new MemoryKeystore()) {
  return { store, keystore, dataDir: path.join(tmp, sub), argon2: ARGON2_TEST, devicePassphrase: 'device-pw' };
}

describe('SoulClient end to end (MemoryStore)', () => {
  it('creates a soul, enrols a second device, approves it, syncs both ways, replays identically', async () => {
    const store = new MemoryStore();
    const { client: a, result } = await SoulClient.create(opts(store, 'a'), {
      ownerId: 'u1',
      name: 'kai',
      ownerPassphrase: 'owner-pw',
      deviceLabel: 'laptop',
    });
    expect(result.recoveryCode).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){5}-[0-9A-Z]{2}$/);

    // host sees only ciphertext
    const raw = store.events.get(result.soulId)!;
    expect(raw.length).toBe(2);
    expect(Buffer.from(raw[0]!.ciphertext).toString()).not.toContain('kai');

    const b = await SoulClient.enrol(opts(store, 'b'), result.soulId, 'desktop');
    expect(b.isActive).toBe(false);
    await expect(b.append(makeEvent('note', { text: 'x' }))).rejects.toBeInstanceOf(CryptoError);

    await a.approveDevice(b.deviceId);
    expect(await b.activate()).toBe(true);

    await a.append(makeEvent('task.completed', { taskId: 't1', title: 'first', witnessed: true }));
    await a.sync();
    await b.sync();
    await b.append(makeEvent('draft.approved', { draftId: 'd1', kind: 'email' }));
    await b.sync();
    await a.sync();

    const sa = await a.state();
    const sb = await b.state();
    expect(sa.replayHash).toBe(sb.replayHash);
    expect(sa.xp).toBe(25);
    expect(Object.keys(sa.devices).sort()).toEqual([a.deviceId, b.deviceId].sort());
  });

  it('owner can approve a device with passphrase or recovery code, without any other device', async () => {
    const store = new MemoryStore();
    const { result } = await SoulClient.create(opts(store, 'a'), {
      ownerId: 'u1',
      name: 'kai',
      ownerPassphrase: 'owner-pw',
      deviceLabel: 'laptop',
    });

    const b = await SoulClient.enrol(opts(store, 'b'), result.soulId, 'phone');
    await SoulClient.approveWithOwnerSecret(store, result.soulId, b.deviceId, { passphrase: 'owner-pw' }, ARGON2_TEST);
    expect(await b.activate()).toBe(true);

    const c = await SoulClient.enrol(opts(store, 'c'), result.soulId, 'tablet');
    await expect(
      SoulClient.approveWithOwnerSecret(store, result.soulId, c.deviceId, { passphrase: 'wrong' }, ARGON2_TEST),
    ).rejects.toBeInstanceOf(CryptoError);
    await SoulClient.approveWithOwnerSecret(
      store,
      result.soulId,
      c.deviceId,
      { recoveryCode: result.recoveryCode.toLowerCase() },
      ARGON2_TEST,
    );
    expect(await c.activate()).toBe(true);

    await b.sync();
    await c.sync();
    expect((await b.state()).replayHash).toBe((await c.state()).replayHash);
  });

  it('revoking a device rotates the key: revoked device cannot read new events, history stays readable', async () => {
    const store = new MemoryStore();
    const { client: a, result } = await SoulClient.create(opts(store, 'a'), {
      ownerId: 'u1',
      name: 'kai',
      ownerPassphrase: 'owner-pw',
      deviceLabel: 'laptop',
    });
    const b = await SoulClient.enrol(opts(store, 'b'), result.soulId, 'stolen');
    await a.approveDevice(b.deviceId);
    await b.activate();
    await a.append(makeEvent('note', { text: 'before' }));
    await a.sync();
    await b.sync();
    expect((await b.state()).counts['note']).toBe(1);

    const v = await a.revokeDevice(b.deviceId, 'owner-pw', result.recoveryCode);
    expect(v).toBe(2);
    await a.append(makeEvent('note', { text: 'after' }));
    await a.sync();

    // revoked device: cannot push, cannot decrypt new events
    await expect(b.append(makeEvent('note', { text: 'evil' })).then(() => b.push())).rejects.toBeInstanceOf(StoreError);
    await expect(b.pull()).rejects.toBeInstanceOf(CryptoError);

    // a new device approved afterwards only gets the current key but can still be approved by `a` with all versions
    const c = await SoulClient.enrol(opts(store, 'c'), result.soulId, 'new');
    await a.approveDevice(c.deviceId);
    await c.activate();
    await c.sync();
    const sc = await c.state();
    expect(sc.counts['note']).toBe(2);
    expect(sc.dkVersion).toBe(2);
    expect(sc.devices[b.deviceId]?.revoked).toBe(true);
    await a.sync(); // pick up c's enrol event
    expect(sc.replayHash).toBe((await a.state()).replayHash);
  });

  it('wrong owner passphrase cannot revoke', async () => {
    const store = new MemoryStore();
    const { client: a, result } = await SoulClient.create(opts(store, 'a'), {
      ownerId: 'u1',
      name: 'kai',
      ownerPassphrase: 'owner-pw',
      deviceLabel: 'laptop',
    });
    const b = await SoulClient.enrol(opts(store, 'b'), result.soulId, 'x');
    await a.approveDevice(b.deviceId);
    await expect(a.revokeDevice(b.deviceId, 'nope')).rejects.toBeInstanceOf(CryptoError);
    expect((await store.getDevice(b.deviceId))!.revokedAt).toBeNull();
  });

  it('host rejects gaps and duplicates atomically', async () => {
    const store = new MemoryStore();
    const { client: a, result } = await SoulClient.create(opts(store, 'a'), {
      ownerId: 'u1',
      name: 'kai',
      ownerPassphrase: 'pw',
      deviceLabel: 'l',
    });
    const heads = await store.heads(result.soulId);
    const rec = store.events.get(result.soulId)![0]!;
    await expect(store.appendEvents([{ ...rec, seq: heads[a.deviceId]! + 2 }])).rejects.toMatchObject({ code: 'gap' });
    await expect(store.appendEvents([{ ...rec, seq: 1 }])).rejects.toMatchObject({ code: 'conflict' });
    await expect(
      store.appendEvents([
        { ...rec, seq: heads[a.deviceId]! + 1 },
        { ...rec, seq: heads[a.deviceId]! + 3 },
      ]),
    ).rejects.toMatchObject({ code: 'gap' });
    expect((await store.heads(result.soulId))[a.deviceId]).toBe(heads[a.deviceId]);
  });

  it('snapshots are verified against replay; a forged snapshot is rejected', async () => {
    const store = new MemoryStore();
    const { client: a } = await SoulClient.create(opts(store, 'a'), {
      ownerId: 'u1',
      name: 'kai',
      ownerPassphrase: 'pw',
      deviceLabel: 'l',
    });
    await a.append(makeEvent('note', { text: 'x' }));
    const s = await a.putSnapshot();
    const v = await a.verifiedSnapshot();
    expect(v?.replayHash).toBe(s.replayHash);
    // tamper: flip a byte in the stored snapshot
    const snap = store.snapshots.get(a.soulId)![0]!;
    snap.ciphertext[3] = snap.ciphertext[3]! ^ 1;
    expect(await a.verifiedSnapshot()).toBeNull();
  });

  it('grants: token works once minted, respects scopes, expiry and revocation', async () => {
    const store = new MemoryStore();
    const { client: a } = await SoulClient.create(opts(store, 'a'), {
      ownerId: 'u1',
      name: 'kai',
      ownerPassphrase: 'pw',
      deviceLabel: 'l',
    });
    const g = await a.createGrant('claude-code', ['events:read', 'state:read']);
    expect(g.token).toMatch(/^ss_[A-Za-z0-9_-]{43}$/);
    expect(await authenticateGrant(store, g.token, ['state:read'])).toMatchObject({ soulId: a.soulId });
    expect(await authenticateGrant(store, g.token, ['events:append'])).toBeNull();
    expect(await authenticateGrant(store, g.token + 'x', [])).toBeNull();
    const short = await a.createGrant('tmp', ['state:read'], 1e-8); // ~0.9 ms
    await new Promise((r) => setTimeout(r, 20));
    expect(await authenticateGrant(store, short.token, ['state:read'])).toBeNull();
    await a.revokeGrant(g.id);
    expect(await authenticateGrant(store, g.token, ['state:read'])).toBeNull();
  });

  it('FileKeystore round-trips secrets with a passphrase and survives reopen', async () => {
    const store = new MemoryStore();
    const ks = new FileKeystore(path.join(tmp, 'keys'), ARGON2_TEST);
    const o = opts(store, 'a', ks);
    const { client: a, result } = await SoulClient.create(o, { ownerId: 'u1', name: 'kai', ownerPassphrase: 'pw', deviceLabel: 'l' });
    await a.append(makeEvent('note', { text: 'persisted' }));
    const reopened = await SoulClient.open(o, result.soulId, result.deviceId);
    expect((await reopened.state()).counts['note']).toBe(1);
    await expect(SoulClient.open({ ...o, devicePassphrase: 'wrong' }, result.soulId, result.deviceId)).rejects.toBeInstanceOf(CryptoError);
    const st = await fs.stat(path.join(tmp, 'keys', result.soulId, `${result.deviceId}.keys.json`));
    expect(st.mode & 0o777).toBe(0o600);
  });
});

describe('DeviceLog', () => {
  it('recovers from a truncated final line and rejects mid-file corruption', async () => {
    const dir = path.join(tmp, 'logs');
    const log = await DeviceLog.open(dir, 's', 'd');
    await log.append(makeEvent('note', { text: 'one' }));
    await log.append(makeEvent('note', { text: 'two' }));
    await fs.appendFile(log.filePath, '{"seq":3,"event":{"v":1,"ts":"2026-01-01T00:00:00Z","ty');
    const re = await DeviceLog.open(dir, 's', 'd');
    expect(re.head).toBe(2);
    expect((await re.readAll()).length).toBe(2);
    const content = await fs.readFile(log.filePath, 'utf8');
    const lines = content.split('\n').filter(Boolean);
    lines[0] = 'garbage';
    await fs.writeFile(log.filePath, lines.join('\n') + '\n');
    await expect(DeviceLog.open(dir, 's', 'd')).rejects.toThrow(/corrupt/);
  });

  it('serialises concurrent appends with contiguous seqs', async () => {
    const log = await DeviceLog.open(path.join(tmp, 'logs2'), 's', 'd');
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => log.append(makeEvent('note', { text: String(i) }))));
    expect(results.map((r) => r.seq).sort((a, b) => a - b)).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    expect((await log.readAll()).length).toBe(20);
  });
});

describe('concurrency', () => {
  it('parallel append+push calls never race on heads', async () => {
    const store = new MemoryStore();
    const { client: a } = await SoulClient.create(opts(store, 'a'), {
      ownerId: 'u1',
      name: 'kai',
      ownerPassphrase: 'pw',
      deviceLabel: 'l',
    });
    await Promise.all(Array.from({ length: 15 }, (_, i) => a.append(makeEvent('note', { text: `n${i}` })).then(() => a.push())));
    const heads = await store.heads(a.soulId);
    expect(heads[a.deviceId]).toBe(17); // 2 creation events + 15
    expect((await a.state()).counts['note']).toBe(15);
  });
});
