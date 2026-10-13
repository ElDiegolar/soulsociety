/**
 * SoulClient: the client-side brain. Owns keys (via Keystore), the local device log,
 * peer logs, and talks to a Store (host) in ciphertext only.
 *
 * One SoulClient = one (soul, device). Everything the host sees goes through encrypt().
 */
import { randomUUID } from 'node:crypto';
import {
  ARGON2_DEFAULT,
  type Argon2Params,
  bindingAad,
  CryptoError,
  decryptPayload,
  deriveKey,
  encryptPayload,
  fromUtf8,
  hash,
  newDataKey,
  newDeviceKeypair,
  newRecoveryCode,
  newSalt,
  normaliseRecoveryCode,
  openSealed,
  randomBytes,
  sealToDevice,
  unwrapKey,
  utf8,
  wrapKey,
  b64,
} from './crypto.js';
import { DeviceLog, PeerLog, type LogEntry } from './log.js';
import { type Keystore, type DeviceSecrets } from './keystore.js';
import { emptyState, replay, type ReplayEntry, type SoulState } from './replay.js';
import { makeEvent, validateEvent, type EventEnvelope } from './schema.js';
import { ALL_SCOPES, type EventRecord, type Scope, type Store, StoreError } from './store.js';

export interface SoulClientOptions {
  store: Store;
  keystore: Keystore;
  dataDir: string;
  argon2?: Argon2Params;
  /** Device passphrase for the keystore; may be '' for MemoryKeystore. */
  devicePassphrase: string;
}

export interface CreateSoulResult {
  soulId: string;
  deviceId: string;
  recoveryCode: string;
}

export class SoulClient {
  private secrets!: DeviceSecrets;
  private log!: DeviceLog;
  private readonly argon2: Argon2Params;
  /** Serialises host round-trips so concurrent callers (e.g. parallel MCP tool calls) never race on heads. */
  private chain: Promise<unknown> = Promise.resolve();

  private constructor(
    private readonly opts: SoulClientOptions,
    public readonly soulId: string,
    public readonly deviceId: string,
  ) {
    this.argon2 = opts.argon2 ?? ARGON2_DEFAULT;
  }

  // ---------------- lifecycle ----------------

  /**
   * Create a brand-new soul on this device. The owner passphrase derives RK; the device becomes
   * the first approved device. Returns the recovery code: show it once, never store it.
   * `name` is encrypted into the first event; only `hostLabel` (default 'soul') is visible to the host.
   */
  static async create(
    opts: SoulClientOptions,
    params: { ownerId: string; name: string; ownerPassphrase: string; deviceLabel: string; hostLabel?: string },
  ): Promise<{ client: SoulClient; result: CreateSoulResult }> {
    const soulId = randomUUID();
    const deviceId = randomUUID();
    const argon2 = opts.argon2 ?? ARGON2_DEFAULT;

    const dk = await newDataKey();
    const salt = await newSalt();
    const rk = await deriveKey(params.ownerPassphrase, salt, argon2);
    const recoveryCode = await newRecoveryCode();
    const recoveryKey = await deriveKey(normaliseRecoveryCode(recoveryCode), salt, argon2);

    const kp = await newDeviceKeypair();

    await opts.store.createSoul({
      id: soulId,
      ownerId: params.ownerId,
      // The host sees only a neutral label; the soul's real name lives in the encrypted soul.created event.
      name: params.hostLabel ?? 'soul',
      salt,
      wrappedDkOwner: await wrapKey(dk, rk),
      wrappedDkRecovery: await wrapKey(dk, recoveryKey),
      dkVersion: 1,
    });
    await opts.store.createDevice({ id: deviceId, soulId, label: params.deviceLabel, publicKey: kp.publicKey });
    await opts.store.approveDevice(deviceId, { 1: await sealToDevice(dk, kp.publicKey) });

    const client = new SoulClient(opts, soulId, deviceId);
    client.secrets = { soulId, deviceId, keypair: kp, dataKeys: { 1: dk } };
    await opts.keystore.save(client.secrets, opts.devicePassphrase);
    client.log = await DeviceLog.open(opts.dataDir, soulId, deviceId);

    await client.append(makeEvent('soul.created', { name: params.name }));
    await client.append(makeEvent('device.enrolled', { deviceId, label: params.deviceLabel }));
    await client.push();

    return { client, result: { soulId, deviceId, recoveryCode } };
  }

  /** Open an existing (soul, device) whose secrets are in the keystore. */
  static async open(opts: SoulClientOptions, soulId: string, deviceId: string): Promise<SoulClient> {
    const client = new SoulClient(opts, soulId, deviceId);
    client.secrets = await opts.keystore.load(soulId, deviceId, opts.devicePassphrase);
    client.log = await DeviceLog.open(opts.dataDir, soulId, deviceId);
    return client;
  }

  /**
   * Enrol this machine as a new device for an existing soul. Creates a pending device record.
   * Someone with the DK (an approved device, or the owner via passphrase/recovery) must approve it.
   */
  static async enrol(opts: SoulClientOptions, soulId: string, deviceLabel: string): Promise<SoulClient> {
    const soul = await opts.store.getSoul(soulId);
    if (!soul) throw new StoreError('soul not found', 'not_found');
    const deviceId = randomUUID();
    const kp = await newDeviceKeypair();
    await opts.store.createDevice({ id: deviceId, soulId, label: deviceLabel, publicKey: kp.publicKey });
    const client = new SoulClient(opts, soulId, deviceId);
    client.secrets = { soulId, deviceId, keypair: kp, dataKeys: {} };
    await opts.keystore.save(client.secrets, opts.devicePassphrase);
    client.log = await DeviceLog.open(opts.dataDir, soulId, deviceId);
    return client;
  }

  /** After approval: fetch sealed DKs, open them, persist. Idempotent. */
  async activate(): Promise<boolean> {
    const dev = await this.opts.store.getDevice(this.deviceId);
    if (!dev || !dev.approvedAt) return false;
    let changed = false;
    for (const [v, sealed] of Object.entries(dev.sealedDks)) {
      const ver = Number(v);
      if (this.secrets.dataKeys[ver]) continue;
      this.secrets.dataKeys[ver] = await openSealed(sealed, this.secrets.keypair);
      changed = true;
    }
    if (changed) await this.opts.keystore.save(this.secrets, this.opts.devicePassphrase);
    if (changed && Object.keys(this.secrets.dataKeys).length && this.log.head === 0) {
      await this.append(makeEvent('device.enrolled', { deviceId: this.deviceId, label: dev.label }));
      await this.push();
    }
    return Object.keys(this.secrets.dataKeys).length > 0;
  }

  get isActive(): boolean {
    return Object.keys(this.secrets.dataKeys).length > 0;
  }

  // ---------------- device management (needs DK) ----------------

  /** Approve a pending device by sealing every DK version this device holds to it. */
  async approveDevice(pendingDeviceId: string): Promise<void> {
    this.requireActive();
    const dev = await this.opts.store.getDevice(pendingDeviceId);
    if (!dev || dev.soulId !== this.soulId) throw new StoreError('device not found in this soul', 'not_found');
    if (dev.revokedAt) throw new StoreError('device is revoked', 'forbidden');
    const sealed: Record<number, Uint8Array> = {};
    for (const [v, dk] of Object.entries(this.secrets.dataKeys)) sealed[Number(v)] = await sealToDevice(dk, dev.publicKey);
    await this.opts.store.approveDevice(pendingDeviceId, sealed);
  }

  /**
   * Revoke a device and rotate the data key. History stays readable to everyone who had the old key;
   * everything after this point is encrypted under the new key, which the revoked device never gets.
   * Requires the owner passphrase to re-wrap the owner/recovery copies.
   */
  async revokeDevice(deviceId: string, ownerPassphrase: string, recoveryCode?: string): Promise<number> {
    this.requireActive();
    if (deviceId === this.deviceId) throw new CryptoError('cannot revoke the current device from itself');
    const soul = await this.opts.store.getSoul(this.soulId);
    if (!soul) throw new StoreError('soul not found', 'not_found');

    const rk = await deriveKey(ownerPassphrase, soul.salt, this.argon2);
    // prove the passphrase before touching anything
    await unwrapKey(soul.wrappedDkOwner, rk);

    await this.opts.store.revokeDevice(deviceId);
    const newVersion = soul.dkVersion + 1;
    const dk = await newDataKey();

    const wrappedDkRecovery = recoveryCode
      ? await wrapKey(dk, await deriveKey(normaliseRecoveryCode(recoveryCode), soul.salt, this.argon2))
      : soul.wrappedDkRecovery; // keep old-version recovery wrap if the code wasn't supplied; owner can refresh later
    await this.opts.store.updateSoulKeys(this.soulId, { wrappedDkOwner: await wrapKey(dk, rk), wrappedDkRecovery, dkVersion: newVersion });

    for (const d of await this.opts.store.listDevices(this.soulId)) {
      if (d.revokedAt || !d.approvedAt) continue;
      await this.opts.store.addSealedDk(d.id, newVersion, await sealToDevice(dk, d.publicKey));
    }
    this.secrets.dataKeys[newVersion] = dk;
    await this.opts.keystore.save(this.secrets, this.opts.devicePassphrase);

    await this.append(makeEvent('device.revoked', { deviceId }));
    await this.append(makeEvent('key.rotated', { dkVersion: newVersion }));
    await this.push();
    return newVersion;
  }

  /** Owner-side bootstrap: unlock DK with passphrase (or recovery code) and seal it to a pending device. */
  static async approveWithOwnerSecret(
    store: Store,
    soulId: string,
    pendingDeviceId: string,
    secret: { passphrase: string } | { recoveryCode: string },
    argon2: Argon2Params = ARGON2_DEFAULT,
  ): Promise<void> {
    const soul = await store.getSoul(soulId);
    if (!soul) throw new StoreError('soul not found', 'not_found');
    const dev = await store.getDevice(pendingDeviceId);
    if (!dev || dev.soulId !== soulId) throw new StoreError('device not found in this soul', 'not_found');
    const dk =
      'passphrase' in secret
        ? await unwrapKey(soul.wrappedDkOwner, await deriveKey(secret.passphrase, soul.salt, argon2))
        : await unwrapKey(soul.wrappedDkRecovery, await deriveKey(normaliseRecoveryCode(secret.recoveryCode), soul.salt, argon2));
    // Owner wrap only ever holds the latest DK; older versions must come from an approved device.
    await store.approveDevice(pendingDeviceId, { [soul.dkVersion]: await sealToDevice(dk, dev.publicKey) });
  }

  // ---------------- events ----------------

  async append(event: EventEnvelope): Promise<LogEntry> {
    this.requireActive();
    return this.log.append(validateEvent(event));
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.chain.then(fn, fn);
    this.chain = p.then(
      () => undefined,
      () => undefined,
    );
    return p;
  }

  /** Push local entries the host doesn't have yet. Returns count pushed. */
  push(): Promise<number> {
    return this.serial(() => this.pushUnlocked());
  }

  private async pushUnlocked(): Promise<number> {
    this.requireActive();
    const heads = await this.opts.store.heads(this.soulId);
    const from = (heads[this.deviceId] ?? 0) + 1;
    const pending = await this.log.readAll(from);
    if (pending.length === 0) return 0;
    const dkVersion = this.currentDkVersion();
    const dk = this.secrets.dataKeys[dkVersion]!;
    const records: EventRecord[] = [];
    for (const entry of pending) {
      const aad = bindingAad({ soulId: this.soulId, deviceId: this.deviceId, seq: entry.seq, dkVersion });
      const ct = await encryptPayload(utf8(JSON.stringify(entry.event)), dk, aad);
      records.push({
        soulId: this.soulId,
        deviceId: this.deviceId,
        seq: entry.seq,
        dkVersion,
        nonce: ct.nonce,
        ciphertext: ct.ciphertext,
        createdAt: '',
      });
    }
    await this.opts.store.appendEvents(records);
    return records.length;
  }

  /** Pull other devices' entries, decrypt, persist into peer logs. Returns count pulled. */
  pull(): Promise<number> {
    return this.serial(() => this.pullUnlocked());
  }

  private async pullUnlocked(): Promise<number> {
    this.requireActive();
    const since: Record<string, number> = {};
    for (const d of await this.opts.store.listDevices(this.soulId)) {
      if (d.id === this.deviceId) continue;
      since[d.id] = await (await PeerLog.open(this.opts.dataDir, this.soulId, d.id)).head();
    }
    since[this.deviceId] = Number.MAX_SAFE_INTEGER; // never pull our own
    let total = 0;
    for (;;) {
      const batch = await this.opts.store.eventsSince(this.soulId, since, 500);
      if (batch.length === 0) break;
      const byDevice = new Map<string, LogEntry[]>();
      for (const r of batch) {
        const dk = this.secrets.dataKeys[r.dkVersion];
        if (!dk) throw new CryptoError(`no data key v${r.dkVersion}; this device may be revoked or not yet rotated`);
        const aad = bindingAad({ soulId: r.soulId, deviceId: r.deviceId, seq: r.seq, dkVersion: r.dkVersion });
        const plain = await decryptPayload({ nonce: r.nonce, ciphertext: r.ciphertext }, dk, aad);
        const event = validateEvent(JSON.parse(fromUtf8(plain)));
        byDevice.set(r.deviceId, [...(byDevice.get(r.deviceId) ?? []), { seq: r.seq, event }]);
      }
      for (const [deviceId, entries] of byDevice) {
        const peer = await PeerLog.open(this.opts.dataDir, this.soulId, deviceId);
        total += await peer.appendMany(entries);
        since[deviceId] = Math.max(since[deviceId] ?? 0, ...entries.map((e) => e.seq));
      }
    }
    return total;
  }

  sync(): Promise<{ pushed: number; pulled: number }> {
    return this.serial(async () => {
      const pushed = await this.pushUnlocked();
      const pulled = await this.pullUnlocked();
      return { pushed, pulled };
    });
  }

  // ---------------- state ----------------

  async allEntries(): Promise<ReplayEntry[]> {
    const out: ReplayEntry[] = [];
    for (const e of await this.log.readAll()) out.push({ ...e, deviceId: this.deviceId });
    for (const d of await this.opts.store.listDevices(this.soulId)) {
      if (d.id === this.deviceId) continue;
      const peer = await PeerLog.open(this.opts.dataDir, this.soulId, d.id);
      for (const e of await peer.readAll()) out.push({ ...e, deviceId: d.id });
    }
    return out;
  }

  async state(): Promise<SoulState> {
    return replay(await this.allEntries(), emptyState());
  }

  /** Encrypt and upload a snapshot of current state (a cache; replay remains the truth). */
  async putSnapshot(): Promise<SoulState> {
    this.requireActive();
    const state = await this.state();
    const dkVersion = this.currentDkVersion();
    const aad = utf8(`soulsociety/snapshot/v1|${this.soulId}|${this.deviceId}|${state.replayHash}|${dkVersion}`);
    const ct = await encryptPayload(utf8(JSON.stringify(state)), this.secrets.dataKeys[dkVersion]!, aad);
    await this.opts.store.putSnapshot({
      soulId: this.soulId,
      deviceId: this.deviceId,
      through: state.heads,
      replayHash: state.replayHash,
      dkVersion,
      nonce: ct.nonce,
      ciphertext: ct.ciphertext,
    });
    return state;
  }

  /** Load the latest snapshot and verify it against a local replay. Returns null if absent or mismatched. */
  async verifiedSnapshot(): Promise<SoulState | null> {
    const snap = await this.opts.store.latestSnapshot(this.soulId);
    if (!snap) return null;
    const dk = this.secrets.dataKeys[snap.dkVersion];
    if (!dk) return null;
    const aad = utf8(`soulsociety/snapshot/v1|${snap.soulId}|${snap.deviceId}|${snap.replayHash}|${snap.dkVersion}`);
    let state: SoulState;
    try {
      state = JSON.parse(fromUtf8(await decryptPayload({ nonce: snap.nonce, ciphertext: snap.ciphertext }, dk, aad))) as SoulState;
    } catch {
      return null;
    }
    const local = await this.state();
    return local.replayHash === state.replayHash ? state : null;
  }

  // ---------------- grants ----------------

  /** Mint a bearer token for a harness. The token is returned once; only its hash is stored. */
  async createGrant(
    label: string,
    scopes: Scope[] = ['events:read', 'events:append', 'state:read'],
    ttlDays?: number,
  ): Promise<{ id: string; token: string }> {
    for (const s of scopes) if (!ALL_SCOPES.includes(s)) throw new StoreError(`unknown scope ${s}`, 'forbidden');
    const raw = await randomBytes(32);
    const token = `ss_${b64(raw).replace(/[+/=]/g, (c) => ({ '+': '-', '/': '_', '=': '' })[c]!)}`;
    const id = randomUUID();
    await this.opts.store.createGrant({
      id,
      soulId: this.soulId,
      label,
      scopes,
      tokenHash: await hash(utf8(token)),
      expiresAt: ttlDays ? new Date(Date.now() + ttlDays * 86400_000).toISOString() : null,
    });
    return { id, token };
  }

  async revokeGrant(id: string): Promise<void> {
    await this.opts.store.revokeGrant(id);
  }

  // ---------------- internals ----------------

  private requireActive(): void {
    if (!this.isActive) throw new CryptoError('device not activated: no data key (pending approval?)');
  }

  private currentDkVersion(): number {
    return Math.max(...Object.keys(this.secrets.dataKeys).map(Number));
  }
}

/** Verify a harness token against the store. Returns the grant if valid, else null. */
export async function authenticateGrant(store: Store, token: string, needed: Scope[]): Promise<{ soulId: string; scopes: Scope[] } | null> {
  if (!token.startsWith('ss_')) return null;
  const g = await store.findGrantByTokenHash(await hash(utf8(token)));
  if (!g || g.revokedAt) return null;
  if (g.expiresAt && new Date(g.expiresAt).getTime() < Date.now()) return null;
  for (const s of needed) if (!g.scopes.includes(s)) return null;
  return { soulId: g.soulId, scopes: g.scopes };
}
