/**
 * Host-side store interface. The host only ever sees ciphertext.
 * Two implementations: MemoryStore (tests, offline), SupabaseStore (production).
 */

export interface SoulRecord {
  id: string;
  ownerId: string;
  name: string; // host-visible label only (default 'soul'); the real name is inside the encrypted log
  salt: Uint8Array; // Argon2id salt for the root key
  wrappedDkOwner: Uint8Array; // DK wrapped by RK (latest version)
  wrappedDkRecovery: Uint8Array; // DK wrapped by recovery key (latest version)
  dkVersion: number;
  createdAt: string;
}

export interface DeviceRecord {
  id: string;
  soulId: string;
  label: string;
  publicKey: Uint8Array;
  /** Sealed DK per version this device may read. Keyed by dkVersion. */
  sealedDks: Record<number, Uint8Array>;
  approvedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

export interface EventRecord {
  soulId: string;
  deviceId: string;
  seq: number;
  dkVersion: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  createdAt: string;
}

export interface SnapshotRecord {
  soulId: string;
  deviceId: string;
  through: Record<string, number>;
  replayHash: string;
  dkVersion: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  createdAt: string;
}

export interface GrantRecord {
  id: string;
  soulId: string;
  label: string;
  scopes: Scope[];
  tokenHash: Uint8Array;
  expiresAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

export type Scope = 'events:read' | 'events:append' | 'snapshots:read' | 'snapshots:write' | 'state:read';
export const ALL_SCOPES: Scope[] = ['events:read', 'events:append', 'snapshots:read', 'snapshots:write', 'state:read'];

export class StoreError extends Error {
  override name = 'StoreError';
  constructor(
    message: string,
    public readonly code: 'conflict' | 'gap' | 'not_found' | 'forbidden' | 'io' = 'io',
  ) {
    super(message);
  }
}

export interface Store {
  // souls
  createSoul(s: Omit<SoulRecord, 'createdAt'>): Promise<SoulRecord>;
  getSoul(id: string): Promise<SoulRecord | null>;
  listSouls(ownerId: string): Promise<SoulRecord[]>;
  updateSoulKeys(id: string, patch: Pick<SoulRecord, 'wrappedDkOwner' | 'wrappedDkRecovery' | 'dkVersion'>): Promise<void>;

  // devices
  createDevice(d: Omit<DeviceRecord, 'createdAt' | 'approvedAt' | 'revokedAt' | 'sealedDks'>): Promise<DeviceRecord>;
  getDevice(id: string): Promise<DeviceRecord | null>;
  listDevices(soulId: string): Promise<DeviceRecord[]>;
  approveDevice(id: string, sealedDks: Record<number, Uint8Array>): Promise<void>;
  addSealedDk(id: string, dkVersion: number, sealed: Uint8Array): Promise<void>;
  revokeDevice(id: string): Promise<void>;

  // events
  heads(soulId: string): Promise<Record<string, number>>;
  appendEvents(events: EventRecord[]): Promise<void>; // atomic; throws StoreError(conflict|gap)
  eventsSince(soulId: string, since: Record<string, number>, limit?: number): Promise<EventRecord[]>;

  // snapshots
  putSnapshot(s: Omit<SnapshotRecord, 'createdAt'>): Promise<void>;
  latestSnapshot(soulId: string): Promise<SnapshotRecord | null>;

  // grants
  createGrant(g: Omit<GrantRecord, 'createdAt' | 'revokedAt'>): Promise<GrantRecord>;
  listGrants(soulId: string): Promise<GrantRecord[]>;
  revokeGrant(id: string): Promise<void>;
  findGrantByTokenHash(tokenHash: Uint8Array): Promise<GrantRecord | null>;
}

// ---------------- MemoryStore ----------------

export class MemoryStore implements Store {
  souls = new Map<string, SoulRecord>();
  devices = new Map<string, DeviceRecord>();
  events = new Map<string, EventRecord[]>(); // soulId -> events in insertion order
  snapshots = new Map<string, SnapshotRecord[]>();
  grants = new Map<string, GrantRecord>();

  private now(): string {
    return new Date().toISOString();
  }

  async createSoul(s: Omit<SoulRecord, 'createdAt'>): Promise<SoulRecord> {
    if (this.souls.has(s.id)) throw new StoreError('soul exists', 'conflict');
    const rec: SoulRecord = { ...s, createdAt: this.now() };
    this.souls.set(s.id, rec);
    return structuredClone(rec);
  }
  async getSoul(id: string): Promise<SoulRecord | null> {
    const s = this.souls.get(id);
    return s ? structuredClone(s) : null;
  }
  async listSouls(ownerId: string): Promise<SoulRecord[]> {
    return [...this.souls.values()].filter((s) => s.ownerId === ownerId).map((s) => structuredClone(s));
  }
  async updateSoulKeys(id: string, patch: Pick<SoulRecord, 'wrappedDkOwner' | 'wrappedDkRecovery' | 'dkVersion'>): Promise<void> {
    const s = this.souls.get(id);
    if (!s) throw new StoreError('soul not found', 'not_found');
    if (patch.dkVersion < s.dkVersion) throw new StoreError('dkVersion must not decrease', 'conflict');
    Object.assign(s, patch);
  }

  async createDevice(d: Omit<DeviceRecord, 'createdAt' | 'approvedAt' | 'revokedAt' | 'sealedDks'>): Promise<DeviceRecord> {
    if (!this.souls.has(d.soulId)) throw new StoreError('soul not found', 'not_found');
    if (this.devices.has(d.id)) throw new StoreError('device exists', 'conflict');
    const rec: DeviceRecord = { ...d, sealedDks: {}, approvedAt: null, revokedAt: null, createdAt: this.now() };
    this.devices.set(d.id, rec);
    return structuredClone(rec);
  }
  async getDevice(id: string): Promise<DeviceRecord | null> {
    const d = this.devices.get(id);
    return d ? structuredClone(d) : null;
  }
  async listDevices(soulId: string): Promise<DeviceRecord[]> {
    return [...this.devices.values()].filter((d) => d.soulId === soulId).map((d) => structuredClone(d));
  }
  async approveDevice(id: string, sealedDks: Record<number, Uint8Array>): Promise<void> {
    const d = this.devices.get(id);
    if (!d) throw new StoreError('device not found', 'not_found');
    if (d.revokedAt) throw new StoreError('device revoked', 'forbidden');
    d.sealedDks = { ...d.sealedDks, ...sealedDks };
    d.approvedAt = d.approvedAt ?? this.now();
  }
  async addSealedDk(id: string, dkVersion: number, sealed: Uint8Array): Promise<void> {
    const d = this.devices.get(id);
    if (!d) throw new StoreError('device not found', 'not_found');
    if (d.revokedAt) throw new StoreError('device revoked', 'forbidden');
    d.sealedDks[dkVersion] = sealed;
  }
  async revokeDevice(id: string): Promise<void> {
    const d = this.devices.get(id);
    if (!d) throw new StoreError('device not found', 'not_found');
    d.revokedAt = d.revokedAt ?? this.now();
  }

  async heads(soulId: string): Promise<Record<string, number>> {
    const out: Record<string, number> = {};
    for (const e of this.events.get(soulId) ?? []) out[e.deviceId] = Math.max(out[e.deviceId] ?? 0, e.seq);
    return out;
  }
  async appendEvents(events: EventRecord[]): Promise<void> {
    if (events.length === 0) return;
    const soulId = events[0]!.soulId;
    if (!events.every((e) => e.soulId === soulId)) throw new StoreError('mixed souls in batch', 'conflict');
    if (!this.souls.has(soulId)) throw new StoreError('soul not found', 'not_found');
    const heads = await this.heads(soulId);
    const byDevice = new Map<string, EventRecord[]>();
    for (const e of events) {
      const d = this.devices.get(e.deviceId);
      if (!d || d.soulId !== soulId) throw new StoreError('device not in soul', 'forbidden');
      if (!d.approvedAt || d.revokedAt) throw new StoreError('device not approved or revoked', 'forbidden');
      byDevice.set(e.deviceId, [...(byDevice.get(e.deviceId) ?? []), e]);
    }
    // validate the whole batch before writing anything (atomic)
    for (const [deviceId, list] of byDevice) {
      list.sort((a, b) => a.seq - b.seq);
      let head = heads[deviceId] ?? 0;
      for (const e of list) {
        if (e.seq <= head) throw new StoreError(`duplicate seq ${e.seq} for ${deviceId}`, 'conflict');
        if (e.seq !== head + 1) throw new StoreError(`gap: have ${head}, got ${e.seq} for ${deviceId}`, 'gap');
        head = e.seq;
      }
    }
    const arr = this.events.get(soulId) ?? [];
    for (const list of byDevice.values()) for (const e of list) arr.push({ ...e, createdAt: this.now() });
    this.events.set(soulId, arr);
  }
  async eventsSince(soulId: string, since: Record<string, number>, limit = 1000): Promise<EventRecord[]> {
    const out: EventRecord[] = [];
    for (const e of this.events.get(soulId) ?? []) {
      if (e.seq > (since[e.deviceId] ?? 0)) out.push(structuredClone(e));
      if (out.length >= limit) break;
    }
    return out;
  }

  async putSnapshot(s: Omit<SnapshotRecord, 'createdAt'>): Promise<void> {
    const arr = this.snapshots.get(s.soulId) ?? [];
    arr.push({ ...s, createdAt: this.now() });
    this.snapshots.set(s.soulId, arr);
  }
  async latestSnapshot(soulId: string): Promise<SnapshotRecord | null> {
    const arr = this.snapshots.get(soulId) ?? [];
    return arr.length ? structuredClone(arr[arr.length - 1]!) : null;
  }

  async createGrant(g: Omit<GrantRecord, 'createdAt' | 'revokedAt'>): Promise<GrantRecord> {
    const rec: GrantRecord = { ...g, revokedAt: null, createdAt: this.now() };
    this.grants.set(g.id, rec);
    return structuredClone(rec);
  }
  async listGrants(soulId: string): Promise<GrantRecord[]> {
    return [...this.grants.values()].filter((g) => g.soulId === soulId).map((g) => structuredClone(g));
  }
  async revokeGrant(id: string): Promise<void> {
    const g = this.grants.get(id);
    if (!g) throw new StoreError('grant not found', 'not_found');
    g.revokedAt = g.revokedAt ?? this.now();
  }
  async findGrantByTokenHash(tokenHash: Uint8Array): Promise<GrantRecord | null> {
    for (const g of this.grants.values()) {
      if (g.tokenHash.length === tokenHash.length && g.tokenHash.every((b, i) => b === tokenHash[i])) return structuredClone(g);
    }
    return null;
  }
}
