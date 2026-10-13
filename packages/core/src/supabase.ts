/**
 * Supabase-backed Store. Ciphertext only. Relies on the RLS policies in supabase/migrations.
 *
 * Two auth modes:
 *  - user mode: a supabase-js client authenticated as the owner (anon key + session). RLS scopes rows.
 *  - service mode: service-role key, used only by the gateway after it has validated a harness grant.
 *
 * Bytea columns travel as base64 strings through PostgREST; the `\x` hex form is also accepted on read.
 */
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { b64, unb64 } from './crypto.js';
import {
  type DeviceRecord,
  type EventRecord,
  type GrantRecord,
  type Scope,
  type SnapshotRecord,
  type SoulRecord,
  type Store,
  StoreError,
} from './store.js';

export interface SupabaseStoreOptions {
  url: string;
  key: string;
  accessToken?: string; // user JWT when not using the client's own session
  client?: SupabaseClient;
}

type Row = Record<string, unknown>;

function toBytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string') {
    if (v.startsWith('\\x')) return new Uint8Array(Buffer.from(v.slice(2), 'hex'));
    return unb64(v);
  }
  throw new StoreError(`unexpected bytea value type ${typeof v}`);
}
function toPg(b: Uint8Array): string {
  return '\\x' + Buffer.from(b).toString('hex');
}
function err(e: { message: string; code?: string } | null, what: string): never {
  const code = e?.code ?? '';
  if (code === '23505') throw new StoreError(`${what}: conflict`, 'conflict');
  if (code === 'P0001' && /gap/i.test(e?.message ?? '')) throw new StoreError(`${what}: ${e?.message}`, 'gap');
  if (code === '42501' || code === 'PGRST301') throw new StoreError(`${what}: forbidden`, 'forbidden');
  throw new StoreError(`${what}: ${e?.message ?? 'unknown error'}`, 'io');
}

export class SupabaseStore implements Store {
  private readonly sb: SupabaseClient;

  constructor(opts: SupabaseStoreOptions) {
    this.sb =
      opts.client ??
      createClient(opts.url, opts.key, {
        auth: { persistSession: false, autoRefreshToken: false },
        ...(opts.accessToken ? { global: { headers: { Authorization: `Bearer ${opts.accessToken}` } } } : {}),
      });
  }

  get client(): SupabaseClient {
    return this.sb;
  }

  // ---- souls ----
  private soulFromRow(r: Row): SoulRecord {
    return {
      id: String(r.id),
      ownerId: String(r.owner),
      name: String(r.name),
      salt: toBytes(r.salt),
      wrappedDkOwner: toBytes(r.wrapped_dk_owner),
      wrappedDkRecovery: toBytes(r.wrapped_dk_recovery),
      dkVersion: Number(r.dk_version),
      createdAt: String(r.created_at),
    };
  }
  async createSoul(s: Omit<SoulRecord, 'createdAt'>): Promise<SoulRecord> {
    const { data, error } = await this.sb
      .from('souls')
      .insert({
        id: s.id,
        owner: s.ownerId,
        name: s.name,
        salt: toPg(s.salt),
        wrapped_dk_owner: toPg(s.wrappedDkOwner),
        wrapped_dk_recovery: toPg(s.wrappedDkRecovery),
        dk_version: s.dkVersion,
      })
      .select()
      .single();
    if (error) err(error, 'createSoul');
    return this.soulFromRow(data as Row);
  }
  async getSoul(id: string): Promise<SoulRecord | null> {
    const { data, error } = await this.sb.from('souls').select().eq('id', id).maybeSingle();
    if (error) err(error, 'getSoul');
    return data ? this.soulFromRow(data as Row) : null;
  }
  async listSouls(ownerId: string): Promise<SoulRecord[]> {
    const { data, error } = await this.sb.from('souls').select().eq('owner', ownerId).order('created_at');
    if (error) err(error, 'listSouls');
    return (data as Row[]).map((r) => this.soulFromRow(r));
  }
  async updateSoulKeys(id: string, patch: Pick<SoulRecord, 'wrappedDkOwner' | 'wrappedDkRecovery' | 'dkVersion'>): Promise<void> {
    const { error } = await this.sb.rpc('soul_rotate_keys', {
      p_soul: id,
      p_wrapped_owner: toPg(patch.wrappedDkOwner),
      p_wrapped_recovery: toPg(patch.wrappedDkRecovery),
      p_dk_version: patch.dkVersion,
    });
    if (error) err(error, 'updateSoulKeys');
  }

  // ---- devices ----
  private deviceFromRow(r: Row): DeviceRecord {
    const sealed: Record<number, Uint8Array> = {};
    for (const [k, v] of Object.entries((r.sealed_dks as Record<string, string>) ?? {})) sealed[Number(k)] = unb64(v);
    return {
      id: String(r.id),
      soulId: String(r.soul_id),
      label: String(r.label),
      publicKey: toBytes(r.pubkey),
      sealedDks: sealed,
      approvedAt: r.approved_at ? String(r.approved_at) : null,
      revokedAt: r.revoked_at ? String(r.revoked_at) : null,
      createdAt: String(r.created_at),
    };
  }
  async createDevice(d: Omit<DeviceRecord, 'createdAt' | 'approvedAt' | 'revokedAt' | 'sealedDks'>): Promise<DeviceRecord> {
    const { data, error } = await this.sb
      .from('devices')
      .insert({ id: d.id, soul_id: d.soulId, label: d.label, pubkey: toPg(d.publicKey), sealed_dks: {} })
      .select()
      .single();
    if (error) err(error, 'createDevice');
    return this.deviceFromRow(data as Row);
  }
  async getDevice(id: string): Promise<DeviceRecord | null> {
    const { data, error } = await this.sb.from('devices').select().eq('id', id).maybeSingle();
    if (error) err(error, 'getDevice');
    return data ? this.deviceFromRow(data as Row) : null;
  }
  async listDevices(soulId: string): Promise<DeviceRecord[]> {
    const { data, error } = await this.sb.from('devices').select().eq('soul_id', soulId).order('created_at');
    if (error) err(error, 'listDevices');
    return (data as Row[]).map((r) => this.deviceFromRow(r));
  }
  async approveDevice(id: string, sealedDks: Record<number, Uint8Array>): Promise<void> {
    const { error } = await this.sb.rpc('device_approve', {
      p_device: id,
      p_sealed: Object.fromEntries(Object.entries(sealedDks).map(([v, b]) => [v, b64(b)])),
    });
    if (error) err(error, 'approveDevice');
  }
  async addSealedDk(id: string, dkVersion: number, sealed: Uint8Array): Promise<void> {
    const { error } = await this.sb.rpc('device_approve', { p_device: id, p_sealed: { [dkVersion]: b64(sealed) } });
    if (error) err(error, 'addSealedDk');
  }
  async revokeDevice(id: string): Promise<void> {
    const { error } = await this.sb.from('devices').update({ revoked_at: new Date().toISOString() }).eq('id', id).is('revoked_at', null);
    if (error) err(error, 'revokeDevice');
  }

  // ---- events ----
  async heads(soulId: string): Promise<Record<string, number>> {
    const { data, error } = await this.sb.rpc('soul_heads', { p_soul: soulId });
    if (error) err(error, 'heads');
    const out: Record<string, number> = {};
    for (const r of (data as { device_id: string; head: number }[]) ?? []) out[r.device_id] = Number(r.head);
    return out;
  }
  async appendEvents(events: EventRecord[]): Promise<void> {
    if (events.length === 0) return;
    const rows = events.map((e) => ({
      soul_id: e.soulId,
      device_id: e.deviceId,
      seq: e.seq,
      dk_version: e.dkVersion,
      nonce: b64(e.nonce),
      ciphertext: b64(e.ciphertext),
    }));
    const { error } = await this.sb.rpc('events_append', { p_events: rows });
    if (error) err(error, 'appendEvents');
  }
  async eventsSince(soulId: string, since: Record<string, number>, limit = 1000): Promise<EventRecord[]> {
    const { data, error } = await this.sb.rpc('events_since', { p_soul: soulId, p_since: since, p_limit: limit });
    if (error) err(error, 'eventsSince');
    return ((data as Row[]) ?? []).map((r) => ({
      soulId: String(r.soul_id),
      deviceId: String(r.device_id),
      seq: Number(r.seq),
      dkVersion: Number(r.dk_version),
      nonce: toBytes(r.nonce),
      ciphertext: toBytes(r.ciphertext),
      createdAt: String(r.created_at),
    }));
  }

  // ---- snapshots ----
  async putSnapshot(s: Omit<SnapshotRecord, 'createdAt'>): Promise<void> {
    const { error } = await this.sb.from('snapshots').insert({
      soul_id: s.soulId,
      device_id: s.deviceId,
      through: s.through,
      replay_hash: s.replayHash,
      dk_version: s.dkVersion,
      nonce: toPg(s.nonce),
      ciphertext: toPg(s.ciphertext),
    });
    if (error) err(error, 'putSnapshot');
  }
  async latestSnapshot(soulId: string): Promise<SnapshotRecord | null> {
    const { data, error } = await this.sb
      .from('snapshots')
      .select()
      .eq('soul_id', soulId)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error) err(error, 'latestSnapshot');
    if (!data) return null;
    const r = data as Row;
    return {
      soulId: String(r.soul_id),
      deviceId: String(r.device_id),
      through: (r.through as Record<string, number>) ?? {},
      replayHash: String(r.replay_hash),
      dkVersion: Number(r.dk_version),
      nonce: toBytes(r.nonce),
      ciphertext: toBytes(r.ciphertext),
      createdAt: String(r.created_at),
    };
  }

  // ---- grants ----
  private grantFromRow(r: Row): GrantRecord {
    return {
      id: String(r.id),
      soulId: String(r.soul_id),
      label: String(r.label),
      scopes: (r.scopes as Scope[]) ?? [],
      tokenHash: toBytes(r.token_hash),
      expiresAt: r.expires_at ? String(r.expires_at) : null,
      revokedAt: r.revoked_at ? String(r.revoked_at) : null,
      createdAt: String(r.created_at),
    };
  }
  async createGrant(g: Omit<GrantRecord, 'createdAt' | 'revokedAt'>): Promise<GrantRecord> {
    const { data, error } = await this.sb
      .from('harness_grants')
      .insert({ id: g.id, soul_id: g.soulId, label: g.label, scopes: g.scopes, token_hash: toPg(g.tokenHash), expires_at: g.expiresAt })
      .select()
      .single();
    if (error) err(error, 'createGrant');
    return this.grantFromRow(data as Row);
  }
  async listGrants(soulId: string): Promise<GrantRecord[]> {
    const { data, error } = await this.sb.from('harness_grants').select().eq('soul_id', soulId).order('created_at');
    if (error) err(error, 'listGrants');
    return (data as Row[]).map((r) => this.grantFromRow(r));
  }
  async revokeGrant(id: string): Promise<void> {
    const { error } = await this.sb
      .from('harness_grants')
      .update({ revoked_at: new Date().toISOString() })
      .eq('id', id)
      .is('revoked_at', null);
    if (error) err(error, 'revokeGrant');
  }
  async findGrantByTokenHash(tokenHash: Uint8Array): Promise<GrantRecord | null> {
    // service-role only (RLS hides grants from non-owners); the gateway calls this.
    const { data, error } = await this.sb.rpc('grant_by_token_hash', { p_hash: toPg(tokenHash) });
    if (error) err(error, 'findGrantByTokenHash');
    const rows = (data as Row[]) ?? [];
    return rows.length ? this.grantFromRow(rows[0]!) : null;
  }
}
