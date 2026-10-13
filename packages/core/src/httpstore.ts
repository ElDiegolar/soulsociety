/**
 * HttpStore: the client side of the ZK relay gateway (DESIGN §7). Talks JSON/HTTP to
 * `@soulsociety/gateway` with a bearer harness token. Ciphertext only, like every Store.
 *
 * Only the device-mode subset of Store is reachable through the gateway: heads/append/eventsSince,
 * devices (read), snapshots. Owner operations (soul creation, grants, approval, revocation,
 * key rotation) are rejected locally with StoreError('forbidden'); they stay on the owner's
 * authenticated Supabase path.
 */
import {
  type DeviceRecord,
  type EventRecord,
  type GrantRecord,
  type SnapshotRecord,
  type SoulRecord,
  type Store,
  StoreError,
} from './store.js';
import { fromWire, toWire } from './wire.js';

export interface HttpStoreOptions {
  /** Gateway origin, e.g. `https://relay.example.com` (no trailing slash needed). */
  baseUrl: string;
  /** Harness grant token (`ss_...`). Sent as `Authorization: Bearer`. */
  token: string;
  /** Soul this token belongs to; needed for routes that don't carry a soulId (getDevice). */
  soulId: string;
  /** Override fetch (tests route to `app.request`). Defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
}

type ErrorCode = ConstructorParameters<typeof StoreError>[1];

const STATUS_TO_CODE: Record<number, NonNullable<ErrorCode>> = {
  401: 'forbidden',
  403: 'forbidden',
  404: 'not_found',
  409: 'conflict',
  422: 'gap',
};

export class HttpStore implements Store {
  private readonly base: string;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly opts: HttpStoreOptions) {
    this.base = opts.baseUrl.replace(/\/+$/, '');
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
  }

  // ---------------- transport ----------------

  private async call<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.opts.token}`, accept: 'application/json' };
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      init.body = JSON.stringify(toWire(body));
    }
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.base}${path}`, init);
    } catch (e) {
      throw new StoreError(`gateway unreachable: ${(e as Error).message}`, 'io');
    }
    if (!res.ok) {
      let msg = `${res.status} ${res.statusText}`;
      let code: NonNullable<ErrorCode> = STATUS_TO_CODE[res.status] ?? 'io';
      try {
        const j = (await res.json()) as { error?: string; message?: string };
        if (j.message) msg = j.message;
        if (j.error && isCode(j.error)) code = j.error;
      } catch {
        /* non-JSON error body */
      }
      throw new StoreError(`gateway ${method} ${path}: ${msg}`, code);
    }
    if (res.status === 204) return undefined as T;
    return fromWire(await res.json()) as T;
  }

  private soulPath(soulId: string, rest: string): string {
    return `/v1/souls/${encodeURIComponent(soulId)}${rest}`;
  }

  // ---------------- events ----------------

  heads(soulId: string): Promise<Record<string, number>> {
    return this.call('GET', this.soulPath(soulId, '/heads'));
  }

  async appendEvents(events: EventRecord[]): Promise<void> {
    if (events.length === 0) return;
    const soulId = events[0]!.soulId;
    if (!events.every((e) => e.soulId === soulId)) throw new StoreError('mixed souls in batch', 'conflict');
    await this.call('POST', this.soulPath(soulId, '/events'), events);
  }

  eventsSince(soulId: string, since: Record<string, number>, limit?: number): Promise<EventRecord[]> {
    const q = new URLSearchParams({ since: JSON.stringify(since) });
    if (limit !== undefined) q.set('limit', String(limit));
    return this.call('GET', this.soulPath(soulId, `/events?${q.toString()}`));
  }

  // ---------------- devices (read-only) ----------------

  getDevice(id: string): Promise<DeviceRecord | null> {
    return this.call('GET', this.soulPath(this.opts.soulId, `/devices/${encodeURIComponent(id)}`)).then(
      (d) => d as DeviceRecord | null,
      (e: unknown) => {
        if (e instanceof StoreError && e.code === 'not_found') return null;
        throw e;
      },
    );
  }

  listDevices(soulId: string): Promise<DeviceRecord[]> {
    return this.call('GET', this.soulPath(soulId, '/devices'));
  }

  // ---------------- snapshots ----------------

  async putSnapshot(s: Omit<SnapshotRecord, 'createdAt'>): Promise<void> {
    await this.call('POST', this.soulPath(s.soulId, '/snapshots'), s);
  }

  latestSnapshot(soulId: string): Promise<SnapshotRecord | null> {
    return this.call<SnapshotRecord | null>('GET', this.soulPath(soulId, '/snapshots/latest'));
  }

  // ---------------- owner operations: not available through the relay ----------------

  createSoul(): Promise<SoulRecord> {
    return this.ownerOnly('createSoul');
  }
  getSoul(): Promise<SoulRecord | null> {
    return this.ownerOnly('getSoul');
  }
  listSouls(): Promise<SoulRecord[]> {
    return this.ownerOnly('listSouls');
  }
  updateSoulKeys(): Promise<void> {
    return this.ownerOnly('updateSoulKeys');
  }
  createDevice(): Promise<DeviceRecord> {
    return this.ownerOnly('createDevice');
  }
  approveDevice(): Promise<void> {
    return this.ownerOnly('approveDevice');
  }
  addSealedDk(): Promise<void> {
    return this.ownerOnly('addSealedDk');
  }
  revokeDevice(): Promise<void> {
    return this.ownerOnly('revokeDevice');
  }
  createGrant(): Promise<GrantRecord> {
    return this.ownerOnly('createGrant');
  }
  listGrants(): Promise<GrantRecord[]> {
    return this.ownerOnly('listGrants');
  }
  revokeGrant(): Promise<void> {
    return this.ownerOnly('revokeGrant');
  }
  findGrantByTokenHash(): Promise<GrantRecord | null> {
    return this.ownerOnly('findGrantByTokenHash');
  }

  private ownerOnly(op: string): Promise<never> {
    return Promise.reject(new StoreError(`${op} is an owner operation; not available through the gateway`, 'forbidden'));
  }
}

function isCode(s: string): s is NonNullable<ErrorCode> {
  return s === 'conflict' || s === 'gap' || s === 'not_found' || s === 'forbidden' || s === 'io';
}
