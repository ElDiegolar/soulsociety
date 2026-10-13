/**
 * FileHostStore: a MemoryStore persisted to one JSON file, with an advisory lock so two
 * processes (two "devices" on one machine) can share it. Lets the full flow run without Supabase.
 * Not for production; it is the local stand-in for the host.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { MemoryStore, type Store } from './store.js';
import { fromWire as de, toWire as ser } from './wire.js';

type Json = Record<string, unknown>;

export class FileHostStore extends MemoryStore implements Store {
  private constructor(private readonly file: string) {
    super();
  }

  static async open(file: string): Promise<FileHostStore> {
    const s = new FileHostStore(file);
    await s.load();
    return s;
  }

  private async load(): Promise<void> {
    let raw: string;
    try {
      raw = await fs.readFile(this.file, 'utf8');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw e;
    }
    const o = de(JSON.parse(raw)) as {
      souls: Json[];
      devices: Json[];
      events: Record<string, Json[]>;
      snapshots: Record<string, Json[]>;
      grants: Json[];
    };
    this.souls = new Map(o.souls.map((s) => [s.id as string, s as never]));
    this.devices = new Map(o.devices.map((d) => [d.id as string, d as never]));
    this.events = new Map(Object.entries(o.events) as never);
    this.snapshots = new Map(Object.entries(o.snapshots) as never);
    this.grants = new Map(o.grants.map((g) => [g.id as string, g as never]));
  }

  private async persist(): Promise<void> {
    await fs.mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const o = ser({
      souls: [...this.souls.values()],
      devices: [...this.devices.values()],
      events: Object.fromEntries(this.events),
      snapshots: Object.fromEntries(this.snapshots),
      grants: [...this.grants.values()],
    });
    const tmp = this.file + '.tmp';
    await fs.writeFile(tmp, JSON.stringify(o), { mode: 0o600 });
    await fs.rename(tmp, this.file);
  }

  /** Reload-then-run-then-persist, under a lock file, so concurrent CLIs don't clobber each other. */
  private async locked<T>(fn: () => Promise<T>): Promise<T> {
    const lock = this.file + '.lock';
    await fs.mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
    for (let i = 0; i < 200; i++) {
      try {
        const fh = await fs.open(lock, 'wx');
        try {
          await this.load();
          const r = await fn();
          await this.persist();
          return r;
        } finally {
          await fh.close();
          await fs.rm(lock, { force: true });
        }
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
        await new Promise((r) => setTimeout(r, 25));
      }
    }
    throw new Error(`could not acquire ${lock}`);
  }

  override createSoul(s: Parameters<MemoryStore['createSoul']>[0]) {
    return this.locked(() => super.createSoul(s));
  }
  override updateSoulKeys(id: string, p: Parameters<MemoryStore['updateSoulKeys']>[1]) {
    return this.locked(() => super.updateSoulKeys(id, p));
  }
  override createDevice(d: Parameters<MemoryStore['createDevice']>[0]) {
    return this.locked(() => super.createDevice(d));
  }
  override approveDevice(id: string, s: Record<number, Uint8Array>) {
    return this.locked(() => super.approveDevice(id, s));
  }
  override addSealedDk(id: string, v: number, s: Uint8Array) {
    return this.locked(() => super.addSealedDk(id, v, s));
  }
  override revokeDevice(id: string) {
    return this.locked(() => super.revokeDevice(id));
  }
  override appendEvents(e: Parameters<MemoryStore['appendEvents']>[0]) {
    return this.locked(() => super.appendEvents(e));
  }
  override putSnapshot(s: Parameters<MemoryStore['putSnapshot']>[0]) {
    return this.locked(() => super.putSnapshot(s));
  }
  override createGrant(g: Parameters<MemoryStore['createGrant']>[0]) {
    return this.locked(() => super.createGrant(g));
  }
  override revokeGrant(id: string) {
    return this.locked(() => super.revokeGrant(id));
  }

  // reads: refresh from disk first
  override async getSoul(id: string) {
    await this.load();
    return super.getSoul(id);
  }
  override async listSouls(o: string) {
    await this.load();
    return super.listSouls(o);
  }
  override async getDevice(id: string) {
    await this.load();
    return super.getDevice(id);
  }
  override async listDevices(s: string) {
    await this.load();
    return super.listDevices(s);
  }
  override async heads(s: string) {
    await this.load();
    return super.heads(s);
  }
  override async eventsSince(s: string, since: Record<string, number>, limit?: number) {
    await this.load();
    return super.eventsSince(s, since, limit);
  }
  override async latestSnapshot(s: string) {
    await this.load();
    return super.latestSnapshot(s);
  }
  override async listGrants(s: string) {
    await this.load();
    return super.listGrants(s);
  }
  override async findGrantByTokenHash(h: Uint8Array) {
    await this.load();
    return super.findGrantByTokenHash(h);
  }
}
