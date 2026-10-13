/**
 * Local append-only device log: one JSONL file per (soul, device).
 * Lines are plaintext events (the local disk is the trust boundary; the host only ever sees ciphertext).
 *
 * Invariants:
 *  - seq starts at 1 and increases by exactly 1 per line
 *  - a line is written with fsync before append() resolves
 *  - a truncated trailing line (crash mid-write) is detected and dropped on open
 */
import { promises as fs } from 'node:fs';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import path from 'node:path';
import { validateEvent, type EventEnvelope } from './schema.js';

export interface LogEntry {
  seq: number;
  event: EventEnvelope;
}

export class LogError extends Error {
  override name = 'LogError';
}

export class DeviceLog {
  private lastSeq = 0;
  private opened = false;
  private writeChain: Promise<void> = Promise.resolve();

  constructor(
    public readonly filePath: string,
    public readonly deviceId: string,
  ) {}

  static async open(dir: string, soulId: string, deviceId: string): Promise<DeviceLog> {
    await fs.mkdir(path.join(dir, soulId), { recursive: true });
    const log = new DeviceLog(path.join(dir, soulId, `${deviceId}.jsonl`), deviceId);
    await log.load();
    return log;
  }

  get head(): number {
    return this.lastSeq;
  }

  private async load(): Promise<void> {
    let raw: string;
    try {
      raw = await fs.readFile(this.filePath, 'utf8');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
        this.opened = true;
        return;
      }
      throw e;
    }
    const lines = raw.split('\n').filter((l) => l !== '');
    let last = 0;
    const good: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      let parsed: LogEntry;
      try {
        parsed = parseLine(line);
      } catch (e) {
        // A partial final line means we crashed mid-append: drop it. Anything earlier is corruption.
        if (i === lines.length - 1) break;
        throw new LogError(`corrupt log ${this.filePath} at line ${i + 1}: ${(e as Error).message}`);
      }
      if (parsed.seq !== last + 1) throw new LogError(`seq gap in ${this.filePath}: expected ${last + 1} got ${parsed.seq}`);
      last = parsed.seq;
      good.push(line);
    }
    if (good.length !== lines.length) {
      const tmp = this.filePath + '.tmp';
      await fs.writeFile(tmp, good.map((l) => l + '\n').join(''), 'utf8');
      await fs.rename(tmp, this.filePath);
    }
    this.lastSeq = last;
    this.opened = true;
  }

  async append(event: EventEnvelope): Promise<LogEntry> {
    if (!this.opened) throw new LogError('log not opened');
    const validated = validateEvent(event);
    const run = async (): Promise<LogEntry> => {
      const seq = this.lastSeq + 1;
      const entry: LogEntry = { seq, event: validated };
      const fh = await fs.open(this.filePath, 'a');
      try {
        await fh.appendFile(JSON.stringify(entry) + '\n', 'utf8');
        await fh.sync();
      } finally {
        await fh.close();
      }
      this.lastSeq = seq;
      return entry;
    };
    const p = this.writeChain.then(run, run);
    this.writeChain = p.then(
      () => undefined,
      () => undefined,
    );
    return p;
  }

  async *entries(fromSeq = 1): AsyncGenerator<LogEntry> {
    if (!this.opened) throw new LogError('log not opened');
    let stream;
    try {
      stream = createReadStream(this.filePath, { encoding: 'utf8' });
    } catch {
      return;
    }
    try {
      const rl = createInterface({ input: stream, crlfDelay: Infinity });
      for await (const line of rl) {
        if (line === '') continue;
        const entry = safeParse(line);
        if (!entry) break;
        if (entry.seq >= fromSeq) yield entry;
      }
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw e;
    }
  }

  async readAll(fromSeq = 1): Promise<LogEntry[]> {
    const out: LogEntry[] = [];
    for await (const e of this.entries(fromSeq)) out.push(e);
    return out;
  }
}

/** A read-only log of another device's events, materialised from sync. Same file format. */
export class PeerLog {
  constructor(
    public readonly filePath: string,
    public readonly deviceId: string,
  ) {}

  static async open(dir: string, soulId: string, deviceId: string): Promise<PeerLog> {
    await fs.mkdir(path.join(dir, soulId), { recursive: true });
    return new PeerLog(path.join(dir, soulId, `${deviceId}.peer.jsonl`), deviceId);
  }

  async head(): Promise<number> {
    const all = await this.readAll();
    return all.length ? all[all.length - 1]!.seq : 0;
  }

  async readAll(): Promise<LogEntry[]> {
    let raw: string;
    try {
      raw = await fs.readFile(this.filePath, 'utf8');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw e;
    }
    const out: LogEntry[] = [];
    for (const line of raw.split('\n')) {
      if (!line) continue;
      const e = safeParse(line);
      if (!e) break;
      out.push(e);
    }
    return out;
  }

  /** Append entries that continue the sequence; ignores already-present ones; throws on a gap. */
  async appendMany(entries: LogEntry[]): Promise<number> {
    let head = await this.head();
    const sorted = [...entries].sort((a, b) => a.seq - b.seq);
    const lines: string[] = [];
    for (const e of sorted) {
      if (e.seq <= head) continue;
      if (e.seq !== head + 1) throw new LogError(`peer gap for ${this.deviceId}: have ${head}, got ${e.seq}`);
      validateEvent(e.event);
      lines.push(JSON.stringify(e));
      head = e.seq;
    }
    if (lines.length) {
      const fh = await fs.open(this.filePath, 'a');
      try {
        await fh.appendFile(lines.join('\n') + '\n', 'utf8');
        await fh.sync();
      } finally {
        await fh.close();
      }
    }
    return lines.length;
  }
}

function parseLine(line: string): LogEntry {
  const o = JSON.parse(line) as unknown;
  if (!o || typeof o !== 'object') throw new LogError('line is not an object');
  const { seq, event } = o as { seq?: unknown; event?: unknown };
  if (typeof seq !== 'number' || !Number.isInteger(seq) || seq < 1) throw new LogError('bad seq');
  return { seq, event: validateEvent(event) };
}

function safeParse(line: string): LogEntry | null {
  try {
    return parseLine(line);
  } catch {
    return null;
  }
}
