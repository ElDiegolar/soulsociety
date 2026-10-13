/**
 * Deterministic replay. Same set of logs → same state → same hash, on any machine, forever.
 *
 * Ordering: by (ts, deviceId, seq). ts is the writer's clock; ties are broken by deviceId
 * (lexicographic) then seq, so two devices can never produce an ambiguous order.
 *
 * Reducers are pure. Unknown event types are counted but otherwise ignored, so a newer
 * client can write events an older client will skip without diverging on the fields it knows.
 */
import { hashHex, utf8 } from './crypto.js';
import type { LogEntry } from './log.js';

export interface ReplayEntry extends LogEntry {
  deviceId: string;
}

export interface Commitment {
  id: string;
  text: string;
  by?: string;
  status: 'open' | 'kept' | 'broken';
  madeAt: string;
}

export interface TrustState {
  level: number;
  status: 'offered' | 'accepted' | 'revoked';
  failures: number;
}

export interface Observation {
  kind: 'preference' | 'pattern' | 'fact' | 'goal' | 'dislike';
  text: string;
  confidence: number;
  source?: string;
  firstSeen: string;
  lastSeen: string;
  count: number;
}

export const MAX_OBSERVATIONS = 200;

export interface SoulState {
  name: string | null;
  xp: number;
  level: number;
  devices: Record<string, { label: string; revoked: boolean }>;
  dkVersion: number;
  trust: Record<string, TrustState>;
  commitments: Record<string, Commitment>;
  observations: Observation[];
  counts: Record<string, number>;
  eventCount: number;
  heads: Record<string, number>;
  lastTs: string | null;
  /** Hash of the ordered event stream (not of this object), so the state hash is schema-independent. */
  replayHash: string;
}

export const XP_PER_TASK = 10;
export const XP_PER_DRAFT = 15;
export const TRUST_DEMOTE_AFTER_FAILURES = 2;
/** Level thresholds: level n requires LEVELS[n-1] xp. */
export const LEVELS = [0, 100, 300, 700, 1500];

export function levelFor(xp: number): number {
  let lvl = 1;
  for (let i = 1; i < LEVELS.length; i++) if (xp >= LEVELS[i]!) lvl = i + 1;
  return lvl;
}

export function emptyState(): SoulState {
  return {
    name: null,
    xp: 0,
    level: 1,
    devices: {},
    dkVersion: 1,
    trust: {},
    commitments: {},
    observations: [],
    counts: {},
    eventCount: 0,
    heads: {},
    lastTs: null,
    replayHash: '',
  };
}

export function orderEntries(entries: ReplayEntry[]): ReplayEntry[] {
  return [...entries].sort((a, b) => {
    if (a.event.ts !== b.event.ts) return a.event.ts < b.event.ts ? -1 : 1;
    if (a.deviceId !== b.deviceId) return a.deviceId < b.deviceId ? -1 : 1;
    return a.seq - b.seq;
  });
}

export function reduce(state: SoulState, e: ReplayEntry): SoulState {
  const s: SoulState = structuredClone(state);
  const d = e.event.data as Record<string, unknown>;
  s.counts[e.event.type] = (s.counts[e.event.type] ?? 0) + 1;
  s.eventCount += 1;
  s.heads[e.deviceId] = Math.max(s.heads[e.deviceId] ?? 0, e.seq);
  s.lastTs = e.event.ts;

  switch (e.event.type) {
    case 'soul.created':
      if (s.name === null) s.name = String(d.name);
      break;
    case 'soul.renamed':
      s.name = String(d.name);
      break;
    case 'device.enrolled':
      s.devices[String(d.deviceId)] = { label: String(d.label ?? ''), revoked: false };
      break;
    case 'device.revoked': {
      const dev = s.devices[String(d.deviceId)];
      if (dev) dev.revoked = true;
      break;
    }
    case 'key.rotated':
      s.dkVersion = Math.max(s.dkVersion, Number(d.dkVersion));
      break;
    case 'task.completed':
      if (d.witnessed === true) s.xp += XP_PER_TASK;
      break;
    case 'draft.approved':
      s.xp += XP_PER_DRAFT;
      break;
    case 'trust.offered':
      s.trust[String(d.capability)] = { level: Number(d.level), status: 'offered', failures: 0 };
      break;
    case 'trust.accepted': {
      const t = s.trust[String(d.capability)];
      if (t && t.status === 'offered') t.status = 'accepted';
      break;
    }
    case 'trust.failed': {
      const t = s.trust[String(d.capability)];
      if (t) {
        t.failures += 1;
        if (t.failures >= TRUST_DEMOTE_AFTER_FAILURES) t.status = 'revoked';
      }
      break;
    }
    case 'commitment.made':
      s.commitments[String(d.id)] = {
        id: String(d.id),
        text: String(d.text),
        ...(d.by ? { by: String(d.by) } : {}),
        status: 'open',
        madeAt: e.event.ts,
      };
      break;
    case 'commitment.kept': {
      const c = s.commitments[String(d.id)];
      if (c && c.status === 'open') c.status = 'kept';
      break;
    }
    case 'commitment.broken': {
      const c = s.commitments[String(d.id)];
      if (c && c.status === 'open') c.status = 'broken';
      break;
    }
    case 'observation': {
      const text = String(d.text).trim();
      const existing = s.observations.find((o) => o.text === text);
      if (existing) {
        existing.count += 1;
        existing.lastSeen = e.event.ts;
        existing.confidence = Math.min(1, Math.max(existing.confidence, Number(d.confidence ?? 0.5)));
      } else {
        s.observations.push({
          kind: d.kind as Observation['kind'],
          text,
          confidence: Number(d.confidence ?? 0.5),
          ...(d.source ? { source: String(d.source) } : {}),
          firstSeen: e.event.ts,
          lastSeen: e.event.ts,
          count: 1,
        });
        if (s.observations.length > MAX_OBSERVATIONS) {
          // drop the weakest, oldest first
          s.observations.sort((a, b) => a.confidence * a.count - b.confidence * b.count || (a.lastSeen < b.lastSeen ? -1 : 1));
          s.observations.splice(0, s.observations.length - MAX_OBSERVATIONS);
        }
      }
      break;
    }
    case 'observation.retracted': {
      const text = String(d.text).trim();
      s.observations = s.observations.filter((o) => o.text !== text);
      break;
    }
    default:
      break; // unknown or informational
  }
  s.level = levelFor(s.xp);
  return s;
}

/** Canonical bytes for one entry, used for the replay hash. Field order is fixed by construction. */
export function canonicalEntry(e: ReplayEntry): string {
  return JSON.stringify({ d: e.deviceId, s: e.seq, t: e.event.ts, y: e.event.type, a: canonicalJson(e.event.data) });
}

function canonicalJson(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonicalJson);
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(o)
        .sort()
        .map((k) => [k, canonicalJson(o[k])]),
    );
  }
  return v;
}

export async function replay(entries: ReplayEntry[], from: SoulState = emptyState()): Promise<SoulState> {
  const ordered = orderEntries(entries);
  let state = from;
  let chain = from.replayHash;
  for (const e of ordered) {
    state = reduce(state, e);
    chain = await hashHex(utf8(chain + '\n' + canonicalEntry(e)));
  }
  state.replayHash = chain;
  return state;
}
