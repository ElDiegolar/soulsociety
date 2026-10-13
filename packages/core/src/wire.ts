/**
 * Wire codec for JSON transports (gateway HTTP, file host). Uint8Array values become
 * `{ "$b": "<base64>" }` objects, recursively; everything else is left as-is.
 * Both ends of the gateway use this, so bytea fields need no per-field knowledge.
 */
import { b64, unb64 } from './crypto.js';

type Json = Record<string, unknown>;

export function toWire(v: unknown): unknown {
  if (v instanceof Uint8Array) return { $b: b64(v) };
  if (Array.isArray(v)) return v.map(toWire);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v as Json).map(([k, x]) => [k, toWire(x)]));
  return v;
}

export function fromWire(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(fromWire);
  if (v && typeof v === 'object') {
    const o = v as Json;
    if (typeof o.$b === 'string' && Object.keys(o).length === 1) return unb64(o.$b);
    return Object.fromEntries(Object.entries(o).map(([k, x]) => [k, fromWire(x)]));
  }
  return v;
}
