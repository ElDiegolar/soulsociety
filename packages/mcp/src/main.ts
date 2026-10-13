#!/usr/bin/env node
/**
 * soul-mcp: MCP server (stdio) over one soul on this device. Keys stay here.
 *
 * Env:
 *   SOULSOCIETY_HOME               (default ~/.soulsociety) — reads config.json for backend + current soul/device
 *   SOULSOCIETY_DEVICE_PASSPHRASE  required (no TTY on stdio transport)
 *   SOULSOCIETY_GRANT              optional harness token; if set, tool access is limited to its scopes
 *   SOULSOCIETY_AUTOSYNC           '1' to sync before reads and after appends (default on)
 *
 * Capability gating: the harness can only append event types permitted by the trust ladder
 * recorded in the soul itself. The ladder is state, not config, so a harness can't edit it.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ARGON2_DEFAULT,
  authenticateGrant,
  FileHostStore,
  FileKeystore,
  MemoryStore,
  type Scope,
  SoulClient,
  type SoulState,
  type Store,
  SupabaseStore,
  validateEvent,
} from '@soulsociety/core';

const HOME = process.env.SOULSOCIETY_HOME ?? path.join(os.homedir(), '.soulsociety');

interface Config {
  backend: 'file' | 'supabase' | 'memory';
  dataDir: string;
  hostFile?: string;
  supabaseUrl?: string;
  supabaseKey?: string;
  current?: { soulId: string; deviceId: string };
}

async function loadConfig(): Promise<Config> {
  const c = JSON.parse(await fs.readFile(path.join(HOME, 'config.json'), 'utf8')) as Config;
  if (!c.current) throw new Error('config has no current soul');
  return c;
}

async function makeStore(c: Config): Promise<Store> {
  if (c.backend === 'supabase') {
    const url = process.env.SUPABASE_URL ?? c.supabaseUrl;
    const key = process.env.SUPABASE_KEY ?? c.supabaseKey;
    if (!url || !key) throw new Error('supabase backend needs SUPABASE_URL and SUPABASE_KEY');
    const accessToken = process.env.SUPABASE_ACCESS_TOKEN;
    return new SupabaseStore({ url, key, ...(accessToken ? { accessToken } : {}) });
  }
  if (c.backend === 'file') return FileHostStore.open(c.hostFile ?? path.join(HOME, 'host.json'));
  return new MemoryStore();
}

/**
 * Which event types a harness may append, by trust state. Everything else requires a human
 * (CLI/body) to append. Mirrors the KAI v1 ladder: autonomy is offered on level-up and must be accepted.
 */
const ALWAYS_ALLOWED = new Set(['note', 'commitment.made', 'observation']);
const CAPABILITY_EVENTS: Record<string, string[]> = {
  witness_tasks: ['task.completed'],
  approve_drafts: ['draft.approved'],
  manage_commitments: ['commitment.kept', 'commitment.broken'],
};

function allowedTypes(state: SoulState): Set<string> {
  const out = new Set(ALWAYS_ALLOWED);
  for (const [cap, t] of Object.entries(state.trust)) {
    if (t.status === 'accepted') for (const ev of CAPABILITY_EVENTS[cap] ?? []) out.add(ev);
  }
  return out;
}

async function main(): Promise<void> {
  const c = await loadConfig();
  const store = await makeStore(c);
  const devicePassphrase = process.env.SOULSOCIETY_DEVICE_PASSPHRASE;
  if (devicePassphrase === undefined) throw new Error('SOULSOCIETY_DEVICE_PASSPHRASE is required');
  const keystore = new FileKeystore(path.join(c.dataDir, 'keys'), ARGON2_DEFAULT);
  const client = await SoulClient.open({ store, keystore, dataDir: c.dataDir, devicePassphrase }, c.current!.soulId, c.current!.deviceId);
  if (!client.isActive) throw new Error('device is not activated for this soul');
  const autosync = (process.env.SOULSOCIETY_AUTOSYNC ?? '1') === '1';

  let scopes: Scope[] = ['events:read', 'events:append', 'state:read', 'snapshots:read', 'snapshots:write'];
  if (process.env.SOULSOCIETY_GRANT) {
    const g = await authenticateGrant(store, process.env.SOULSOCIETY_GRANT, []);
    if (!g || g.soulId !== client.soulId) throw new Error('grant invalid, expired, revoked, or for another soul');
    scopes = g.scopes;
  }
  const need = (s: Scope) => {
    if (!scopes.includes(s)) throw new Error(`grant lacks scope ${s}`);
  };

  const server = new McpServer(
    { name: 'soul-mcp', version: '0.1.0' },
    {
      instructions: [
        "This server exposes the user's soul: a portable, encrypted, append-only record of who they are and what they have done.",
        "At the start of a session, call soul_state once and treat its observations as the user's standing preferences.",
        'If a soul-companion skill is available, load it before writing. Record durable preferences with soul_observe.',
        'Only append event types listed in allowedAppendTypes; task.completed requires that you witnessed the completion.',
        'Never ask the user for passphrases, recovery codes, or tokens.',
      ].join(' '),
    },
  );

  server.tool(
    'soul_state',
    'Derived state of the soul (replayed from the full event history).',
    { sync: z.boolean().optional() },
    async ({ sync }) => {
      need('state:read');
      if (sync ?? autosync) await client.sync();
      const s = await client.state();
      return { content: [{ type: 'text', text: JSON.stringify({ ...s, allowedAppendTypes: [...allowedTypes(s)] }, null, 2) }] };
    },
  );

  server.tool(
    'soul_history',
    'Events in replay order, optionally filtered by type prefix and limited to the most recent N.',
    { typePrefix: z.string().optional(), limit: z.number().int().min(1).max(500).optional() },
    async ({ typePrefix, limit }) => {
      need('events:read');
      const all = await client.allEntries();
      const sorted = all.sort((a, b) =>
        a.event.ts < b.event.ts
          ? -1
          : a.event.ts > b.event.ts
            ? 1
            : a.deviceId < b.deviceId
              ? -1
              : a.deviceId > b.deviceId
                ? 1
                : a.seq - b.seq,
      );
      const filtered = typePrefix ? sorted.filter((e) => e.event.type.startsWith(typePrefix)) : sorted;
      const tail = filtered.slice(-(limit ?? 100));
      return { content: [{ type: 'text', text: JSON.stringify(tail, null, 2) }] };
    },
  );

  server.tool(
    'soul_append',
    "Append an event. Only types permitted by the soul's own trust ladder are accepted; others need a human.",
    { type: z.string(), data: z.record(z.unknown()).optional() },
    async ({ type, data }) => {
      need('events:append');
      const state = await client.state();
      const ok = allowedTypes(state);
      if (!ok.has(type)) {
        return {
          isError: true,
          content: [
            { type: 'text', text: `"${type}" is not permitted for a harness at the current trust level. Allowed: ${[...ok].join(', ')}` },
          ],
        };
      }
      const ev = validateEvent({ v: 1, ts: new Date().toISOString(), type, data: data ?? {} });
      const entry = await client.append(ev);
      if (autosync) await client.push();
      return { content: [{ type: 'text', text: JSON.stringify({ seq: entry.seq, deviceId: client.deviceId }) }] };
    },
  );

  server.tool(
    'soul_request_capability',
    'Ask the human to offer a capability (recorded as a note; the human accepts via trust.offered/accepted outside the harness).',
    { capability: z.string(), reason: z.string().max(500) },
    async ({ capability, reason }) => {
      need('events:append');
      const ev = validateEvent({
        v: 1,
        ts: new Date().toISOString(),
        type: 'note',
        data: { text: `[capability request] ${capability}: ${reason}` },
      });
      const entry = await client.append(ev);
      if (autosync) await client.push();
      return {
        content: [{ type: 'text', text: JSON.stringify({ recorded: true, seq: entry.seq, known: Object.keys(CAPABILITY_EVENTS) }) }],
      };
    },
  );

  server.tool(
    'soul_observe',
    'Record something learned about the user while working (preference, pattern, fact, goal, dislike). Dedups by text; retraction is human-only.',
    {
      kind: z.enum(['preference', 'pattern', 'fact', 'goal', 'dislike']),
      text: z.string().min(1).max(500),
      confidence: z.number().min(0).max(1).optional(),
      source: z.string().max(80).optional(),
    },
    async ({ kind, text, confidence, source }) => {
      need('events:append');
      const ev = validateEvent({
        v: 1,
        ts: new Date().toISOString(),
        type: 'observation',
        data: { kind, text, confidence: confidence ?? 0.5, ...(source ? { source } : {}) },
      });
      const entry = await client.append(ev);
      if (autosync) await client.push();
      return { content: [{ type: 'text', text: JSON.stringify({ seq: entry.seq }) }] };
    },
  );

  server.tool('soul_sync', 'Push local events and pull peers.', {}, async () => {
    need('events:read');
    const r = await client.sync();
    return { content: [{ type: 'text', text: JSON.stringify(r) }] };
  });

  server.tool('soul_snapshot', 'Upload an encrypted, verifiable snapshot of current state.', {}, async () => {
    need('snapshots:write');
    const s = await client.putSnapshot();
    return { content: [{ type: 'text', text: JSON.stringify({ replayHash: s.replayHash, eventCount: s.eventCount }) }] };
  });

  server.resource('soul://state', 'soul://state', async () => {
    need('state:read');
    const s = await client.state();
    return { contents: [{ uri: 'soul://state', mimeType: 'application/json', text: JSON.stringify(s, null, 2) }] };
  });

  await server.connect(new StdioServerTransport());
}

main().catch((e: Error) => {
  process.stderr.write(`soul-mcp: ${e.message}\n`);
  process.exit(1);
});
