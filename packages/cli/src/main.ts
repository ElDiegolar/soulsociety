#!/usr/bin/env node
/**
 * soul-sync: CLI for soulsociety souls.
 *
 * Config: ~/.soulsociety/config.json  { backend: 'memory'|'supabase', supabaseUrl, supabaseKey, dataDir }
 * Env overrides: SOULSOCIETY_HOME, SUPABASE_URL, SUPABASE_KEY, SUPABASE_ACCESS_TOKEN,
 *   SOULSOCIETY_DEVICE_PASSPHRASE, SOULSOCIETY_OWNER_PASSPHRASE, SOULSOCIETY_RECOVERY_CODE (non-interactive use)
 *
 * The 'file' backend stores the host side on local disk (JSON) so the whole flow can be exercised
 * offline, including multi-device by pointing two data dirs at the same host file.
 */
import { Command } from 'commander';
import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ARGON2_DEFAULT,
  FileHostStore,
  FileKeystore,
  makeEvent,
  MemoryStore,
  SoulClient,
  SupabaseStore,
  type KnownEventType,
  type Scope,
  type Store,
  validateEvent,
} from '@soulsociety/core';

interface Config {
  backend: 'file' | 'supabase';
  dataDir: string;
  hostFile?: string;
  supabaseUrl?: string;
  supabaseKey?: string;
  current?: { soulId: string; deviceId: string };
}

const HOME = process.env.SOULSOCIETY_HOME ?? path.join(os.homedir(), '.soulsociety');
const CONFIG = path.join(HOME, 'config.json');

async function loadConfig(): Promise<Config> {
  try {
    return JSON.parse(await fs.readFile(CONFIG, 'utf8')) as Config;
  } catch {
    return { backend: 'file', dataDir: path.join(HOME, 'data'), hostFile: path.join(HOME, 'host.json') };
  }
}
async function saveConfig(c: Config): Promise<void> {
  await fs.mkdir(HOME, { recursive: true, mode: 0o700 });
  await fs.writeFile(CONFIG, JSON.stringify(c, null, 2), { mode: 0o600 });
}

async function makeStore(c: Config): Promise<Store> {
  if (c.backend === 'supabase') {
    const url = process.env.SUPABASE_URL ?? c.supabaseUrl;
    const key = process.env.SUPABASE_KEY ?? c.supabaseKey;
    if (!url || !key) throw new Error('supabase backend needs SUPABASE_URL and SUPABASE_KEY (or config)');
    const accessToken = process.env.SUPABASE_ACCESS_TOKEN;
    return new SupabaseStore({ url, key, ...(accessToken ? { accessToken } : {}) });
  }
  if (c.backend === 'file') return FileHostStore.open(c.hostFile ?? path.join(HOME, 'host.json'));
  return new MemoryStore();
}

type SecretKind = 'device' | 'owner' | 'recovery' | 'plain';
const ENV_FOR: Record<SecretKind, string | undefined> = {
  device: 'SOULSOCIETY_DEVICE_PASSPHRASE',
  owner: 'SOULSOCIETY_OWNER_PASSPHRASE',
  recovery: 'SOULSOCIETY_RECOVERY_CODE',
  plain: undefined,
};

let stdinLines: Promise<string[]> | null = null;
async function nextStdinLine(): Promise<string> {
  stdinLines ??= (async () => {
    let buf = '';
    for await (const chunk of process.stdin) buf += chunk;
    return buf.split(/\r?\n/);
  })();
  const lines = await stdinLines;
  return lines.length ? lines.shift()! : '';
}

/**
 * Ask for a secret. Resolution order: dedicated env var (for scripts/CI), then a hidden TTY prompt,
 * then successive lines from piped stdin (stdin is read once; each prompt consumes the next line).
 */
async function prompt(question: string, kind: SecretKind = 'plain'): Promise<string> {
  const envName = ENV_FOR[kind];
  if (envName && process.env[envName] !== undefined) return process.env[envName]!;
  if (!process.stdin.isTTY) {
    process.stderr.write(question);
    const a = await nextStdinLine();
    process.stderr.write('\n');
    return a;
  }
  const hidden = kind !== 'plain';
  process.stderr.write(question);
  return new Promise((resolve) => {
    const stdin = process.stdin;
    let buf = '';
    stdin.setRawMode?.(hidden);
    stdin.resume();
    stdin.setEncoding('utf8');
    const onData = (ch: string) => {
      for (const c of ch) {
        if (c === '\n' || c === '\r' || c === '\u0004') {
          stdin.setRawMode?.(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          process.stderr.write('\n');
          resolve(buf);
          return;
        }
        if (c === '\u0003') process.exit(130);
        if (c === '\u007f') buf = buf.slice(0, -1);
        else buf += c;
      }
    };
    stdin.on('data', onData);
  });
}

async function openCurrent(c: Config): Promise<SoulClient> {
  if (!c.current) throw new Error('no current soul; run `soul-sync create` or `soul-sync enrol`');
  const store = await makeStore(c);
  const keystore = new FileKeystore(path.join(c.dataDir, 'keys'), ARGON2_DEFAULT);
  const devicePassphrase = await prompt('device passphrase: ', 'device');
  return SoulClient.open({ store, keystore, dataDir: c.dataDir, devicePassphrase }, c.current.soulId, c.current.deviceId);
}

const program = new Command().name('soul-sync').description('soulsociety: encrypted, user-owned soul sync').version('0.1.0');

program
  .command('config')
  .description('show or set config')
  .option('--backend <file|supabase>')
  .option('--supabase-url <url>')
  .option('--supabase-key <key>')
  .option('--data-dir <dir>')
  .action(async (o) => {
    const c = await loadConfig();
    if (o.backend) c.backend = o.backend;
    if (o.supabaseUrl) c.supabaseUrl = o.supabaseUrl;
    if (o.supabaseKey) c.supabaseKey = o.supabaseKey;
    if (o.dataDir) c.dataDir = path.resolve(o.dataDir);
    await saveConfig(c);
    const shown = { ...c, supabaseKey: c.supabaseKey ? '***' : undefined };
    console.log(JSON.stringify(shown, null, 2));
  });

program
  .command('create')
  .description('create a new soul on this device')
  .requiredOption('--name <name>')
  .option('--owner <id>', 'owner id (Supabase user id); defaults to "local"', 'local')
  .option('--label <label>', 'device label', os.hostname())
  .action(async (o) => {
    const c = await loadConfig();
    const store = await makeStore(c);
    const ownerPassphrase = await prompt('owner passphrase (never stored): ', 'owner');
    const again = process.env.SOULSOCIETY_OWNER_PASSPHRASE !== undefined ? ownerPassphrase : await prompt('repeat: ', 'owner');
    if (ownerPassphrase !== again) throw new Error('passphrases differ');
    if (ownerPassphrase.length < 8) throw new Error('use at least 8 characters');
    const devicePassphrase = await prompt("device passphrase (protects this device's keyfile): ", 'device');
    const keystore = new FileKeystore(path.join(c.dataDir, 'keys'), ARGON2_DEFAULT);
    const { result } = await SoulClient.create(
      { store, keystore, dataDir: c.dataDir, devicePassphrase },
      { ownerId: o.owner, name: o.name, ownerPassphrase, deviceLabel: o.label },
    );
    c.current = { soulId: result.soulId, deviceId: result.deviceId };
    await saveConfig(c);
    console.log(`soul    ${result.soulId}`);
    console.log(`device  ${result.deviceId}`);
    console.log('');
    console.log('RECOVERY CODE — write it down now, it is not stored anywhere:');
    console.log(`  ${result.recoveryCode}`);
  });

program
  .command('enrol')
  .description('enrol this device into an existing soul (pending until approved)')
  .requiredOption('--soul <id>')
  .option('--label <label>', 'device label', os.hostname())
  .action(async (o) => {
    const c = await loadConfig();
    const store = await makeStore(c);
    const devicePassphrase = await prompt('device passphrase for this device: ', 'device');
    const keystore = new FileKeystore(path.join(c.dataDir, 'keys'), ARGON2_DEFAULT);
    const client = await SoulClient.enrol({ store, keystore, dataDir: c.dataDir, devicePassphrase }, o.soul, o.label);
    c.current = { soulId: o.soul, deviceId: client.deviceId };
    await saveConfig(c);
    console.log(`pending device ${client.deviceId}`);
    console.log('approve it from an active device:  soul-sync approve ' + client.deviceId);
    console.log('or with the owner passphrase:      soul-sync approve --owner ' + client.deviceId);
    console.log('then here:                         soul-sync activate');
  });

program
  .command('activate')
  .description('after approval: fetch and unseal the data key')
  .action(async () => {
    const c = await loadConfig();
    const client = await openCurrent(c);
    console.log((await client.activate()) ? 'active' : 'still pending approval');
  });

program
  .command('approve <deviceId>')
  .description('approve a pending device (from an active device, or with --owner / --recovery)')
  .option('--owner', "use the owner passphrase instead of this device's key")
  .option('--recovery', 'use the recovery code instead')
  .action(async (deviceId: string, o) => {
    const c = await loadConfig();
    if (o.owner || o.recovery) {
      if (!c.current) throw new Error('no current soul');
      const store = await makeStore(c);
      const secret = o.recovery
        ? { recoveryCode: await prompt('recovery code: ', 'recovery') }
        : { passphrase: await prompt('owner passphrase: ', 'owner') };
      await SoulClient.approveWithOwnerSecret(store, c.current.soulId, deviceId, secret);
    } else {
      const client = await openCurrent(c);
      await client.approveDevice(deviceId);
    }
    console.log('approved');
  });

program
  .command('revoke <deviceId>')
  .description('revoke a device and rotate the data key')
  .action(async (deviceId: string) => {
    const c = await loadConfig();
    const client = await openCurrent(c);
    const pw = await prompt('owner passphrase: ', 'owner');
    const rc = await prompt('recovery code (enter to keep the previous recovery wrap): ', 'recovery');
    const v = await client.revokeDevice(deviceId, pw, rc || undefined);
    console.log(`revoked; data key is now v${v}`);
  });

program
  .command('devices')
  .description('list devices')
  .action(async () => {
    const c = await loadConfig();
    if (!c.current) throw new Error('no current soul');
    const store = await makeStore(c);
    for (const d of await store.listDevices(c.current.soulId)) {
      const status = d.revokedAt ? 'revoked' : d.approvedAt ? 'active' : 'pending';
      console.log(`${d.id}  ${status.padEnd(8)} ${d.label}${d.id === c.current.deviceId ? '  (this device)' : ''}`);
    }
  });

program
  .command('append <type> [json]')
  .description('append an event, e.g. append task.completed \'{"taskId":"t1","title":"x","witnessed":true}\'')
  .option('--no-push')
  .action(async (type: string, json: string | undefined, o) => {
    const c = await loadConfig();
    const client = await openCurrent(c);
    const data = json ? (JSON.parse(json) as Record<string, unknown>) : {};
    const ev = validateEvent({ v: 1, ts: new Date().toISOString(), type, data });
    const entry = await client.append(ev);
    if (o.push) await client.push();
    console.log(`seq ${entry.seq}`);
  });

program
  .command('sync')
  .description('push local events, pull peers')
  .action(async () => {
    const c = await loadConfig();
    const client = await openCurrent(c);
    const r = await client.sync();
    console.log(`pushed ${r.pushed}, pulled ${r.pulled}`);
  });

program
  .command('state')
  .description('replay and print derived state')
  .option('--sync', 'sync first')
  .action(async (o) => {
    const c = await loadConfig();
    const client = await openCurrent(c);
    if (o.sync) await client.sync();
    console.log(JSON.stringify(await client.state(), null, 2));
  });

program
  .command('snapshot')
  .description('upload an encrypted snapshot of current state')
  .action(async () => {
    const c = await loadConfig();
    const client = await openCurrent(c);
    const s = await client.putSnapshot();
    console.log(`snapshot at replay ${s.replayHash.slice(0, 12)}… (${s.eventCount} events)`);
  });

program
  .command('grant <label>')
  .description('mint a harness token (shown once)')
  .option('--scopes <list>', 'comma list', 'events:read,events:append,state:read')
  .option('--ttl-days <n>', 'expiry', parseFloat)
  .action(async (label: string, o) => {
    const c = await loadConfig();
    const client = await openCurrent(c);
    const g = await client.createGrant(label, o.scopes.split(',') as Scope[], o.ttlDays);
    console.log(`grant ${g.id}`);
    console.log(`token ${g.token}`);
  });

program
  .command('grants')
  .description('list / revoke grants')
  .option('--revoke <id>')
  .action(async (o) => {
    const c = await loadConfig();
    if (!c.current) throw new Error('no current soul');
    const store = await makeStore(c);
    if (o.revoke) {
      await store.revokeGrant(o.revoke);
      console.log('revoked');
      return;
    }
    for (const g of await store.listGrants(c.current.soulId)) {
      console.log(
        `${g.id}  ${g.revokedAt ? 'revoked' : 'active '}  ${g.label}  [${g.scopes.join(',')}]${g.expiresAt ? '  exp ' + g.expiresAt : ''}`,
      );
    }
  });

program
  .command('demo-event <kind>')
  .description('append a typical KAI event: task | draft | note')
  .action(async (kind: string) => {
    const c = await loadConfig();
    const client = await openCurrent(c);
    const map: Record<string, () => ReturnType<typeof makeEvent>> = {
      task: () =>
        makeEvent('task.completed' as KnownEventType, { taskId: `t-${Date.now()}`, title: 'demo task', witnessed: true } as never),
      draft: () => makeEvent('draft.approved' as KnownEventType, { draftId: `d-${Date.now()}`, kind: 'email' } as never),
      note: () => makeEvent('note' as KnownEventType, { text: 'hello from soul-sync' } as never),
    };
    const f = map[kind];
    if (!f) throw new Error('kind must be task|draft|note');
    await client.append(f());
    await client.push();
    console.log('ok');
  });

program.parseAsync(process.argv).catch((e: Error) => {
  console.error(`error: ${e.message}`);
  process.exit(1);
});
