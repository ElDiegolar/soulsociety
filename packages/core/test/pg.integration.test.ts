// Integration test: applies supabase/migrations/0001_init.sql to a real Postgres (see scripts/pg-up.sh)
// and checks that RLS, triggers and RPCs enforce what DESIGN.md says.
// Supabase's auth model is simulated per transaction with `set local role` + request.jwt.claim.* GUCs.
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import pg from 'pg';

const url = process.env.SOUL_PG_URL ?? 'postgres://postgres:postgres@127.0.0.1:54329/postgres';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const AUTH_STUB = path.join(root, 'supabase/test/auth_stub.sql');
const MIGRATION = path.join(root, 'supabase/migrations/0001_init.sql');

const pool = new pg.Pool({ connectionString: url, max: 4 });

type Role = 'authenticated' | 'service_role' | 'anon';
type Tx = { q: (sql: string, params?: unknown[]) => Promise<pg.QueryResult> };

/** Run `fn` inside a transaction impersonating a Supabase request for `uid` with `role`. Commits unless fn throws. */
async function as<T>(uid: string | null, fn: (tx: Tx) => Promise<T>, role: Role = 'authenticated'): Promise<T> {
  const c = await pool.connect();
  try {
    await c.query('begin');
    await c.query(`set local role ${role}`);
    await c.query(`select set_config('request.jwt.claim.sub', $1, true)`, [uid ?? '']);
    await c.query(`select set_config('request.jwt.claim.role', $1, true)`, [role]);
    const out = await fn({ q: (sql, params) => c.query(sql, params) });
    await c.query('commit');
    return out;
  } catch (e) {
    await c.query('rollback').catch(() => {});
    throw e;
  } finally {
    c.release();
  }
}

/** Expect a SQLSTATE from a promise. */
async function expectCode(p: Promise<unknown>, code: string) {
  let err: any = null;
  try {
    await p;
  } catch (e) {
    err = e;
  }
  expect(err, `expected SQLSTATE ${code}, but query succeeded`).not.toBeNull();
  expect(err.code, `expected SQLSTATE ${code}, got ${err.code}: ${err.message}`).toBe(code);
}

const b64 = (b: Buffer) => b.toString('base64');
const rnd = (n: number) => randomBytes(n);

async function createUser(id: string) {
  await pool.query('insert into auth.users(id) values ($1) on conflict do nothing', [id]);
}

async function createSoul(owner: string, name = 'soul'): Promise<string> {
  return as(owner, async (tx) => {
    const r = await tx.q(
      `insert into public.souls(owner, name, salt, wrapped_dk_owner, wrapped_dk_recovery)
       values ($1, $2, $3, $4, $5) returning id`,
      [owner, name, rnd(16), rnd(72), rnd(72)],
    );
    return r.rows[0].id as string;
  });
}

async function createDevice(owner: string, soul: string, approve = true): Promise<string> {
  return as(owner, async (tx) => {
    const r = await tx.q(`insert into public.devices(soul_id, label, pubkey) values ($1, $2, $3) returning id`, [soul, 'dev', rnd(32)]);
    const id = r.rows[0].id as string;
    if (approve) await tx.q(`select public.device_approve($1, $2::jsonb)`, [id, JSON.stringify({ '1': b64(rnd(80)) })]);
    return id;
  });
}

function ev(soul: string, device: string, seq: number) {
  return { soul_id: soul, device_id: device, seq, dk_version: 1, nonce: b64(rnd(24)), ciphertext: b64(rnd(40)) };
}

const A = randomUUID();
const B = randomUUID();

beforeAll(async () => {
  const c = await pool.connect();
  try {
    await c.query('drop schema if exists public cascade');
    await c.query('create schema public');
    await c.query('grant all on schema public to public');
    await c.query('drop schema if exists auth cascade');
    await c.query(readFileSync(AUTH_STUB, 'utf8'));
    await c.query(readFileSync(MIGRATION, 'utf8'));
  } finally {
    c.release();
  }
  await createUser(A);
  await createUser(B);
}, 60_000);

afterAll(async () => {
  await pool.end();
});

describe('RLS: souls and devices are owner-scoped', () => {
  it('owner A inserts a soul; B cannot see it nor add a device to it', async () => {
    const soul = await createSoul(A, 'alpha');

    const mine = await as(A, (tx) => tx.q('select id from public.souls where id = $1', [soul]));
    expect(mine.rowCount).toBe(1);

    const theirs = await as(B, (tx) => tx.q('select id from public.souls where id = $1', [soul]));
    expect(theirs.rowCount).toBe(0);

    await expectCode(
      as(B, (tx) => tx.q(`insert into public.devices(soul_id, label, pubkey) values ($1, 'x', $2)`, [soul, rnd(32)])),
      '42501',
    );

    // B cannot even insert a soul claiming A as owner (with check).
    await expectCode(
      as(B, (tx) =>
        tx.q(`insert into public.souls(owner, name, salt, wrapped_dk_owner, wrapped_dk_recovery) values ($1,'x',$2,$3,$4)`, [
          A,
          rnd(16),
          rnd(72),
          rnd(72),
        ]),
      ),
      '42501',
    );
  });

  it('anon has no access at all (stub grants anon nothing -> 42501)', async () => {
    await createSoul(A, 'anon-check');
    await expectCode(
      as(null, (tx) => tx.q('select count(*)::int as n from public.souls'), 'anon'),
      '42501',
    );
  });
});

describe('events_append', () => {
  it('rejects an unapproved device with 42501', async () => {
    const soul = await createSoul(A);
    const dev = await createDevice(A, soul, false);
    await expectCode(
      as(A, (tx) => tx.q('select public.events_append($1::jsonb)', [JSON.stringify([ev(soul, dev, 1)])])),
      '42501',
    );
  });

  it('rejects a device of another soul, and a non-owner caller', async () => {
    const soulA = await createSoul(A);
    const soulA2 = await createSoul(A);
    const dev = await createDevice(A, soulA);
    // approved device but wrong soul
    await expectCode(
      as(A, (tx) => tx.q('select public.events_append($1::jsonb)', [JSON.stringify([ev(soulA2, dev, 1)])])),
      '42501',
    );
    // B is not the owner
    await expectCode(
      as(B, (tx) => tx.q('select public.events_append($1::jsonb)', [JSON.stringify([ev(soulA, dev, 1)])])),
      '42501',
    );
  });

  it('accepts seq 1,2; rejects duplicate (23505) and gap (P0001); a batch with a gap is atomic', async () => {
    const soul = await createSoul(A);
    const dev = await createDevice(A, soul);

    const n = await as(A, (tx) =>
      tx.q('select public.events_append($1::jsonb) as n', [JSON.stringify([ev(soul, dev, 1), ev(soul, dev, 2)])]),
    );
    expect(n.rows[0].n).toBe(2);

    await expectCode(
      as(A, (tx) => tx.q('select public.events_append($1::jsonb)', [JSON.stringify([ev(soul, dev, 2)])])),
      '23505',
    );
    await expectCode(
      as(A, (tx) => tx.q('select public.events_append($1::jsonb)', [JSON.stringify([ev(soul, dev, 4)])])),
      'P0001',
    );
    // 3 is valid, 5 is a gap -> whole batch must roll back, head stays at 2
    await expectCode(
      as(A, (tx) => tx.q('select public.events_append($1::jsonb)', [JSON.stringify([ev(soul, dev, 3), ev(soul, dev, 5)])])),
      'P0001',
    );
    const heads = await as(A, (tx) => tx.q('select head from public.soul_heads($1)', [soul]));
    expect(heads.rows.map((r) => Number(r.head))).toEqual([2]);

    // unordered batch is sorted by seq before validation
    const n2 = await as(A, (tx) =>
      tx.q('select public.events_append($1::jsonb) as n', [JSON.stringify([ev(soul, dev, 4), ev(soul, dev, 3)])]),
    );
    expect(n2.rows[0].n).toBe(2);
  });

  it('service_role may append on behalf of a harness', async () => {
    const soul = await createSoul(A);
    const dev = await createDevice(A, soul);
    const n = await as(
      null,
      (tx) => tx.q('select public.events_append($1::jsonb) as n', [JSON.stringify([ev(soul, dev, 1)])]),
      'service_role',
    );
    expect(n.rows[0].n).toBe(1);
  });
});

describe('events are immutable', () => {
  it('owner update/delete touch nothing (RLS); trigger raises 42501 for RLS-bypassing roles; direct insert denied', async () => {
    const soul = await createSoul(A);
    const dev = await createDevice(A, soul);
    await as(A, (tx) => tx.q('select public.events_append($1::jsonb)', [JSON.stringify([ev(soul, dev, 1)])]));

    // Owner: there is no update/delete policy, so RLS makes the statement touch 0 rows (no error, nothing changes).
    const up = await as(A, (tx) => tx.q('update public.events set dk_version = 2 where device_id = $1', [dev]));
    expect(up.rowCount).toBe(0);
    // (the auth stub grants authenticated no DELETE privilege, so this is 42501; with a DELETE grant RLS would make it 0 rows)
    try {
      const del = await as(A, (tx) => tx.q('delete from public.events where device_id = $1', [dev]));
      expect(del.rowCount).toBe(0);
    } catch (e: any) {
      expect(e.code).toBe('42501');
    }
    // Anyone who does reach the rows (table owner / service_role, which bypass RLS) is stopped by the trigger.
    await expectCode(pool.query('update public.events set dk_version = 2 where device_id = $1', [dev]), '42501');
    await expectCode(pool.query('delete from public.events where device_id = $1', [dev]), '42501');
    await expectCode(
      as(null, (tx) => tx.q('update public.events set dk_version = 2 where device_id = $1', [dev]), 'service_role'),
      '42501',
    );
    await expectCode(
      as(A, (tx) =>
        tx.q(`insert into public.events(soul_id, device_id, seq, dk_version, nonce, ciphertext) values ($1,$2,2,1,$3,$4)`, [
          soul,
          dev,
          rnd(24),
          rnd(40),
        ]),
      ),
      '42501',
    );
    await expectCode(
      as(null, (tx) => tx.q('delete from public.events where device_id = $1', [dev]), 'service_role'),
      '42501',
    );

    const left = await as(A, (tx) =>
      tx.q('select count(*)::int as n, min(dk_version)::int as v from public.events where device_id = $1', [dev]),
    );
    expect(left.rows[0].n).toBe(1);
    expect(left.rows[0].v).toBe(1);
  });
});

describe('events_since', () => {
  it('returns only rows newer than the per-device since-vector', async () => {
    const soul = await createSoul(A);
    const d1 = await createDevice(A, soul);
    const d2 = await createDevice(A, soul);
    await as(A, (tx) =>
      tx.q('select public.events_append($1::jsonb)', [JSON.stringify([ev(soul, d1, 1), ev(soul, d1, 2), ev(soul, d1, 3)])]),
    );
    await as(A, (tx) => tx.q('select public.events_append($1::jsonb)', [JSON.stringify([ev(soul, d2, 1), ev(soul, d2, 2)])]));

    const all = await as(A, (tx) => tx.q('select device_id, seq::int from public.events_since($1, $2::jsonb)', [soul, '{}']));
    expect(all.rowCount).toBe(5);

    const since = { [d1]: 2 }; // d2 absent -> from 0
    const part = await as(A, (tx) =>
      tx.q('select device_id, seq::int from public.events_since($1, $2::jsonb)', [soul, JSON.stringify(since)]),
    );
    const got = part.rows.map((r) => `${r.device_id === d1 ? 'd1' : 'd2'}:${r.seq}`).sort();
    expect(got).toEqual(['d1:3', 'd2:1', 'd2:2']);

    const limited = await as(A, (tx) => tx.q('select 1 from public.events_since($1, $2::jsonb, 2)', [soul, '{}']));
    expect(limited.rowCount).toBe(2);

    // another user sees nothing through the same RPC (security invoker + RLS)
    const none = await as(B, (tx) => tx.q('select 1 from public.events_since($1, $2::jsonb)', [soul, '{}']));
    expect(none.rowCount).toBe(0);
  });
});

describe('devices: device_approve + devices_guard', () => {
  it('device_approve merges sealed_dks and sets approved_at exactly once', async () => {
    const soul = await createSoul(A);
    const dev = await createDevice(A, soul, false);

    await as(A, (tx) => tx.q('select public.device_approve($1, $2::jsonb)', [dev, JSON.stringify({ '1': 'AAA' })]));
    const first = await as(A, (tx) => tx.q('select sealed_dks, approved_at from public.devices where id = $1', [dev]));
    expect(first.rows[0].sealed_dks).toEqual({ '1': 'AAA' });
    expect(first.rows[0].approved_at).toBeInstanceOf(Date);

    await as(A, (tx) => tx.q('select public.device_approve($1, $2::jsonb)', [dev, JSON.stringify({ '2': 'BBB' })]));
    const second = await as(A, (tx) => tx.q('select sealed_dks, approved_at from public.devices where id = $1', [dev]));
    expect(second.rows[0].sealed_dks).toEqual({ '1': 'AAA', '2': 'BBB' });
    expect(second.rows[0].approved_at.getTime()).toBe(first.rows[0].approved_at.getTime());

    // non-owner cannot approve (RLS hides the row -> not found -> 42501)
    await expectCode(
      as(B, (tx) => tx.q('select public.device_approve($1, $2::jsonb)', [dev, '{"3":"CCC"}'])),
      '42501',
    );
  });

  it('devices_guard forbids changing pubkey, clearing approved_at, and un-revoking', async () => {
    const soul = await createSoul(A);
    const dev = await createDevice(A, soul);

    await expectCode(
      as(A, (tx) => tx.q('update public.devices set pubkey = $2 where id = $1', [dev, rnd(32)])),
      '42501',
    );
    await expectCode(
      as(A, (tx) => tx.q('update public.devices set approved_at = null where id = $1', [dev])),
      '42501',
    );

    // revoke is fine, un-revoke is not
    const rev = await as(A, (tx) => tx.q('update public.devices set revoked_at = now() where id = $1 and revoked_at is null', [dev]));
    expect(rev.rowCount).toBe(1);
    await expectCode(
      as(A, (tx) => tx.q('update public.devices set revoked_at = null where id = $1', [dev])),
      '42501',
    );
    await expectCode(
      as(A, (tx) => tx.q(`update public.devices set revoked_at = now() + interval '1 day' where id = $1`, [dev])),
      '42501',
    );

    // revoked device cannot be re-approved nor append
    await expectCode(
      as(A, (tx) => tx.q('select public.device_approve($1, $2::jsonb)', [dev, '{"2":"x"}'])),
      '42501',
    );
    await expectCode(
      as(A, (tx) => tx.q('select public.events_append($1::jsonb)', [JSON.stringify([ev(soul, dev, 1)])])),
      '42501',
    );
  });
});

describe('soul_rotate_keys', () => {
  it('accepts an increasing version, rejects non-increasing and non-owner', async () => {
    const soul = await createSoul(A);
    await as(A, (tx) => tx.q('select public.soul_rotate_keys($1, $2, $3, 2)', [soul, rnd(72), rnd(72)]));
    const v = await as(A, (tx) => tx.q('select dk_version from public.souls where id = $1', [soul]));
    expect(v.rows[0].dk_version).toBe(2);

    await expectCode(
      as(A, (tx) => tx.q('select public.soul_rotate_keys($1, $2, $3, 2)', [soul, rnd(72), rnd(72)])),
      '23505',
    );
    await expectCode(
      as(A, (tx) => tx.q('select public.soul_rotate_keys($1, $2, $3, 1)', [soul, rnd(72), rnd(72)])),
      '23505',
    );
    await expectCode(
      as(B, (tx) => tx.q('select public.soul_rotate_keys($1, $2, $3, 3)', [soul, rnd(72), rnd(72)])),
      '23505',
    );
  });
});

describe('harness_grants', () => {
  it('scopes check constraint rejects an unknown scope', async () => {
    const soul = await createSoul(A);
    await expectCode(
      as(A, (tx) =>
        tx.q(`insert into public.harness_grants(soul_id, label, scopes, token_hash) values ($1, 'h', $2, $3)`, [
          soul,
          ['events:read', 'souls:delete'],
          rnd(32),
        ]),
      ),
      '23514',
    );
    const ok = await as(A, (tx) =>
      tx.q(`insert into public.harness_grants(soul_id, label, scopes, token_hash) values ($1, 'h', $2, $3) returning id`, [
        soul,
        ['events:read', 'events:append'],
        rnd(32),
      ]),
    );
    expect(ok.rowCount).toBe(1);
  });

  it('grant_by_token_hash resolves only under service_role', async () => {
    const soul = await createSoul(A);
    const hash = rnd(32);
    await as(A, (tx) =>
      tx.q(`insert into public.harness_grants(soul_id, label, scopes, token_hash) values ($1, 'h', $2, $3)`, [soul, ['events:read'], hash]),
    );

    const svc = await as(null, (tx) => tx.q('select soul_id, scopes from public.grant_by_token_hash($1)', [hash]), 'service_role');
    expect(svc.rowCount).toBe(1);
    expect(svc.rows[0].soul_id).toBe(soul);
    expect(svc.rows[0].scopes).toEqual(['events:read']);

    // authenticated: execute is revoked, so it is either denied (42501) or yields no rows. Never a row.
    let rows = 0;
    try {
      const r = await as(A, (tx) => tx.q('select soul_id from public.grant_by_token_hash($1)', [hash]));
      rows = r.rowCount ?? 0;
    } catch (e: any) {
      expect(e.code).toBe('42501');
    }
    expect(rows).toBe(0);

    // owner can still see their own grant through RLS, but not the token of a stranger's soul
    const own = await as(A, (tx) => tx.q('select 1 from public.harness_grants where token_hash = $1', [hash]));
    expect(own.rowCount).toBe(1);
    const other = await as(B, (tx) => tx.q('select 1 from public.harness_grants where token_hash = $1', [hash]));
    expect(other.rowCount).toBe(0);
  });
});
