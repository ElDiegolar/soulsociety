import { describe, expect, it } from 'vitest';
import { makeEvent, validateEvent, SchemaError } from '../src/schema.js';
import { emptyState, orderEntries, replay, type ReplayEntry } from '../src/replay.js';

function e(deviceId: string, seq: number, ts: string, type: Parameters<typeof makeEvent>[0], data: any): ReplayEntry {
  return { deviceId, seq, event: makeEvent(type, data, new Date(ts)) };
}

describe('replay', () => {
  it('is deterministic regardless of input order', async () => {
    const entries: ReplayEntry[] = [
      e('b', 1, '2026-01-01T00:00:02Z', 'task.completed', { taskId: 't2', title: 'two', witnessed: true }),
      e('a', 1, '2026-01-01T00:00:00Z', 'soul.created', { name: 'kai' }),
      e('a', 2, '2026-01-01T00:00:01Z', 'task.completed', { taskId: 't1', title: 'one', witnessed: true }),
      e('a', 3, '2026-01-01T00:00:03Z', 'draft.approved', { draftId: 'd1', kind: 'email' }),
    ];
    const s1 = await replay(entries);
    const s2 = await replay([...entries].reverse());
    expect(s1.replayHash).toBe(s2.replayHash);
    expect(s1.xp).toBe(35);
    expect(s1.name).toBe('kai');
    expect(s1.heads).toEqual({ a: 3, b: 1 });
  });

  it('breaks ts ties by deviceId then seq', () => {
    const o = orderEntries([
      e('b', 1, '2026-01-01T00:00:00Z', 'note', { text: 'b1' }),
      e('a', 2, '2026-01-01T00:00:00Z', 'note', { text: 'a2' }),
      e('a', 1, '2026-01-01T00:00:00Z', 'note', { text: 'a1' }),
    ]);
    expect(o.map((x) => `${x.deviceId}${x.seq}`)).toEqual(['a1', 'a2', 'b1']);
  });

  it('levels, trust demotion and commitments', async () => {
    const entries: ReplayEntry[] = [];
    let seq = 0;
    const t = (i: number) => new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString();
    for (let i = 0; i < 10; i++) entries.push(e('a', ++seq, t(seq), 'task.completed', { taskId: `t${i}`, title: 'x', witnessed: true }));
    entries.push(e('a', ++seq, t(seq), 'trust.offered', { capability: 'send_email', level: 2 }));
    entries.push(e('a', ++seq, t(seq), 'trust.accepted', { capability: 'send_email' }));
    entries.push(e('a', ++seq, t(seq), 'trust.failed', { capability: 'send_email', reason: 'x' }));
    entries.push(e('a', ++seq, t(seq), 'commitment.made', { id: 'c1', text: 'ship it' }));
    entries.push(e('a', ++seq, t(seq), 'commitment.kept', { id: 'c1' }));
    entries.push(e('a', ++seq, t(seq), 'commitment.kept', { id: 'c1' })); // duplicate ignored
    let s = await replay(entries);
    expect(s.xp).toBe(100);
    expect(s.level).toBe(2);
    expect(s.trust['send_email']).toEqual({ level: 2, status: 'accepted', failures: 1 });
    expect(s.commitments['c1']?.status).toBe('kept');
    entries.push(e('a', ++seq, t(seq), 'trust.failed', { capability: 'send_email', reason: 'y' }));
    s = await replay(entries);
    expect(s.trust['send_email']?.status).toBe('revoked');
  });

  it('unknown event types are counted but do not change state', async () => {
    const s = await replay([
      { deviceId: 'a', seq: 1, event: validateEvent({ v: 1, ts: '2026-01-01T00:00:00Z', type: 'future.thing', data: { x: 1 } }) },
    ]);
    expect(s.counts['future.thing']).toBe(1);
    expect(s.xp).toBe(0);
  });

  it('incremental replay from a prior state equals full replay', async () => {
    const a = e('a', 1, '2026-01-01T00:00:00Z', 'soul.created', { name: 'k' });
    const b = e('a', 2, '2026-01-01T00:00:01Z', 'task.completed', { taskId: 't', title: 'x', witnessed: true });
    const full = await replay([a, b]);
    const partial = await replay([a], emptyState());
    const inc = await replay([b], partial);
    expect(inc.replayHash).toBe(full.replayHash);
    expect(inc.xp).toBe(full.xp);
  });
});

describe('schema', () => {
  it('rejects forbidden engagement inputs', () => {
    expect(() => validateEvent({ v: 1, ts: '2026-01-01T00:00:00Z', type: 'note', data: { text: 'hi', streak: 5 } })).toThrow(SchemaError);
  });
  it('rejects unwitnessed task completion', () => {
    expect(() =>
      validateEvent({ v: 1, ts: '2026-01-01T00:00:00Z', type: 'task.completed', data: { taskId: 't', title: 'x', witnessed: false } }),
    ).toThrow(SchemaError);
  });
  it('rejects bad timestamps and types', () => {
    expect(() => validateEvent({ v: 1, ts: 'yesterday', type: 'note', data: { text: 'x' } })).toThrow(SchemaError);
    expect(() => validateEvent({ v: 1, ts: '2026-01-01T00:00:00Z', type: 'Bad Type', data: {} })).toThrow(SchemaError);
  });
});

describe('observations', () => {
  it('dedups by text, raises confidence, retracts, and stays bounded', async () => {
    const { makeEvent } = await import('../src/schema.js');
    const { replay, MAX_OBSERVATIONS } = await import('../src/replay.js');
    const t = (i: number) => new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString();
    const entries: any[] = [];
    let seq = 0;
    entries.push({
      deviceId: 'a',
      seq: ++seq,
      event: makeEvent('observation', { kind: 'preference', text: 'likes short answers', confidence: 0.4 }, new Date(t(seq))),
    });
    entries.push({
      deviceId: 'a',
      seq: ++seq,
      event: makeEvent('observation', { kind: 'preference', text: 'likes short answers', confidence: 0.9 }, new Date(t(seq))),
    });
    entries.push({
      deviceId: 'a',
      seq: ++seq,
      event: makeEvent('observation', { kind: 'dislike', text: 'hates nagging' }, new Date(t(seq))),
    });
    let s = await replay(entries);
    expect(s.observations.length).toBe(2);
    expect(s.observations[0]).toMatchObject({ text: 'likes short answers', count: 2, confidence: 0.9 });
    entries.push({ deviceId: 'a', seq: ++seq, event: makeEvent('observation.retracted', { text: 'hates nagging' }, new Date(t(seq))) });
    s = await replay(entries);
    expect(s.observations.map((o) => o.text)).toEqual(['likes short answers']);
    for (let i = 0; i < MAX_OBSERVATIONS + 20; i++)
      entries.push({
        deviceId: 'a',
        seq: ++seq,
        event: makeEvent('observation', { kind: 'fact', text: `fact ${i}`, confidence: 0.1 }, new Date(t(seq))),
      });
    s = await replay(entries);
    expect(s.observations.length).toBe(MAX_OBSERVATIONS);
    expect(s.observations.some((o) => o.text === 'likes short answers')).toBe(true); // strongest survives
  });
});
