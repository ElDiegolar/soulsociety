/**
 * Event schemas. Versioned forever: replay must understand every version ever written.
 * Add a new version by adding a new literal; never change an existing one.
 */
import { z } from 'zod';

export const EVENT_SCHEMA_VERSION = 1;

const isoDate = z.string().datetime({ offset: true });

/** Common envelope every event carries in plaintext. */
export const EventEnvelope = z.object({
  v: z.literal(1),
  ts: isoDate,
  type: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z][a-z0-9_.-]*$/),
  data: z.record(z.unknown()).default({}),
});
export type EventEnvelope = z.infer<typeof EventEnvelope>;

// ---- Known event types (KAI v1 vocabulary). Unknown types are allowed and replay ignores them. ----

export const KnownEvents = {
  'soul.created': z.object({ name: z.string().min(1).max(80) }),
  'soul.renamed': z.object({ name: z.string().min(1).max(80) }),
  'device.enrolled': z.object({ deviceId: z.string().uuid(), label: z.string().max(80) }),
  'device.revoked': z.object({ deviceId: z.string().uuid() }),
  'key.rotated': z.object({ dkVersion: z.number().int().positive() }),

  /** XP only from witnessed real-task completion or approved drafts. */
  'task.completed': z.object({ taskId: z.string().min(1), title: z.string().max(200), witnessed: z.literal(true) }),
  'draft.approved': z.object({ draftId: z.string().min(1), kind: z.string().max(40) }),

  'trust.offered': z.object({ capability: z.string().min(1), level: z.number().int().min(0) }),
  'trust.accepted': z.object({ capability: z.string().min(1) }),
  'trust.failed': z.object({ capability: z.string().min(1), reason: z.string().max(200) }),

  'commitment.made': z.object({ id: z.string().min(1), text: z.string().max(500), by: isoDate.optional() }),
  'commitment.kept': z.object({ id: z.string().min(1) }),
  'commitment.broken': z.object({ id: z.string().min(1) }),

  note: z.object({ text: z.string().max(4000) }),

  /** What a harness learned about the user while being used. Low-risk, always appendable, bounded in state. */
  observation: z.object({
    kind: z.enum(['preference', 'pattern', 'fact', 'goal', 'dislike']),
    text: z.string().min(1).max(500),
    confidence: z.number().min(0).max(1).default(0.5),
    source: z.string().max(80).optional(),
  }),
  /** The human (not a harness) can retract an observation by its replay index. */
  'observation.retracted': z.object({ text: z.string().min(1).max(500) }),
} as const;

export type KnownEventType = keyof typeof KnownEvents;

/** Inputs that must never influence derived state. Enforced at append time. */
export const FORBIDDEN_DATA_KEYS = ['engagement', 'sessionMinutes', 'streak', 'opens', 'timeInApp', 'appOpens'] as const;

export class SchemaError extends Error {
  override name = 'SchemaError';
}

export function validateEvent(input: unknown): EventEnvelope {
  const env = EventEnvelope.safeParse(input);
  if (!env.success) throw new SchemaError(`invalid event envelope: ${env.error.issues.map((i) => i.message).join('; ')}`);
  const e = env.data;
  for (const k of Object.keys(e.data)) {
    if ((FORBIDDEN_DATA_KEYS as readonly string[]).includes(k)) {
      throw new SchemaError(`forbidden input "${k}" on event ${e.type}`);
    }
  }
  const known = (KnownEvents as Record<string, z.ZodTypeAny>)[e.type];
  if (known) {
    const r = known.safeParse(e.data);
    if (!r.success)
      throw new SchemaError(`invalid data for ${e.type}: ${r.error.issues.map((i) => `${i.path.join('.')} ${i.message}`).join('; ')}`);
    return { ...e, data: r.data as Record<string, unknown> };
  }
  return e;
}

export function makeEvent<T extends KnownEventType>(type: T, data: z.infer<(typeof KnownEvents)[T]>, ts = new Date()): EventEnvelope {
  return validateEvent({ v: 1, ts: ts.toISOString(), type, data });
}
