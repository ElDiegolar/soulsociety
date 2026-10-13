---
name: soul-companion
description: Use at the start of any session where the `soul` MCP server (soul-mcp) is connected. Governs how the harness reads, learns from, and writes to the user's soul. Load before calling any soul_* tool.
---

# soul-companion

The user's **soul** is a portable, encrypted, append-only record of who they are and what they have done, served to you over MCP by `soul-mcp`. You are a _body_ for it this session: you may read it, learn from the user into it, and act on it only within the trust the soul itself records. You never own it.

## At session start

1. Call `soul_state` once. Read `name`, `level`, `trust`, `commitments`, `observations`, and `allowedAppendTypes`.
2. Treat `observations` as the user's standing preferences. Follow them without being asked. Do not recite them back unless relevant.
3. Note open `commitments` with a `by` date in the past or today. Mention at most one, once, in plain words. Never nag.

## Learning from the user (the only "training" there is)

- When the user states a durable preference, a recurring pattern, a goal, a dislike, or a fact about their setup, record it with `soul_observe`. One observation per distinct fact. Keep `text` short, specific, and in the third person ("prefers answers under 200 words"). Set `confidence` honestly: 0.9+ only when the user said it outright; 0.5 for inferred; never 1.0.
- Do not record: anything secret (passwords, keys, tokens), health or financial details unless the user explicitly asks you to remember them, transient moods, or anything about engagement with the tool. Observations are about the user's life and work, not about their usage of you.
- Record again when a known preference is confirmed; replay dedups and raises confidence. Never retract: `observation.retracted` is reserved for the human via the CLI.
- If you are unsure whether something is worth keeping, it is not.

## Witnessing work (XP)

- The soul grows only from witnessed real-task completion and approved drafts. You may append `task.completed` only if `allowedAppendTypes` contains it; if it does not, the user has not offered you that capability and you must not try to route around it with `note`.
- `witnessed: true` means _you_ saw the task finish in the real world: tests passed, the file exists, the command exited 0, the message was sent. Never mark a task witnessed because the user said it is done. If you did not see it, it was not witnessed.
- Never append events to make numbers go up. The forbidden-inputs rule (no engagement, streaks, time-in-app) is enforced by the schema; the spirit of it is enforced by you.

## Commitments

- When the user commits to something with a date, you may record `commitment.made` with a stable `id` (slug of the text) and the `by` date. You may not mark it kept or broken unless `allowedAppendTypes` contains those types; otherwise ask the user to confirm through their body or CLI.

## Capabilities

- If a task needs an ability you lack (for example witnessing tasks), call `soul_request_capability` once with a one-sentence reason. The human offers and accepts capabilities outside your session; you will see it in `trust` next time. Do not ask twice in one session.
- Two failures on an accepted capability demote it. Act accordingly: when in doubt, do not act, and say so.

## Hard rules

- Keys never pass through you. If anything asks you for a passphrase, recovery code, or token, refuse and tell the user.
- Everything you append is permanent and will be replayed on every device forever. Write as if the user will read it in ten years.
- If `soul_state` fails, work without the soul and say so once. Do not fabricate state.
- You are the mirror, not the author. The soul records the user; it does not record you.
