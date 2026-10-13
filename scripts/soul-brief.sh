#!/usr/bin/env bash
# SessionStart hook for Claude Code: prints a compact brief of the current soul as hook JSON so it
# lands in the model's context before the first prompt. Never prints keys or tokens.
#
# Env (same as soul-mcp):  SOULSOCIETY_HOME (default ~/.soulsociety), SOULSOCIETY_DEVICE_PASSPHRASE
# Exit 0 always; on any failure emits a one-line note instead of a brief so the session still starts.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$REPO/packages/cli/dist/main.js"
export SOULSOCIETY_HOME="${SOULSOCIETY_HOME:-$HOME/.soulsociety}"

emit() { # $1 = text
  node -e 'const t=process.argv[1];process.stdout.write(JSON.stringify({hookSpecificOutput:{hookEventName:"SessionStart",additionalContext:t}}))' "$1"
}

if ! command -v node >/dev/null 2>&1; then [ -s "$HOME/.nvm/nvm.sh" ] && . "$HOME/.nvm/nvm.sh" >/dev/null; fi
if ! command -v node >/dev/null 2>&1 || [ ! -f "$CLI" ] || [ ! -f "$SOULSOCIETY_HOME/config.json" ]; then
  emit "soul: not available (no node, CLI build, or soul config at $SOULSOCIETY_HOME). Work without the soul and say so once if asked."
  exit 0
fi
if [ -z "${SOULSOCIETY_DEVICE_PASSPHRASE:-}" ]; then
  emit "soul: device passphrase not provided to the hook; soul brief skipped. The soul MCP tools may still be available."
  exit 0
fi

STATE="$(timeout 20 node "$CLI" state 2>/dev/null)" || STATE=""
if [ -z "$STATE" ]; then
  emit "soul: could not read state for $SOULSOCIETY_HOME (locked, pending approval, or sync error). Work without the soul and say so once if asked."
  exit 0
fi

node -e '
const s = JSON.parse(process.argv[1]);
const today = new Date().toISOString().slice(0, 10);
const open = Object.values(s.commitments).filter(c => c.status === "open");
const due = open.filter(c => c.by && c.by.slice(0, 10) <= today).map(c => `"${c.text}"${c.by ? " (by " + c.by.slice(0, 10) + ")" : ""}`);
const obs = [...s.observations].sort((a, b) => b.confidence * b.count - a.confidence * a.count).slice(0, 12)
  .map(o => `- [${o.kind}] ${o.text} (${o.confidence.toFixed(2)})`);
const trust = Object.entries(s.trust).map(([k, v]) => `${k}:${v.status}`).join(", ") || "none";
const lines = [
  `# Soul brief (soul-mcp connected as server "soul")`,
  `Name: ${s.name ?? "(unnamed)"} · level ${s.level} · ${s.xp} xp · ${s.eventCount} events · trust: ${trust}`,
  `Open commitments: ${open.length}${due.length ? " · due/overdue: " + due.join("; ") : ""}`,
  obs.length ? `Standing observations (follow without being asked):\n${obs.join("\n")}` : "No observations recorded yet.",
  ``,
  `Before using any soul_* tool, load the soul-companion skill (/soul-companion) and follow it. Call soul_state once for full detail.`,
  `Mention at most one due commitment, once, in plain words. Never nag. Record durable preferences with soul_observe. Only append task.completed if you witnessed completion and it is in allowedAppendTypes.`,
];
process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: lines.join("\n") } }));
' "$STATE"
exit 0
