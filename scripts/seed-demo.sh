#!/usr/bin/env bash
# Seed three generic demo souls on the file backend so harnesses and UIs have something realistic to read.
# Each soul lives in its own SOULSOCIETY_HOME under $DEMO_ROOT and all share one host file (like one hosted account).
#
#   bash scripts/seed-demo.sh            # creates ~/.soulsociety-demo/{atlas,sprout,ember}
#   DEMO_ROOT=/tmp/demo bash scripts/seed-demo.sh
#
# Afterwards:  SOULSOCIETY_HOME=~/.soulsociety-demo/atlas SOULSOCIETY_DEVICE_PASSPHRASE=demo node packages/cli/dist/main.js state
set -euo pipefail
cd "$(dirname "$0")/.."
command -v node >/dev/null || { [ -s "$HOME/.nvm/nvm.sh" ] && . "$HOME/.nvm/nvm.sh"; }
[ -f packages/cli/dist/main.js ] || npm run build >/dev/null

DEMO_ROOT="${DEMO_ROOT:-$HOME/.soulsociety-demo}"
HOST="$DEMO_ROOT/host.json"
CLI="node $PWD/packages/cli/dist/main.js"
export SOULSOCIETY_DEVICE_PASSPHRASE=demo SOULSOCIETY_OWNER_PASSPHRASE=demo-owner-passphrase

rm -rf "$DEMO_ROOT"; mkdir -p "$DEMO_ROOT"
MANIFEST="$DEMO_ROOT/MANIFEST.txt"
: > "$MANIFEST"

mk() { # name label
  local home="$DEMO_ROOT/$1"
  SOULSOCIETY_HOME=$home $CLI config --backend file >/dev/null
  node -e "const fs=require('fs');const p='$home/config.json';const c=JSON.parse(fs.readFileSync(p,'utf8'));c.hostFile='$HOST';fs.writeFileSync(p,JSON.stringify(c))"
  SOULSOCIETY_HOME=$home $CLI create --name "$1" --label "$2" > "$home/create.out"
  { echo "== $1"; cat "$home/create.out"; echo; } >> "$MANIFEST"
}
ap() { # name type json
  SOULSOCIETY_HOME="$DEMO_ROOT/$1" $CLI append "$2" "$3" --no-push >/dev/null
}
push() { SOULSOCIETY_HOME="$DEMO_ROOT/$1" $CLI sync >/dev/null; }

# ---------- atlas: a seasoned dev companion, level 2, trusted to witness tasks, lots of observations ----------
mk atlas laptop
for i in $(seq 1 12); do ap atlas task.completed "{\"taskId\":\"pr-$i\",\"title\":\"ship PR #$i\",\"witnessed\":true}"; done
ap atlas draft.approved '{"draftId":"d-standup","kind":"standup"}'
ap atlas trust.offered '{"capability":"witness_tasks","level":2}'
ap atlas trust.accepted '{"capability":"witness_tasks"}'
ap atlas trust.offered '{"capability":"manage_commitments","level":2}'
ap atlas trust.accepted '{"capability":"manage_commitments"}'
ap atlas observation '{"kind":"preference","text":"prefers answers under 200 words with the conclusion first","confidence":0.9,"source":"stated"}'
ap atlas observation '{"kind":"pattern","text":"does deep work before 11:00 and reviews PRs after lunch","confidence":0.6,"source":"inferred"}'
ap atlas observation '{"kind":"fact","text":"works in a Node/TypeScript monorepo with vitest and Supabase","confidence":0.95,"source":"stated"}'
ap atlas observation '{"kind":"dislike","text":"dislikes being reminded of the same thing twice in a session","confidence":0.9,"source":"stated"}'
ap atlas observation '{"kind":"goal","text":"wants to ship a beta of the companion app this quarter","confidence":0.7,"source":"stated"}'
ap atlas commitment.made '{"id":"write-adr-sync","text":"write the ADR for the sync protocol","by":"2026-10-20T00:00:00Z"}'
ap atlas commitment.made '{"id":"fix-flaky-e2e","text":"fix the flaky e2e test","by":"2026-10-10T00:00:00Z"}'
ap atlas commitment.kept '{"id":"fix-flaky-e2e"}'
ap atlas note '{"text":"first session with the new harness went well"}'
push atlas

# ---------- sprout: brand new, nothing learned yet, one open commitment ----------
mk sprout phone
ap sprout commitment.made '{"id":"read-design-doc","text":"read DESIGN.md end to end","by":"2026-10-15T00:00:00Z"}'
ap sprout observation '{"kind":"fact","text":"is new to the companion; no preferences recorded yet","confidence":0.5,"source":"onboarding"}'
push sprout

# ---------- ember: history with a broken commitment, a demoted capability, and a revoked device ----------
mk ember desktop
for i in $(seq 1 4); do ap ember task.completed "{\"taskId\":\"chore-$i\",\"title\":\"chore $i\",\"witnessed\":true}"; done
ap ember trust.offered '{"capability":"approve_drafts","level":1}'
ap ember trust.accepted '{"capability":"approve_drafts"}'
ap ember trust.failed '{"capability":"approve_drafts","reason":"approved a draft the user had rejected"}'
ap ember trust.failed '{"capability":"approve_drafts","reason":"sent before approval"}'
ap ember commitment.made '{"id":"call-bank","text":"call the bank about the card","by":"2026-10-01T00:00:00Z"}'
ap ember commitment.broken '{"id":"call-bank"}'
ap ember observation '{"kind":"preference","text":"wants to be asked before anything is sent on their behalf","confidence":0.95,"source":"stated after incident"}'
ap ember observation '{"kind":"pattern","text":"tends to over-commit on Mondays","confidence":0.4,"source":"inferred"}'
push ember
# second device for ember, then revoke it so the soul carries a rotation in its history
EMBER_SOUL=$(awk '/^soul/{print $2}' "$DEMO_ROOT/ember/create.out")
EMBER_RC=$(tail -1 "$DEMO_ROOT/ember/create.out" | tr -d ' ')
SOULSOCIETY_HOME="$DEMO_ROOT/ember-old-laptop" $CLI config --backend file >/dev/null
node -e "const fs=require('fs');const p='$DEMO_ROOT/ember-old-laptop/config.json';const c=JSON.parse(fs.readFileSync(p,'utf8'));c.hostFile='$HOST';fs.writeFileSync(p,JSON.stringify(c))"
OLD=$(SOULSOCIETY_HOME="$DEMO_ROOT/ember-old-laptop" $CLI enrol --soul "$EMBER_SOUL" --label old-laptop | awk '/^pending device/{print $3}')
SOULSOCIETY_RECOVERY_CODE="$EMBER_RC" SOULSOCIETY_HOME="$DEMO_ROOT/ember" $CLI approve --recovery "$OLD" >/dev/null
SOULSOCIETY_HOME="$DEMO_ROOT/ember-old-laptop" $CLI activate >/dev/null
SOULSOCIETY_RECOVERY_CODE="$EMBER_RC" SOULSOCIETY_HOME="$DEMO_ROOT/ember" $CLI revoke "$OLD" >/dev/null
push ember

# a harness grant per soul, recorded in the manifest
for s in atlas sprout ember; do
  { echo "== grant for $s"; SOULSOCIETY_HOME="$DEMO_ROOT/$s" $CLI grant demo-harness; echo; } >> "$MANIFEST"
done

echo "seeded under $DEMO_ROOT (manifest with soul ids, recovery codes and harness tokens: $MANIFEST)"
for s in atlas sprout ember; do
  SOULSOCIETY_HOME="$DEMO_ROOT/$s" $CLI state | node -e "let b='';process.stdin.on('data',d=>b+=d).on('end',()=>{const j=JSON.parse(b);console.log('$s'.padEnd(7),'level',j.level,'xp',String(j.xp).padStart(4),'events',String(j.eventCount).padStart(3),'obs',j.observations.length,'commitments',Object.values(j.commitments).map(c=>c.id+':'+c.status).join(',')||'-','trust',Object.entries(j.trust).map(([k,v])=>k+':'+v.status).join(',')||'-','dk v'+j.dkVersion)})"
done
echo
echo "use one from Claude Code:"
echo "  claude mcp add soul -e SOULSOCIETY_HOME=$DEMO_ROOT/atlas -e SOULSOCIETY_DEVICE_PASSPHRASE=demo -- node $PWD/packages/mcp/dist/main.js"
