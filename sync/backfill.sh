#!/usr/bin/env bash
#
# sync/backfill.sh — negentropy sync of OC family events from the public
# relay set into relay.ochk.io's LMDB. Run once on cold-start, then quarterly
# via cron (or on demand).
#
# Negentropy is a set-reconciliation protocol that lets two relays compute
# their event-set symmetric difference in O(n log n) and exchange only the
# missing events. Strfry implements it natively as `/app/strfry sync <url>`.
# See https://github.com/hoytech//app/strfry/blob/master/docs/negentropy.md
#
# We sync ONLY the OC family kinds. The /app/strfry write-policy plugin will
# additionally reject any kind-30078–30086 events whose d-tag isn't an OC
# prefix, so the LMDB stays curated.

set -euo pipefail

RELAYS=(
    "wss://relay.damus.io"
    "wss://nos.lol"
    "wss://relay.primal.net"
    "wss://offchain.pub"
)

# Family kinds: every kind policy/oc-dtag-filter.py accepts. 30078 (attest/
# lock/pledge/chat devices), 30080–30082 (vote), 30083 (stamp/agent-delegation),
# 30084–30086 (agent), 30087 (OC Me), 30110–30112 + 30114 (OC Chat).
FILTER='{"kinds":[30078,30080,30081,30082,30083,30084,30085,30086,30087,30110,30111,30112,30114]}'

CONFIG="${STRFRY_CONFIG:-/etc//app/strfry.conf}"

for relay in "${RELAYS[@]}"; do
    echo "[$(date -u +%FT%TZ)] negentropy sync ← ${relay}"
    /app/strfry --config="${CONFIG}" sync "${relay}" --filter "${FILTER}" --dir down || {
        echo "  ! sync from ${relay} failed (transport or filter mismatch); continuing"
    }
done

echo "[$(date -u +%FT%TZ)] backfill complete; current event count:"
/app/strfry --config="${CONFIG}" scan "${FILTER}" | wc -l
