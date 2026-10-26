#!/bin/sh
# oc-relay-boot: starts relay.ochk.io behind oc-relay-front.
#
# Once per volume it first rewrites the event store through strfry export and
# import, into a new file. An imported event carries no source address (strfry
# 0.9.7 cmd_import.cpp:58), and a new file holds none of the stale page copies
# LMDB leaves behind, so no address strfry stored before the front survives.
# The rewrite is kept only when the new store holds exactly the old one's event
# ids; otherwise the relay starts on the old store and tries again next start.
set -u

DB=${OC_RELAY_DB:-/data/strfry/db}
CONF=${OC_RELAY_CONF:-/etc/strfry.conf}
STRFRY=${OC_RELAY_STRFRY:-/app/strfry}
FRONT=${OC_RELAY_FRONT:-/usr/local/bin/oc-relay-front}
DONE="$DB/.sources-cleared-1"

say() { echo "oc-relay-boot: $*"; }

# The sorted event ids of a JSONL export; fails, with no pipe to hide it, on an unreadable line.
ids() {
    python3 -c 'import json, sys
sys.stdout.write("".join(i + "\n" for i in sorted(json.loads(l)["id"] for l in sys.stdin if l.strip())))'
}

rewrite() {
    next="$DB/next"
    rm -rf "$next" && mkdir -p "$next" || return 1
    sed "s#^db = .*#db = \"$next/\"#" "$CONF" > "$next/strfry.conf" || return 1
    grep -q "^db = \"$next/\"" "$next/strfry.conf" || return 1
    "$STRFRY" --config="$CONF" export > "$next/old.jsonl" || return 1
    "$STRFRY" --config="$next/strfry.conf" import < "$next/old.jsonl" || return 1
    "$STRFRY" --config="$next/strfry.conf" export > "$next/new.jsonl" || return 1
    ids < "$next/old.jsonl" > "$next/old.ids" || return 1
    ids < "$next/new.jsonl" > "$next/new.ids" || return 1
    if ! cmp -s "$next/old.ids" "$next/new.ids"; then
        say "the new store holds $(wc -l < "$next/new.ids") of $(wc -l < "$next/old.ids") events; keeping the old one"
        return 1
    fi
    mv "$next/data.mdb" "$DB/data.mdb" || return 1
    rm -f "$DB/lock.mdb"
    touch "$DONE"
    say "rewrote the store: $(wc -l < "$next/new.ids") events, no source addresses"
}

if [ ! -e "$DONE" ]; then
    if ! rewrite; then
        say "store rewrite failed; starting on the old store"
    fi
    rm -rf "$DB/next"
fi

exec "$FRONT" "$STRFRY" --config="$CONF" relay
