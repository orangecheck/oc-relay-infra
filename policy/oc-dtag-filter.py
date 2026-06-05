#!/usr/bin/env python3
# oc-dtag-filter.py — strfry write-policy plugin for relay.ochk.io
#
# Musl-native (Python on Alpine) replacement for the original Deno plugin, which
# was a glibc-linked binary on this musl/Alpine base: it could not run, so strfry
# rejected EVERY event with "internal error" and the relay stored nothing from
# 2026-05-08 until this rewrite. strfry has NO built-in kind allowlist, so this
# plugin is the ONLY kind/d-tag gate — without it the relay accepts every kind.
#
# Protocol: strfry pipes one JSON message per line on stdin; we reply with one
# JSON line per message: {"id":..,"action":"accept"|"reject"|"shadowReject","msg"?:..}.
# We accept events of the family's kinds IFF the event carries a `d` tag whose
# value starts with one of the canonical OC namespace prefixes; everything else
# is rejected with a stable, machine-readable reason.
#
# Source of truth for the prefix table: workspace KINDS.md / CLAUDE.md
# (verbs 30078,30080-30086; OrangeOS 30087-30093; OC Chat 30110-30112).
# Reference: https://github.com/hoytech/strfry/blob/master/docs/plugins.md

import json
import sys

ALLOWED_PREFIXES = {
    # 30078 is co-claimed by OC Attest (attestation), OC Lock (device record),
    # and OC Pledge. Verifiers disambiguate via the envelope's `kind` field.
    30078: ["oc-attest:", "oc-lock:", "oc-pledge:", "oc-pledge-outcome:", "oc-pledge-abandonment:"],
    30080: ["oc-vote-poll:"],
    30081: ["oc-vote-ballot:"],
    30082: ["oc-vote-reveal:"],
    # 30083 is co-claimed by OC Stamp (stamp) and OC Agent (delegation).
    30083: ["oc-stamp:", "oc-agent-del:"],
    30084: ["oc-agent-act:"],
    30085: ["oc-agent-rev:"],
    30086: ["oc-agent-sub:"],
    # OrangeOS (30087-30093).
    30087: ["oc-os-dec:"],
    30088: ["oc-fs:"],
    30089: ["oc-os-rec:"],
    30090: ["oc-os-erev:"],
    30091: ["oc-os-succ:"],
    30092: ["oc-os-ckpt:"],
    30093: ["oc-pkg:"],
    # OC Chat (30110-30112) — a mode of OC Lock; verb-rooted d-tags.
    30110: ["oc-lock-chat-ch:"],
    30111: ["oc-lock-chat-msg:"],
    30112: ["oc-lock-chat-seal:"],
}


def d_tag_of(event):
    for tag in event.get("tags", []):
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "d":
            return tag[1]
    return None


def decide(event):
    eid = event.get("id", "")
    kind = event.get("kind")
    allowed = ALLOWED_PREFIXES.get(kind)
    if allowed is None:
        return {"id": eid, "action": "reject",
                "msg": "blocked: kind %s is not in the oc family allowlist" % kind}
    d = d_tag_of(event)
    if d is None:
        return {"id": eid, "action": "reject",
                "msg": "blocked: kind %s requires a d tag with one of %s" % (kind, allowed)}
    if not any(d.startswith(p) for p in allowed):
        return {"id": eid, "action": "reject",
                "msg": "blocked: d tag '%s' is not an oc namespace prefix for kind %s" % (d[:32], kind)}
    return {"id": eid, "action": "accept"}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            continue
        if msg.get("type") not in ("new", "lookback"):
            continue
        out = decide(msg.get("event", {}))
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
