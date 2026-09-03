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
# (verbs 30078,30080-30086; OC Me 30087; OC Chat 30110-30112 + 30114).
# Reference: https://github.com/hoytech/strfry/blob/master/docs/plugins.md

import json
import re
import sys

ALLOWED_PREFIXES = {
    # 30078 is co-claimed by OC Attest (attestation), OC Lock (device record),
    # OC Pledge, and OC Chat (did:oc session record). Verifiers disambiguate via
    # the envelope's `kind` field.
    #
    # Attest does NOT use a prefix: oc-attest-protocol/SPEC.md L228 and
    # NIP_ORANGECHECK.md L39 both prescribe a BARE `["d", "<attestation_id>"]`.
    # See BARE_ID_KINDS below — requiring an "oc-attest:" prefix here rejected
    # every spec-conformant attestation the SDK has ever published.
    30078: [
        "oc-lock:",  # oc-lock-protocol SPEC.md L71, L337: "oc-lock:device:*"
        "oc-pledge:",
        "oc-pledge-outcome:",
        "oc-pledge-abandonment:",
        # Implementation-only namespace, no spec text yet: oc-chat-web publishes
        # did:oc session records at oc-chat:device:<did_oc> (src/lib/chat/
        # session-binding.ts L75). oc-chat-protocol SPEC §3 says the device
        # record IS the OC Lock §3 record, so this second namespace is
        # undocumented and brand-rooted where the family convention is
        # verb-rooted. Accepted because it is live and load-bearing for chat
        # sign-in; tracked as errata in KINDS.md rather than silently blessed.
        "oc-chat:device:",
    ],
    # oc-vote-protocol SPEC.md L106/L195/L316 and its §12 namespace claim (L528)
    # all use "oc-vote:<type>:" — a COLON after the verb. KINDS.md listed the
    # hyphenated "oc-vote-poll:" form, this table copied it, and so the relay
    # rejected every poll, ballot and reveal the shipped clients emit. Nothing
    # has ever published the hyphenated form; the spec form is the only truth.
    30080: ["oc-vote:poll:"],
    30081: ["oc-vote:ballot:"],
    30082: ["oc-vote:reveal:"],
    # 30083 is co-claimed by OC Stamp (stamp) and OC Agent (delegation).
    30083: ["oc-stamp:", "oc-agent-del:"],
    30084: ["oc-agent-act:"],
    30085: ["oc-agent-rev:"],
    30086: ["oc-agent-sub:"],
    # 30087 is OC Me (me.ochk.io) — billable-event / payment / rebind /
    # payout-binding / distribution / drop envelopes, all disjoint d-tag
    # prefixes on one kind (verifiers also read envelope.kind). This slot was
    # once earmarked for OrangeOS, a speculative project that was never built;
    # OC Me is the real, live owner. Before this the relay mapped 30087 to
    # oc-os-dec: and silently rejected every me.ochk envelope. (30088-30093
    # released with OrangeOS.)
    30087: [
        "oc-me-event:",
        "oc-me-payment:",
        "oc-me-rebind:",
        "oc-me-payout-binding:",
        "oc-me-distribution:",
        "oc-me-drop:",
    ],
    # OC Chat (30110-30114) — a mode of OC Lock; verb-rooted d-tags.
    30110: ["oc-lock-chat-ch:"],
    30111: ["oc-lock-chat-msg:"],
    30112: ["oc-lock-chat-seal:"],
    # 30114 is the discoverability directory: people listings use the
    # oc-lock-chat-dir: namespace (SPEC §8.2.1), channel listings use the
    # distinct oc-lock-chat-chdir: namespace (§8.3 separate-namespace rule).
    30114: ["oc-lock-chat-dir:", "oc-lock-chat-chdir:"],
}

# Kinds where a BARE content-addressed id is a legitimate d-tag, no prefix.
# Only OC Attest: id = sha256(canonical_message), rendered as 64 lowercase hex
# (oc-attest-protocol SPEC.md §7). Anchored exact-match, so this widens the gate
# by exactly one shape and cannot be used to smuggle arbitrary d-tags through.
BARE_ID_KINDS = {30078: re.compile(r"^[0-9a-f]{64}$")}


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
    bare = BARE_ID_KINDS.get(kind)
    if not any(d.startswith(p) for p in allowed) and not (bare and bare.match(d)):
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
