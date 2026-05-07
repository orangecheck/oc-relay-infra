#!/usr/bin/env -S deno run --allow-read=/data/strfry --allow-write=/data/strfry/logs
//
// oc-dtag-filter.ts — strfry write-policy plugin for relay.ochk.io
//
// strfry pipes one JSON message per line on stdin, and the plugin replies
// with one JSON line per message containing {id, action: "accept" | "reject" | "shadowReject", msg?}.
//
// We accept events of the family's eight kinds IFF the event carries a `d`
// tag whose value starts with one of the canonical OC namespace prefixes.
// Everything else is rejected with a stable, machine-readable reason.
//
// Source-of-truth for the prefix table: ~/Projects/ochk/CLAUDE.md and the
// owning protocol spec for each kind.
//
// Reference: https://github.com/hoytech/strfry/blob/master/docs/plugins.md
//            https://github.com/relayable-org/strfry-policies (pattern)

const ALLOWED_PREFIXES: Record<number, readonly string[]> = {
    // 30078 is co-claimed by OC Attest (kind 30078 attestation), OC Lock
    // (device record), and OC Pledge (pledge / pledge-outcome / pledge-
    // abandonment). Verifiers disambiguate via the envelope's `kind` field.
    30078: [
        "oc-attest:",
        "oc-lock:",
        "oc-pledge:",
        "oc-pledge-outcome:",
        "oc-pledge-abandonment:",
    ],
    30080: ["oc-vote-poll:"],
    30081: ["oc-vote-ballot:"],
    30082: ["oc-vote-reveal:"],
    // 30083 is co-claimed by OC Stamp (stamp) and OC Agent (delegation).
    // Disjoint d-tag prefixes; verifiers also see envelope.kind.
    30083: ["oc-stamp:", "oc-agent-del:"],
    30084: ["oc-agent-act:"],
    30085: ["oc-agent-rev:"],
    30086: ["oc-agent-sub:"],
} as const;

interface NostrEvent {
    id: string;
    pubkey: string;
    created_at: number;
    kind: number;
    tags: string[][];
    content: string;
    sig: string;
}

interface InMessage {
    type: "new" | "lookback";
    event: NostrEvent;
    receivedAt: number;
    sourceType: "IP4" | "IP6" | "Import" | "Stream" | "Sync";
    sourceInfo: string;
}

interface OutMessage {
    id: string;
    action: "accept" | "reject" | "shadowReject";
    msg?: string;
}

function dTagOf(event: NostrEvent): string | null {
    for (const tag of event.tags) {
        if (tag.length >= 2 && tag[0] === "d") return tag[1];
    }
    return null;
}

function decide(event: NostrEvent): OutMessage {
    const allowed = ALLOWED_PREFIXES[event.kind];
    if (!allowed) {
        return {
            id: event.id,
            action: "reject",
            msg: `blocked: kind ${event.kind} is not in the oc family allowlist`,
        };
    }
    const dTag = dTagOf(event);
    if (!dTag) {
        return {
            id: event.id,
            action: "reject",
            msg: `blocked: kind ${event.kind} requires a d tag with one of [${allowed.join(", ")}]`,
        };
    }
    const ok = allowed.some((prefix) => dTag.startsWith(prefix));
    if (!ok) {
        return {
            id: event.id,
            action: "reject",
            msg: `blocked: d tag '${dTag.slice(0, 32)}…' does not start with an oc namespace prefix for kind ${event.kind}`,
        };
    }
    return { id: event.id, action: "accept" };
}

const decoder = new TextDecoder();
const encoder = new TextEncoder();

const buf = new Uint8Array(64 * 1024);
let leftover = "";

while (true) {
    const n = await Deno.stdin.read(buf);
    if (n === null) break;
    const chunk = decoder.decode(buf.subarray(0, n));
    const lines = (leftover + chunk).split("\n");
    leftover = lines.pop() ?? "";
    for (const line of lines) {
        if (!line) continue;
        let msg: InMessage;
        try {
            msg = JSON.parse(line);
        } catch {
            // Drop malformed input. Strfry will log the absent reply.
            continue;
        }
        if (msg.type !== "new" && msg.type !== "lookback") continue;
        const out = decide(msg.event);
        await Deno.stdout.write(encoder.encode(JSON.stringify(out) + "\n"));
    }
}
