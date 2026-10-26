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
import os
import re
import select
import subprocess
import sys
import time

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
    # 30087 is OC Me (me.ochk.io) — billable-event / payment / rebind / trust /
    # payout-binding / distribution / distribution-void / drop envelopes, all disjoint d-tag
    # prefixes on one kind (verifiers also read envelope.kind). This slot was
    # once earmarked for OrangeOS, a speculative project that was never built;
    # OC Me is the real, live owner. Before this the relay mapped 30087 to
    # oc-os-dec: and silently rejected every me.ochk envelope. (30088-30093
    # released with OrangeOS.)
    30087: [
        "oc-me-event:",
        "oc-me-payment:",
        "oc-me-rebind:",
        "oc-me-trust:",
        "oc-me-payout-binding:",
        "oc-me-distribution:",
        "oc-me-distribution-void:",
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


# Kind 30114 is the OC Chat directory. relay.ochk.io is its named directory
# relay (oc-chat-protocol SPEC §8.2.6), so a 30114 event that passes the prefix
# gate is also checked against the claim rule by a Node sidecar that runs the
# rule's one implementation (@orangecheck/lock-core/directory). strfry waits for
# each answer before the next event, so the sidecar gets GATE_TIMEOUT_S; a late,
# dead or garbled sidecar is a refusal, never an admission. Other kinds never
# reach it.
DIR_KIND = 30114
GATE_CMD = json.loads(os.environ.get("OC_DIR_GATE_CMD") or "null") or [
    "/opt/node/lib/ld-musl-x86_64.so.1", "--library-path", "/opt/node/lib",
    "/opt/node/bin/node", "/data/strfry/policy/dir-gate/gate.mjs",
]
GATE_TIMEOUT_S = float(os.environ.get("OC_DIR_GATE_TIMEOUT_S") or "3.0")
GATE_BUSY = "rate-limited: directory check busy, try again"
# Why the bridge refused, counted per UTC day beside the sidecar's own counts.
BRIDGE_COUNTS = os.environ.get("OC_DIR_GATE_BRIDGE_COUNTS", "/data/strfry/db/dir-gate-bridge-counts.json")


def count_refusal(why, path=BRIDGE_COUNTS):
    days = {}
    try:
        with open(path) as f:
            days = json.load(f)
        if not isinstance(days, dict):
            days = {}
    except Exception:
        pass
    today = days.setdefault(time.strftime("%Y-%m-%d", time.gmtime()), {})
    today[why] = today.get(why, 0) + 1
    try:
        days = {k: days[k] for k in sorted(days)[-14:]}
        with open(path + ".tmp", "w") as f:
            json.dump(days, f)
        os.replace(path + ".tmp", path)
    except Exception:
        pass
    sys.stderr.write("oc-dtag-filter: directory check refused (%s, %d today)\n" % (why, today[why]))
    sys.stderr.flush()


class DirGate:
    def __init__(self, cmd, timeout):
        self.cmd = cmd
        self.timeout = timeout
        self.proc = None
        self.buf = b""

    def _stop(self):
        if self.proc is not None:
            try:
                self.proc.kill()
                self.proc.wait(timeout=1)
            except Exception:
                pass
        self.proc = None
        self.buf = b""

    def ask(self, eid, msg):
        try:
            if self.proc is None or self.proc.poll() is not None:
                self._stop()
                self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            line = json.dumps({"id": eid, "event": msg.get("event", {}),
                               "sourceType": msg.get("sourceType"), "sourceInfo": msg.get("sourceInfo")})
            self.proc.stdin.write(line.encode() + b"\n")
            self.proc.stdin.flush()
            fd = self.proc.stdout.fileno()
            deadline = time.monotonic() + self.timeout
            while True:
                while b"\n" in self.buf:
                    raw, self.buf = self.buf.split(b"\n", 1)
                    try:
                        ans = json.loads(raw)
                    except Exception:
                        continue
                    if not isinstance(ans, dict) or ans.get("id") != eid:
                        continue
                    if ans.get("action") == "accept":
                        return {"id": eid, "action": "accept"}
                    reason = ans.get("msg")
                    if ans.get("action") == "reject" and isinstance(reason, str) and reason:
                        return {"id": eid, "action": "reject", "msg": reason[:200]}
                    raise ValueError("garbled answer")
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError()
                ready, _, _ = select.select([fd], [], [], left)
                if not ready:
                    raise TimeoutError()
                chunk = os.read(fd, 65536)
                if not chunk:
                    raise EOFError()
                self.buf += chunk
        except Exception as err:
            # A late answer must never be read as the next event's, so the sidecar goes.
            self._stop()
            why = {TimeoutError: "timeout", EOFError: "sidecar exited", BrokenPipeError: "sidecar exited",
                   ValueError: "garbled answer", FileNotFoundError: "sidecar did not start",
                   PermissionError: "sidecar did not start"}.get(type(err), "bridge error")
            count_refusal(why)
            return {"id": eid, "action": "reject", "msg": GATE_BUSY}


def main():
    gate = DirGate(GATE_CMD, GATE_TIMEOUT_S)
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
        event = msg.get("event", {})
        out = decide(event)
        if out["action"] == "accept" and event.get("kind") == DIR_KIND:
            out = gate.ask(out["id"], msg)
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
