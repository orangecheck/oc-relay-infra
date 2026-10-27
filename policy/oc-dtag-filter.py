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

import collections
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
# dead or garbled sidecar is a refusal, never an admission. A kind-30078 OC Lock
# device record goes to it too, to check its BIP-322 signature. Nothing else
# reaches it.
DIR_KIND = 30114
DEVICE_KIND = 30078
DEVICE_PREFIX = "oc-lock:device:"


def gated(event):
    if event.get("kind") == DIR_KIND:
        return True
    d = d_tag_of(event)
    return event.get("kind") == DEVICE_KIND and isinstance(d, str) and d.startswith(DEVICE_PREFIX)

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


# Per-source write limits. sourceInfo is the front's daily pseudonym for the
# visitor (an IPv6 address by its /64, front/main.go), so a source is one
# visitor for one UTC day, and the limits reset when the pseudonyms do.
# Measured 2026-10-26/27 over 20.7 h: no source sent more than 3 events in a
# minute; no author has more than 7 stored in a day, and the relay never took
# more than 11 in a day. Only network writes count: Import, Stream and Sync
# (backfill, archive) don't. Every event a source sends counts before it is
# judged, so a flood cannot spend the directory gate's chain reads. The state
# lives in this process only. The counts file holds totals by reason and how
# many sources were limited, per day, never which.
LIMITED_SOURCE_TYPES = ("IP4", "IP6")
BURST = 30  # events a source may send at once...
REFILL_S = 2.0  # ...and one more every 2 seconds: 30 a minute
DAY_EVENTS = 1000  # per source per UTC day
DAY_BYTES = 4 * 1024 * 1024  # of event JSON, per source per UTC day
BRAKE_REFUSALS = 60  # events refused on their merits within an hour...
BRAKE_S = 3600  # ...refuse everything the source sends for the next hour
MAX_SOURCES = 50000  # past this, the least recently seen source is forgotten
FLUSH_S = 1.0  # the counts file is written at most once a second, and on a source's first limit
RATE_LIMITED = "rate-limited: too many events from this address, try again later"
LIMIT_COUNTS = os.environ.get("OC_LIMIT_COUNTS", "/data/strfry/db/rate-limit-counts.json")


def event_size(event):
    # surrogatepass: a lone surrogate (strfry refuses one before this) is counted, not a crash.
    return len(json.dumps(event, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "surrogatepass"))


class SourceLimits:
    def __init__(self, path=LIMIT_COUNTS, now=time.time):
        self.path = path
        self.now = now
        self.day = None
        self.sources = collections.OrderedDict()
        self.limited = set()
        self.counts = {}
        self.base_sources = 0
        self.dirty = False
        self.flushed_at = 0.0

    def _roll(self, now):
        day = time.strftime("%Y-%m-%d", time.gmtime(now))
        if day == self.day:
            return
        if self.dirty:
            self._flush(now)  # the day that ends keeps its last counts
        self.day = day
        self.sources.clear()
        self.limited.clear()
        # A restarted plugin keeps the day's totals. A source limited both
        # before and after a restart is counted twice, never not at all.
        today = self._read().get(day, {})
        if not isinstance(today, dict):
            today = {}
        self.counts = {k: v for k, v in today.items() if k != "sources" and isinstance(v, int)}
        self.base_sources = today.get("sources") if isinstance(today.get("sources"), int) else 0

    def _read(self):
        try:
            with open(self.path) as f:
                days = json.load(f)
            return days if isinstance(days, dict) else {}
        except Exception:
            return {}

    def _flush(self, now):
        self.dirty = False
        self.flushed_at = now
        days = self._read()
        days[self.day] = dict(self.counts, sources=self.base_sources + len(self.limited))
        try:
            days = {k: days[k] for k in sorted(days)[-14:]}
            with open(self.path + ".tmp", "w") as f:
                json.dump(days, f)
            os.replace(self.path + ".tmp", self.path)
        except Exception:
            pass

    def _source(self, key, now):
        s = self.sources.get(key)
        if s is None:
            s = {"tokens": float(BURST), "at": now, "events": 0, "bytes": 0,
                 "refused": collections.deque(), "braked_until": 0.0}
            self.sources[key] = s
            if len(self.sources) > MAX_SOURCES:
                self.sources.popitem(last=False)
        else:
            self.sources.move_to_end(key)
        return s

    def _limit(self, key, why, now):
        self.counts[why] = self.counts.get(why, 0) + 1
        self.dirty = True
        # Up to MAX_SOURCES senders a day are told apart; past that the count stays there.
        first = key not in self.limited and len(self.limited) < MAX_SOURCES
        if first:
            self.limited.add(key)
            sys.stderr.write("oc-dtag-filter: a source hit the write limit (%s; %d sources today)\n"
                             % (why, self.base_sources + len(self.limited)))
            sys.stderr.flush()
        if first or now - self.flushed_at >= FLUSH_S:
            self._flush(now)
        return why

    @staticmethod
    def _counted(msg):
        return msg.get("type") == "new" and msg.get("sourceType") in LIMITED_SOURCE_TYPES

    def check(self, msg, size):
        """None if the event may be judged; otherwise which limit its source is over."""
        if not self._counted(msg):
            return None
        key = str(msg.get("sourceInfo"))
        now = self.now()
        self._roll(now)
        if self.dirty and now - self.flushed_at >= FLUSH_S:
            self._flush(now)
        s = self._source(key, now)
        if s["braked_until"] > now:
            return self._limit(key, "refusals", now)
        s["tokens"] = min(float(BURST), s["tokens"] + (now - s["at"]) / REFILL_S)
        s["at"] = now
        if s["tokens"] < 1:
            return self._limit(key, "burst", now)
        if s["events"] >= DAY_EVENTS:
            return self._limit(key, "day", now)
        if s["bytes"] + size > DAY_BYTES:
            return self._limit(key, "bytes", now)
        s["tokens"] -= 1
        s["events"] += 1
        s["bytes"] += size
        return None

    def refused(self, msg):
        """The relay refused this source's event on its merits: not for a limit, not for a busy gate."""
        if not self._counted(msg):
            return
        now = self.now()
        self._roll(now)
        s = self._source(str(msg.get("sourceInfo")), now)
        q = s["refused"]
        q.append(now)
        while q and q[0] <= now - BRAKE_S:
            q.popleft()
        if len(q) >= BRAKE_REFUSALS:
            q.clear()
            s["braked_until"] = now + BRAKE_S


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
    limits = SourceLimits()
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
        if limits.check(msg, event_size(event)):
            out = {"id": event.get("id", ""), "action": "reject", "msg": RATE_LIMITED}
        else:
            out = decide(event)
            if out["action"] == "accept" and gated(event):
                out = gate.ask(out["id"], msg)
            if out["action"] == "reject" and out.get("msg") != GATE_BUSY:
                limits.refused(msg)
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
