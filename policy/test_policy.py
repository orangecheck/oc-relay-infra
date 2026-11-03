#!/usr/bin/env python3
"""Assert the write policy accepts what the shipped clients ACTUALLY emit.

Why this file exists: the policy's prefix table was hand-copied from KINDS.md,
and KINDS.md had drifted from the specs. The relay therefore rejected every OC
Vote poll/ballot/reveal ("oc-vote:poll:" vs the table's "oc-vote-poll:") and
every OC Attest attestation (a bare 64-hex id vs a demanded "oc-attest:"
prefix) for as long as the plugin has been running. Nothing caught it: the
rejection is a per-event OK=false on a websocket, invisible unless you read the
publish result, and until 2026-09 no client even listed relay.ochk.io.

So the cases below are not invented. Each is the literal d-tag string a real
publisher builds, cited to the file and line it is built at. When a client
changes its d-tag, this test fails and the policy gets updated with it.

    python3 policy/test_policy.py
"""
import importlib.util
import pathlib
import re
import sys

spec = importlib.util.spec_from_file_location(
    "policy", pathlib.Path(__file__).parent / "oc-dtag-filter.py"
)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

ADDR = "bc1pezn5yjxmz9nuahtqprvhfeya2nv4zdfk49u5amquhqptykx695rs60hqa2"
ID = "bbde80f884ae849d2cc8d4fa19687e7ec862f8b7c85a3ee8cf93739548e23658"
DID = "did:oc:ed30f1d9fc9acf7a88283069a2f97fc8"

# (kind, d-tag, where it is built) — every one MUST be accepted.
EMITTED = [
    (30078, ID, "@orangecheck/sdk src/nostr.ts:63 (bare attestation_id, SPEC L228)"),
    (30078, f"oc-lock:device:{ADDR}", "@orangecheck/lock-device src/index.ts:111"),
    (30078, f"oc-pledge:{ID}", "oc-pledge-web src/lib/pledge/event.ts:61"),
    (30080, f"oc-vote:poll:{ID}", "oc-vote-web src/lib/vote/events.ts:53 + vote-cli events.ts:41"),
    (30081, f"oc-vote:ballot:{ID}:{ADDR}", "oc-vote-web events.ts:81 + vote-cli events.ts:57"),
    (30082, f"oc-vote:reveal:{ID}", "oc-vote-web events.ts:100 + vote-cli events.ts:72"),
    (30083, f"oc-stamp:{ID}", "oc-stamp-web src/lib/stamp/event.ts:60"),
    (30083, f"oc-agent-del:{ID}", "oc-agent-web src/lib/nostr/event.ts:63"),
    (30085, f"oc-agent-rev:{ID}", "oc-agent-web src/lib/nostr/event.ts:97"),
    (30087, f"oc-me-event:{ID}", "oc-me-web (billable event envelope)"),
    (30087, f"oc-me-payment:{ID}", "oc-me-web (payment envelope)"),
    (30087, f"oc-me-rebind:{ID}", "oc-me-web (rebind envelope)"),
    (30087, f"oc-me-trust:{ID}", "oc-me-web src/lib/nostr/event.ts D_PREFIX.trust_attestation"),
    (30087, f"oc-me-payout-binding:{ID}", "oc-me-web (payout binding)"),
    (30087, f"oc-me-distribution:{ID}", "oc-me-web (distribution)"),
    (30087, f"oc-me-distribution-void:{ID}", "oc-me-web (distribution void)"),
    (30087, f"oc-me-drop:{ID}", "oc-me-web (drop manifest)"),
]

# The gate must still be a gate. Every one MUST be rejected.
BLOCKED = [
    (1, "anything", "kind 1 is not a family kind"),
    (30080, f"oc-vote-poll:{ID}", "the hyphenated form KINDS.md wrongly listed; nothing emits it"),
    (30078, "not-an-oc-namespace", "arbitrary d-tag on a family kind"),
    (30078, ID.upper(), "uppercase hex is not the canonical attestation id rendering"),
    (30078, ID[:63], "63 hex chars is not a sha256"),
    (30078, ID + "a", "65 hex chars is not a sha256"),
    (30083, f"oc-vote:poll:{ID}", "right namespace, wrong kind"),
    (30110, f"oc-chat:ch:{ID}", "brand-rooted chat d-tag; spec is verb-rooted oc-lock-chat-ch:"),
]

failures = []
for kind, d, why in EMITTED:
    got = policy.decide({"id": "x", "kind": kind, "tags": [["d", d]]})
    if got["action"] != "accept":
        failures.append(f"  SHOULD ACCEPT kind {kind} d={d[:44]}\n      built at: {why}\n      relay: {got.get('msg')}")

for kind, d, why in BLOCKED:
    got = policy.decide({"id": "x", "kind": kind, "tags": [["d", d]]})
    if got["action"] == "accept":
        failures.append(f"  SHOULD REJECT kind {kind} d={d[:44]}\n      reason: {why}")

# OC Chat's session device records (oc-chat-protocol SPEC §8.6). Chat reads a
# bind only with ochk.io's vouch, so a record without one (the shape chat
# published before 2026-09-24, oc-chat-web 6b5b5b4) is read by no one and is
# refused here, so it cannot come back after it is deleted. The relay checks
# the shape; chat verifies the signatures. Tags as session-binding.ts
# finalizeSessionDeviceEvent builds them.
VOUCH = "eyJhbGciOiJFZERTQSJ9.b2MtY2hhdDpkZXZpY2Utdm91Y2g6djE.c2ln"
SESSION = [["d", f"oc-chat:device:{DID}"], ["addr", DID], ["device_id", "dev-1"], ["device_pk", "ab" * 32],
           ["alg", "x25519"], ["auth", "session"], ["binding_sig", ""]]
def with_tags(base, **over):
    tags = [t for t in base if t[0] not in over] + [[k, v] for k, v in over.items() if v is not None]
    return {"id": "x", "kind": 30078, "tags": tags}
CHAT_ACCEPT = [
    (with_tags(SESSION, vouch=VOUCH), "a bind with ochk.io's vouch"),
    (with_tags(SESSION, device_pk="revoked"), "a device's own revocation (device_pk 'revoked'), which carries no vouch"),
    ({"id": "x", "kind": 30078, "tags": [["d", f"oc-chat:device:{DID}"], ["addr", DID], ["revocation", VOUCH]]},
     "ochk.io's signed revocation: a resolver must not refuse it for its device_id, device_pk or auth tags"),
]
CHAT_REJECT = [
    (with_tags(SESSION), "no vouch: the pre-fix shape chat ignores (P66)"),
    (with_tags(SESSION, vouch=""), "an empty vouch"),
    (with_tags(SESSION, vouch="not-a-jws"), "a vouch that is not a compact JWS"),
    (with_tags(SESSION, vouch=VOUCH, addr="did:oc:00000000000000000000000000000000"), "addr names another did:oc than the d tag"),
    (with_tags(SESSION, vouch=VOUCH, auth=None), "no auth=session tag"),
    (with_tags(SESSION, vouch=VOUCH, device_id=None), "no device_id"),
    ({"id": "x", "kind": 30078, "tags": [["d", f"oc-chat:device:{DID}"]]}, "a d tag and nothing else"),
    ({"id": "x", "kind": 30078, "tags": [["d", f"oc-chat:device:{DID}"], ["addr", "did:oc:00000000000000000000000000000000"], ["revocation", VOUCH]]},
     "a host revocation filed under another did:oc's slot"),
]
for ev, why in CHAT_ACCEPT:
    got = policy.decide(ev)
    if got["action"] != "accept":
        failures.append(f"  SHOULD ACCEPT oc-chat:device ({why})\n      relay: {got.get('msg')}")
for ev, why in CHAT_REJECT:
    got = policy.decide(ev)
    if got["action"] == "accept":
        failures.append(f"  SHOULD REJECT oc-chat:device ({why})")

# A family kind with no d tag at all is still a reject.
if policy.decide({"id": "x", "kind": 30080, "tags": []})["action"] == "accept":
    failures.append("  SHOULD REJECT kind 30080 with no d tag")

# So is one with two. strfry matches a #d filter against every d value, so a
# second d files the event under that slot too (an address's oc-lock:device:
# slot, say) without the slot's own check. Nothing the family publishes has two.
for kind, d, _ in EMITTED:
    for tags in ([["d", d], ["d", f"oc-lock:device:{ADDR}"]], [["d", d], ["d", d]], [["d"], ["d", d]]):
        if policy.decide({"id": "x", "kind": kind, "tags": tags})["action"] == "accept":
            failures.append(f"  SHOULD REJECT kind {kind} with tags {[t[:2] for t in tags]}"[:160])

# ---------------------------------------------------------------------------
# ABUSE.md publishes this same matrix to integrators. It drifted from the code
# once already (both said "oc-vote-poll:" while every client emits
# "oc-vote:poll:"), so assert the doc and the plugin agree in both directions.
abuse = (pathlib.Path(__file__).parent.parent / "ABUSE.md").read_text()
table = abuse[abuse.index("| 30078 |"):abuse.index("Events outside this matrix")]

for kind, prefixes in policy.ALLOWED_PREFIXES.items():
    if f"| {kind} |" not in table:
        failures.append(f"  ABUSE.md has no row for kind {kind}")
        continue
    for p in prefixes:
        if f"`{p}`" not in table:
            failures.append(f"  ABUSE.md kind {kind} row is missing prefix `{p}`")

# ...and nothing in the doc that the plugin would actually reject.
known = {p for ps in policy.ALLOWED_PREFIXES.values() for p in ps}
for cited in set(re.findall(r"`(oc-[a-z-]+:[a-z-]*:?)`", table)):
    if cited not in known:
        failures.append(f"  ABUSE.md advertises `{cited}`, which the plugin rejects")

if 30078 in policy.BARE_ID_KINDS and "64-hex" not in table:
    failures.append("  ABUSE.md kind 30078 row does not mention the bare 64-hex attestation id")

# The docs also state the allowed KIND range in prose, in both files. That
# sentence said "30078-30086" long after 30087 (OC Me) and 30110-30114 (OC
# Chat) were added to the plugin — a whole product's kind missing from the
# integrator-facing description of what the relay accepts. Derive the range
# from the plugin and assert both files carry it.
def _kind_ranges(kinds):
    runs, start, prev = [], kinds[0], kinds[0]
    for k in kinds[1:]:
        if k == prev + 1:
            prev = k
            continue
        runs.append((start, prev))
        start = prev = k
    runs.append((start, prev))
    return ", ".join(f"{a}" if a == b else f"{a}\u2013{b}" for a, b in runs)

expected_range = _kind_ranges(sorted(policy.ALLOWED_PREFIXES))
readme = (pathlib.Path(__file__).parent.parent / "README.md").read_text()
for doc_name, doc in (("ABUSE.md", abuse), ("README.md", readme)):
    if expected_range not in doc:
        failures.append(
            f"  {doc_name} does not state the plugin's kind range verbatim\n"
            f"      expected: {expected_range}"
        )

if failures:
    print(f"policy: {len(failures)} failing case(s)\n")
    print("\n\n".join(failures))
    sys.exit(1)
print(f"policy: {len(EMITTED)} emitted d-tags accepted, {len(BLOCKED) + 1} non-conforming rejected,\n        ABUSE.md matrix + both docs' kind range match the plugin ({expected_range})")
