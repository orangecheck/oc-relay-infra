# Abuse policy — relay.ochk.io

`relay.ochk.io` is a curated Nostr relay for the OrangeCheck family of protocols. This file defines what events the relay accepts, what we reject, our takedown procedure, and our transparency log policy.

## What we accept

Only events of kinds in the family's normative range and with canonical OC `d`-tag prefixes:

| kind | sub-protocol | required `d`-tag prefix |
|---|---|---|
| 30078 | OC Attest / OC Lock / OC Pledge / OC Chat | a bare 64-hex `attestation_id` (OC Attest), or `oc-lock:`, `oc-pledge:`, `oc-pledge-outcome:`, `oc-pledge-abandonment:`, `oc-chat:device:` |
| 30080 | OC Vote — poll | `oc-vote:poll:` |
| 30081 | OC Vote — ballot | `oc-vote:ballot:` |
| 30082 | OC Vote — reveal | `oc-vote:reveal:` |
| 30083 | OC Stamp / OC Agent — delegation | `oc-stamp:` or `oc-agent-del:` |
| 30084 | OC Agent — action | `oc-agent-act:` |
| 30085 | OC Agent — revocation | `oc-agent-rev:` |
| 30086 | OC Agent — sub-delegation | `oc-agent-sub:` |
| 30087 | OC Me | `oc-me-event:`, `oc-me-payment:`, `oc-me-rebind:`, `oc-me-trust:`, `oc-me-payout-binding:`, `oc-me-distribution:`, `oc-me-distribution-void:`, `oc-me-drop:` |
| 30110 | OC Chat — channel descriptor | `oc-lock-chat-ch:` |
| 30111 | OC Chat — channel post | `oc-lock-chat-msg:` |
| 30112 | OC Chat — seal descriptor | `oc-lock-chat-seal:` |
| 30114 | OC Chat — discoverability directory | `oc-lock-chat-dir:` (people), `oc-lock-chat-chdir:` (channels) |

Events outside this matrix are rejected with a per-event `OK` of `false` carrying
a `blocked: …` reason. **Both halves of the gate — the kind allowlist and the
d-tag prefix check — are enforced solely by `policy/oc-dtag-filter.py`.** strfry
has no built-in kind allowlist; an earlier version of this file claimed one was
configured in `strfry.conf` (`events.allowedKinds`), which is not a directive
that exists. If the plugin fails to start, the relay accepts *every* kind.

This table is asserted against the plugin by `policy/test_policy.py`, so it
cannot drift from the code again. It did once: the table and the plugin both
said `oc-vote-poll:` while every shipped OC Vote client emits `oc-vote:poll:`,
and the relay silently refused every poll, ballot and reveal.

## What we reject

- Events of any kind outside 30078, 30080–30087, 30110–30112, 30114.
- Events on an allowed kind whose `d` tag does not start with one of the OC prefixes above (the one exception being a bare 64-hex `attestation_id` on kind 30078, which is the form `oc-attest-protocol` SPEC §7 prescribes).
- Events whose BIP-322 / Schnorr signatures don't verify (strfry's built-in check).
- Events larger than 128 KiB (the `events.maxEventSize` ceiling, comfortably above the largest envelope in the family's test vectors).
- Kind-30114 directory records that fail OC Chat's directory gate (below), and OC Lock device records (`oc-lock:device:`) without a BIP-322 signature by the address they are filed under.

We do not read the *content* of an envelope to make an accept/reject decision, with two exceptions: kind 30114, and OC Lock device records. relay.ochk.io is the named **directory relay** of OC Chat ([SPEC §8.2.6](https://github.com/orangecheck/oc-chat-protocol/blob/main/SPEC.md)), and a directory relay admits a listing only if its claim passes §8.2.2 (1)–(4): a `v: 2` record, signed by its inbox key, that key bound to the address by an OC Lock device record (read here and from relay.damus.io and nos.lol, where OC Chat clients also publish them), the claim anchored in Bitcoin with 6 confirmations, every Bitcoin attestation in its proof (and in each re-point's) confirmed by its block's header, and its coin clearing the floor at the anchor and still standing. A tombstone needs a bound key and must end a claim this relay holds. A key counts as bound only once this relay's whole slot of device records for the address was read, since a revocation may be signed by any key; the public relays are read when this relay does not bind the key, so a revocation held only there is not seen while this relay binds it. An OC Lock device record (kind 30078, `oc-lock:device:<address>`) is admitted only with a BIP-322 signature by that address, a binding or a revocation alike, so no one else can fill an address's slot; a key that already holds a record there may also replace it with a revocation of its own device, signed or not (OC Lock's unsigned advice); one naming another device goes through the signature check. The per-device slot form, `oc-lock:device:<address>:<device_id>`, is refused here as relay policy: publish to the address's slot. One coin backs at most one live claim per namespace here. The check is the published rule (`@orangecheck/lock-core/directory`), run by `policy/dir-gate/`, and it reads the chain from mempool.space. A check that cannot finish refuses with `rate-limited: …`, never admits. The relay counts its directory answers by reason, per day, and keeps nothing about who sent them. Readers re-verify every record, so the relay can withhold a claim but cannot reorder or forge one. Everywhere else the relay enforces shape, not semantics. If you want semantic rejection, you want a verifier, not a relay.

## What we don't moderate

We do not delete or block events based on:

- Who signed them
- What proposition they commit to
- What the swearer's address is
- Whether the OC verifier would mark them invalid (the relay does not run a verifier)
- Whether the swearer is on a public-relay block list

We treat the relay as a public commons for the family's wire format, with shape gates only.

## Takedown procedure

We honor takedown requests against specific event IDs **only** for content that is unlawful under U.S. law. The procedure:

1. Send a takedown request to `abuse@ochk.io` with: the event ID, the kind, the d-tag, the legal basis, and your contact information. Anonymous requests are ignored.
2. We confirm receipt within 5 business days. We respond with our decision within 15 business days.
3. If we honor the request, the event is deleted from `relay.ochk.io`'s LMDB. **We do not request takedown from public relays on the requester's behalf** — that's between the requester and the public relay operator. The event is still public on Nostr unless every operator agrees.
4. The decision is logged at `https://relay.ochk.io/transparency` with: kind, d-tag, ISO date, legal basis (one short phrase). The full event content is NEVER included in the transparency log.

A takedown of an event from our relay does *not* take it down from public relays. Public-relay copies remain — the event is still verifiable forever from the swearer's local copy or from any public relay. This is intentional: the relay's role is reliability and curation, not censorship.

## What our infrastructure can see, and what it can't

The relay sees: every event published to it (kind, d-tag, content, signature, timestamp), and every query against it (subscriber pubkey if NIP-42 were enabled — it isn't, on the write or read path).

The relay does not see, and could not see if it tried:
- The plaintext of any encrypted OC Lock envelope (encryption is end-to-end against the recipient's BTC address).
- The Bitcoin chain state any OC Pledge resolves against (verifiers query mempool.space / Esplora directly).
- The off-chain wallet activity of any swearer.

## Inquiries

- Abuse: `abuse@ochk.io`
- Operations: `ops@ochk.io`
- Transparency log: `https://relay.ochk.io/transparency`
- Source: `https://github.com/orangecheck/oc-relay-infra`

## When this file goes stale

Update **ABUSE.md** any time:

- A new family kind is allocated (update the table).
- The takedown procedure changes (e.g., DMCA-specific handling lands).
- The transparency log shape changes (e.g., we add or remove fields).
- Legal counsel updates our position on what content we will/won't honor takedowns for.
