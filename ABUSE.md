# Abuse policy — relay.ochk.io

`relay.ochk.io` is a curated Nostr relay for the OrangeCheck family of protocols. This file defines what events the relay accepts, what we reject, our takedown procedure, and our transparency log policy.

## What we accept

Only events of kinds in the family's normative range and with canonical OC `d`-tag prefixes:

| kind | sub-protocol | required `d`-tag prefix |
|---|---|---|
| 30078 | OC Attest / OC Lock / OC Pledge | `oc-attest:`, `oc-lock:`, `oc-pledge:` (or `oc-pledge-outcome:`, `oc-pledge-abandonment:`) |
| 30080 | OC Vote — poll | `oc-vote-poll:` |
| 30081 | OC Vote — ballot | `oc-vote-ballot:` |
| 30082 | OC Vote — reveal | `oc-vote-reveal:` |
| 30083 | OC Stamp / OC Agent — delegation | `oc-stamp:` or `oc-agent-del:` |
| 30084 | OC Agent — action | `oc-agent-act:` |
| 30085 | OC Agent — revocation | `oc-agent-rev:` |
| 30086 | OC Agent — sub-delegation | `oc-agent-sub:` |

Events outside this matrix are silently rejected with `{"reason": "blocked: not an oc family event"}`. The kind allowlist is enforced by `strfry.conf`'s `events.allowedKinds`. The d-tag prefix gate is enforced by `policy/oc-dtag-filter.ts`.

## What we reject

- Events of any kind outside 30078–30086.
- Kind-30078–30086 events whose `d` tag does not start with one of the OC prefixes above.
- Events whose BIP-322 / Schnorr signatures don't verify (strfry's built-in check).
- Events larger than 128 KiB (the `events.maxEventSize` ceiling, comfortably above the largest envelope in the family's test vectors).

We do not — and will never — read the *content* of an envelope to make an accept/reject decision. The relay enforces shape, not semantics. If you want semantic rejection, you want a verifier, not a relay.

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
