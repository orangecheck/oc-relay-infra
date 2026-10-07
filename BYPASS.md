# BYPASS — every relay.ochk.io feature has a public-relay equivalent

This file is the family's promise that **`relay.ochk.io` is never the only copy of anything**. Every client publishes each event to `relay.ochk.io` and to the public set — `nos.lol`, `relay.primal.net`, `offchain.pub`, `relay.snort.social` — and every read path races them all. If `relay.ochk.io` disappeared tomorrow, every OC verifier in the field should still find and verify every OC envelope.

**Today that promise does not hold.** Publishing to a public relay is not storage: those relays prune. Measured 2026-10-07, none of the 33 family events on `relay.ochk.io` (kinds 30078, 30080, 30081, 30087, 30110–30112, 30114) exist on any of the four relays above or on `relay.damus.io`, and OC Vote's only poll had to be restored from a signed copy after `nos.lol` dropped it. The only second copy is the Fly volume's daily snapshot, kept five days, with the same provider. Restoring the invariant needs a copy that no relay operator, OC included, can prune: an export of every family event to storage outside Fly.

The pattern mirrors [`oc-guardian-kit/BYPASS.md`](https://github.com/orangecheck/oc-guardian-kit/blob/main/BYPASS.md): infrastructure parity is not a configuration choice, it's an architectural invariant.

## What relay.ochk.io does, and how to do the same thing without it

| feature | relay.ochk.io path | public-only path |
|---|---|---|
| Publish a kind-30078 OC Pledge envelope | client publishes to relay.ochk.io + 4 public relays | client publishes to 4 public relays alone |
| Read all pledges sworn by `bc1q…` | client queries relay.ochk.io + 4 public relays, dedupes by event id | client queries 4 public relays, dedupes by event id |
| Family-vitals counts on `ochk.io` | NIP-45 COUNT on relay.ochk.io with d-tag prefix filter | NIP-45 COUNT on `nos.lol` (the path the homepage used pre-relay), or fan-out on the four public relays |
| Backfill historical envelopes | strfry negentropy sync from public relays *into* relay.ochk.io | none today — public relays do not keep them (see above) |
| Audit log of takedown requests | `relay.ochk.io/transparency` (kind + d-tag + date only, never event content) | request takedown directly with the public relay operator, governed by their abuse policy |

## Build-time invariant

`@orangecheck/nostr-core`'s `DEFAULT_RELAYS` is typed `ValidRelaySet`, so `tsc` fails if the set shrinks to one relay or to `relay.ochk.io` alone. That guards the publish path. It cannot guard retention, which is what failed.

## Why this matters

If `relay.ochk.io` were the only place an OC envelope lived, then:

- OC could censor by deletion.
- OC could go down and take the family's history with it.
- OC verifiers couldn't run without OC infrastructure.
- The "Bitcoin load-bearing" claim would have a Nostr-shaped hole in it.

None of those are acceptable. The relay is commodity infrastructure that competes on reliability and family-curated indexing, not a trust anchor.

## When this file goes stale

Update **BYPASS.md** any time:

- A new feature lands on `relay.ochk.io` that doesn't have an obvious public-relay equivalent. (If you can't write the equivalent, the feature shouldn't ship.)
- The public-relay set materially changes — a new "default" relay added or one removed.
- The TypeScript invariants in `@orangecheck/nostr-core` are tightened or relaxed.
