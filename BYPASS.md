# BYPASS — every relay.ochk.io feature has a public-relay equivalent

This file is the family's promise that **`relay.ochk.io` is never the only copy of anything**. Every client publishes each event to `relay.ochk.io` and to the public set — `nos.lol`, `relay.primal.net`, `relay.damus.io`, `nostr.oxtr.dev` — and every read path races them all. If `relay.ochk.io` disappeared tomorrow, every OC verifier in the field should still find and verify every OC envelope.

**Today that promise does not hold.** Publishing to a public relay is not storage: on 2026-10-21 some refused what we sent and one kept none of what it accepted, which is why the set above changed that day (oc-claude `research/RELAY-COVERAGE-DECISIONS.md`). Measured 2026-10-07, 42 of the 52 family events on `relay.ochk.io` existed on none of the public relays the family then used; the 10 that survive are September OC Chat device records on damus. OC Vote's only poll had to be restored from a signed copy after `nos.lol` dropped it.

So the second copy is now ours to keep. The `Archive` workflow fetches every family kind from `relay.ochk.io` daily, recomputes each event id, checks each signature, applies the relay's own kind and `d`-tag rule again, and commits the result to the [`archive`](https://github.com/orangecheck/oc-relay-infra/tree/archive) branch as `events.jsonl`. It lives outside Fly, whose own volume snapshots are kept five days.

The archive is a copy of what the relay stores, not of what the family's readers accept. For most kinds the relay checks shape alone (see `ABUSE.md`), so the archive can hold records every reader rejects: a channel version no reader accepts, an OC Chat device record ochk.io never vouched for, test junk. Restore `relay.ochk.io` from it by publishing the events back to it, so its write policy checks each one again. Before copying any of it to another relay, keep only what the family's readers accept, or the copy spreads records they ignore.

The pattern mirrors [`oc-guardian-kit/BYPASS.md`](https://github.com/orangecheck/oc-guardian-kit/blob/main/BYPASS.md): infrastructure parity is not a configuration choice, it's an architectural invariant.

## What relay.ochk.io does, and how to do the same thing without it

| feature | relay.ochk.io path | public-only path |
|---|---|---|
| Publish a kind-30078 OC Pledge envelope | client publishes to relay.ochk.io + 4 public relays | client publishes to 4 public relays alone |
| Read all pledges sworn by `bc1q…` | client queries relay.ochk.io + 4 public relays, dedupes by event id | client queries 4 public relays, dedupes by event id |
| Family-vitals counts on `ochk.io` | REQ per kind on relay.ochk.io, counted by the client up to strfry's 500-event limit (strfry 0.9.7 has no NIP-45 COUNT) | the same REQ fan-out on the four public relays, deduped by event id |
| Restore history after losing the volume | publish `events.jsonl` from the `archive` branch back to relay.ochk.io, whose write policy checks each event again | read `events.jsonl` from the `archive` branch, and copy to a public relay only the events the family's readers accept |
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
