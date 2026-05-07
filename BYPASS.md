# BYPASS — every relay.ochk.io feature has a public-relay equivalent

This file is the family's promise that **`relay.ochk.io` is never the only copy of anything**. Every event that lands on it also lands on at least three of `nos.lol`, `relay.nostr.band`, `relay.primal.net`, `offchain.pub` (the public relay set the family has used since day one). Every read path that consults `relay.ochk.io` also races at least three public relays. If `relay.ochk.io` disappeared tomorrow, every OC verifier in the field would still verify every OC envelope.

The pattern mirrors [`oc-guardian-kit/BYPASS.md`](https://github.com/orangecheck/oc-guardian-kit/blob/main/BYPASS.md): infrastructure parity is not a configuration choice, it's an architectural invariant.

## What relay.ochk.io does, and how to do the same thing without it

| feature | relay.ochk.io path | public-only path |
|---|---|---|
| Publish a kind-30078 OC Pledge envelope | client publishes to relay.ochk.io + 4 public relays | client publishes to 4 public relays alone (always has, always will) |
| Read all pledges sworn by `bc1q…` | client queries relay.ochk.io + 4 public relays, dedupes by event id | client queries 4 public relays, dedupes by event id |
| Family-vitals counts on `ochk.io` | NIP-45 COUNT on relay.ochk.io with d-tag prefix filter | NIP-45 COUNT on `nos.lol` (the path the homepage used pre-relay), or fan-out on the four public relays |
| Backfill historical envelopes | strfry negentropy sync from public relays *into* relay.ochk.io | not needed — public relays already have them |
| Audit log of takedown requests | `relay.ochk.io/transparency` (kind + d-tag + date only, never event content) | request takedown directly with the public relay operator, governed by their abuse policy |

## Build-time invariants (will land in Phase 3)

Once `@orangecheck/nostr-core` is extracted to `oc-packages`, the package's published `DEFAULT_RELAYS` constant gets these invariants enforced at the type level:

```ts
// Build fails if a future engineer simplifies to ours-only.
type Invariant = DEFAULT_RELAYS extends readonly [...infer R]
    ? R['length'] extends 0 | 1
        ? never
        : R extends readonly ['wss://relay.ochk.io']
        ? never
        : R
    : never;
```

These are not enforced today. They will be enforced before `relay.ochk.io` is added as a default in any consumer.

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
