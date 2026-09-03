# oc-relay-infra

Infrastructure repo for **`wss://relay.ochk.io`** — the OrangeCheck family's first-party Nostr relay.

> **Not a protocol. Not a requirement. Not a SPOF.** Every OC envelope is also published to public relays, and every verifier MUST query at least one non-OC relay. This relay is a reliability backstop and family-kind indexer; it is never the only copy of anything.

## What this is

A single-region [strfry](https://github.com/hoytech/strfry) instance, configured to:

1. Accept the family's eight Nostr kinds (30078–30086) and reject everything else.
2. Additionally reject events that don't carry a canonical OC `d`-tag prefix (`oc-pledge:`, `oc-stamp:`, `oc-agent-del:`, etc.) — the curation that turns a generic 30078–30086 relay into a *family* relay.
3. Sync historical events from `nos.lol`, `relay.nostr.band`, `relay.primal.net`, and `offchain.pub` via [negentropy](https://github.com/hoytech/strfry/blob/master/docs/negentropy.md).
4. Serve a small `/health` endpoint with `{event_count, last_event_at, lmdb_size_bytes, kind_distribution}` for monitoring + the family-vitals widget on `ochk.io`.

That's it. No NIP-42 auth on writes. No paid tiers. No content moderation beyond kind + d-tag shape.

## What this is NOT

- A protocol. Relay infrastructure is not in any normative `oc-*-protocol` spec — specs stay relay-agnostic by design.
- A required publish target. Every web app's `DEFAULT_RELAYS` keeps the public set; relay.ochk.io is appended. The TypeScript invariant is enforced at the type level (see `@orangecheck/nostr-core` once extracted in Phase 3).
- A required read target. Every read continues to race ≥3 public relays.
- A custodian, escrow, or trust anchor. Trust anchors are Bitcoin (BIP-322 attestations) and Nostr-published envelopes (offline-verifiable). Relays are commodity infrastructure.

## Why now

Five web repos in the family currently document the empirical failure mode:

> "`relay.damus.io` and `relay.snort.social` aggressively reject events from fresh pubkeys with no WoT history (which is what a no-NIP-07 publish produces), so they're excluded from the write path here."

— [`oc-pledge-web/src/lib/nostr/client.ts:9-14`](https://github.com/orangecheck/oc-pledge-web/blob/main/src/lib/nostr/client.ts#L9-L14) (and four siblings, drift between them already visible).

`oc-fleet-web/src/pages/api/cron/republish-nostr.ts` exists *because* request-path publishes drop. A Vercel Cron retries every 5 minutes. That cron is a workaround for the gap a first-party relay closes.

A first-party kind-allowlisted relay collapses the structural split between "ephemeral pubkey" publish flows (pledge / vote / fleet-reputation / stamp / lock / agent) and "stable service-key" publish flows (attest / me / fleet-server-publisher) into a single guaranteed-accept endpoint, without taking us out of the public Nostr graph.

## File set

```
oc-relay-infra/
├── README.md             this file
├── BYPASS.md             every relay.ochk.io feature has a public-relay equivalent — by design
├── ABUSE.md              what we accept, what we reject, takedown policy, transparency log
├── LICENSE               MIT
├── strfry.conf           the production relay config (kind allowlist, retention, no-auth)
├── Dockerfile            pinned strfry image + python3 for the policy plugin
├── fly.toml              Fly.io deploy config (single region fra, 50 GB volume)
├── policy/
│   ├── oc-dtag-filter.py strfry write-policy plugin (Python) — kind + d-tag gate
│   └── test_policy.py     asserts the gate accepts what shipped clients emit
├── sync/
│   └── backfill.sh       negentropy sync from public relays, cold-start + quarterly
└── monitoring/
    └── health.ts         /health JSON probe — NOT DEPLOYED. The Dockerfile
                          never copies it and fly.toml health-checks TCP 7777
                          directly, so nothing serves this. Kept for when a
                          status surface wants it.
```

## Deployment

Hosted on **Fly.io**, single region `fra` (Frankfurt). Fly handles TLS termination at the edge and proxies wss://relay.ochk.io → strfry:7777 over the private network. Persistent storage is a 50 GiB Fly Volume mounted at `/data/strfry/db`.

```bash
flyctl deploy                                     # build + ship
flyctl certs add relay.ochk.io                    # attach DNS, request Let's Encrypt
flyctl ssh console -C "/usr/local/bin/oc-relay-backfill"   # cold-start negentropy sync
flyctl logs                                       # tail
```

**Phase 0 — repo scaffold.** ✅ Done.
**Phase 1 — Fly provision + DNS + client co-publish.** ✅ Done (this commit).
**Phase 2 — read-side fallback + family-vitals switchover.** Not started.
**Phase 3 — family indexer endpoint + npm consolidation.** Not started.

## Decisions

- **Domain:** `relay.ochk.io` (matches the subdomain-per-product convention).
- **Hosting:** Fly.io single region (fra). Anycast available if we ever need it.
- **Cost ceiling:** <€30/mo year-one (compute + 50 GB volume + monitoring).
- **Transparency log:** yes — kind + d-tag + ISO date at `relay.ochk.io/transparency`, never event content. Defensible without becoming a content judge.
- **On-call:** William primary; year one accepts "may stay down until next business day" because the BYPASS invariant means public relays still serve everything.
- **Migration scope:** all seven web repos in Phase 1 (`oc-attest-web` SERVICE_KEY_RELAYS included alongside the six others).

## Family relationship

| Repo | What it does with this relay |
|---|---|
| `oc-attest-web` | Phase 1: `relay.ochk.io` appended to `SERVICE_KEY_RELAYS` |
| `oc-pledge-web`, `oc-fleet-web`, `oc-vote-web`, `oc-stamp-web`, `oc-lock-web` | Phase 1: appended to `DEFAULT_RELAYS` (browser-side publish + read) |
| `oc-agent-web` | Phase 1: appended to `RELAY_URLS` |
| `oc-me-web` | Phase 1: appended to env-driven `OC_NOSTR_RELAYS` (Vercel env, no code change) |
| `oc-www` | Phase 2: `api/family-stats.ts` switches from single-relay `nos.lol` COUNT to `relay.ochk.io` with d-tag prefix filters |
| `oc-docs` | Phase 2: new page `infrastructure/relay` describing the relay, allowlist, abuse policy, BYPASS principle |

## Operational

- **Status:** `https://status.ochk.io/relay` (existing status module, new probe row)
- **Backups:** nightly `strfry export` to a Hetzner storage box, retained 30 days. Quarterly restore drill.
- **Monitoring:** UptimeRobot pings `/health` every 5 min. Alert on miss + on `event_count` plateau (suggests a write-path break).
- **Negentropy sync:** quarterly cron, runs `sync/backfill.sh`, ensures relay holds the family's public-relay history.

## License

MIT. See LICENSE.

## See also

- [`hoytech/strfry`](https://github.com/hoytech/strfry) — the relay binary
- [`relayable-org/strfry-policies`](https://github.com/relayable-org/strfry-policies) — Deno policy plugin pattern
- The [research doc](https://github.com/orangecheck/oc-relay-infra/blob/main/docs/2026-05-relay-decision.md) capturing the decision (when migrated)
