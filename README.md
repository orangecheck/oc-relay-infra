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
├── Dockerfile            pinned strfry image + Caddy for TLS
├── compose.yaml          docker-compose for Hetzner / Fly
├── policy/
│   └── oc-dtag-filter.ts strfry write-policy plugin (Deno) — d-tag prefix gate
├── sync/
│   └── backfill.sh       negentropy sync from public relays, cold-start + quarterly
├── monitoring/
│   └── health.ts         /health JSON probe (consumed by status.ochk.io)
└── deploy/
    └── hetzner-init.sh   cloud-init bootstrap (NOT executed automatically)
```

## Deployment status

**Phase 0 — repo scaffold.** ✅ This file set is reviewed and ready.

**Phase 1 — Hetzner provision + DNS.** ⏳ Pending human approval of the open questions in this README's footer.

**Phase 2 — read-side fallback.** Not started.

**Phase 3 — family indexer + npm consolidation.** Not started.

## Open questions for review

These need explicit human decision before Phase 1:

1. **Domain.** `relay.ochk.io` recommended (matches the subdomain-per-product convention). Alternative: `nostr.ochk.io` (more discoverable, but implies more Nostr surface).
2. **Hosting.** Hetzner Cloud (CX22, fsn1-dc14, ~€5/mo) recommended. Alternative: Fly.io. Hetzner gets us off Vercel single-platform; Fly.io is anycast (overkill for one region).
3. **Cost ceiling.** Year-one estimate: <€30/mo total (compute + 50 GB block storage + monitoring). Confirm cap.
4. **Transparency log.** Publish takedown decisions (kind + d-tag + date, never event content) at `relay.ochk.io/transparency`? Recommended yes — defensible without putting us in the content-judgment business.
5. **On-call.** William primary; secondary TBD. Year one accepts "may stay down until next business day"? Recommended yes (BYPASS invariant — public relays still serve).
6. **Migration order.** Include `oc-attest-web`'s 9-relay `SERVICE_KEY_RELAYS` set in Phase 1? Recommended yes (one-line change, zero risk).

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
