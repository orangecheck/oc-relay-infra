# oc-relay-infra

Infrastructure repo for **`wss://relay.ochk.io`** — the OrangeCheck family's first-party Nostr relay.

> **Not a protocol. Not a requirement. Not a SPOF.** Every OC envelope is also published to public relays, and every verifier MUST query at least one non-OC relay. This relay is a reliability backstop and family-kind indexer; it is never the only copy of anything.

## What this is

A single-region [strfry](https://github.com/hoytech/strfry) instance, configured to:

1. Accept the family's Nostr kinds (30078, 30080–30087, 30110–30112, 30114 — 13 of them) and reject everything else.
2. Additionally reject events that don't carry a canonical OC `d`-tag prefix (`oc-pledge:`, `oc-stamp:`, `oc-agent-del:`, etc. — plus a bare 64-hex `attestation_id`, which is what OC Attest's spec prescribes) — the curation that turns a generic relay into a *family* relay. The authoritative table is `policy/oc-dtag-filter.py`; `ABUSE.md` republishes it and `policy/test_policy.py` asserts the two agree.
3. Sync historical events from `relay.damus.io`, `nos.lol`, `relay.primal.net`, and `nostr.oxtr.dev` via [negentropy](https://github.com/hoytech/strfry/blob/master/docs/negentropy.md).
4. Act as OC Chat's named directory relay: a kind-30114 record that passes the prefix gate must also pass the claim rule of OC Chat §8.2.6, checked by `policy/dir-gate/` with the published rule (`@orangecheck/lock-core/directory`). The same sidecar admits an OC Lock device record only with a BIP-322 signature by its address. See `ABUSE.md`.
5. Answer `/health` from `oc-relay-front`: strfry's NIP-11 name, version and supported NIPs, read over loopback, plus `source_unknown`, the count of requests that came without a usable `Fly-Client-IP`. Fly's health check and analytics.ochk.io read it.

## Visitor addresses

strfry stores a source with every event and logs it on Connect. It never sees a visitor's address. `oc-relay-front` (`front/`) listens where Fly forwards and hands strfry, on loopback, an `x-oc-source` header holding a pseudonym for the UTC day: `fd` and the first 15 bytes of HMAC-SHA256 over the address (an IPv6 address by its /64) under a 32-byte salt that lives only in the front's memory and is replaced on the first request of each day. Within a day one visitor's connections share a pseudonym; across days nobody can link them, us included. A request without a usable `Fly-Client-IP` gets `fd00::`, one shared bucket, and is counted in `/health`. No header naming the visitor reaches strfry.

Fly's edge still sees each visitor's address, as Vercel does for the family's sites. At the front's first start on a volume, `boot/oc-relay-boot.sh` rewrote the store through `strfry export` and `import` into a new file, so no address stored before the front remains in it; Fly's volume snapshots held the old file until they aged out.

That's it. No NIP-42 auth on writes. No paid tiers. No content moderation beyond kind + d-tag shape, the directory's claim rule for kind 30114, and the BIP-322 check on OC Lock device records.

## What this is NOT

- A protocol. Relay infrastructure is not in any normative `oc-*-protocol` spec — specs stay relay-agnostic by design.
- A required publish target. Every web app's `DEFAULT_RELAYS` keeps the public set; relay.ochk.io is appended. The TypeScript invariant is enforced at the type level (see `@orangecheck/nostr-core` once extracted in Phase 3).
- A required read target. Every read continues to race ≥3 public relays.
- A custodian, escrow, or trust anchor. Trust anchors are Bitcoin (BIP-322 attestations) and Nostr-published envelopes (offline-verifiable). Relays are commodity infrastructure.

## Why now

Five web repos in the family currently document the empirical failure mode:

> "`relay.damus.io` and `relay.snort.social` aggressively reject events from fresh pubkeys with no WoT history (which is what a no-NIP-07 publish produces), so they're excluded from the write path here."

— the relay client in `oc-pledge-web`, a private repo (and four siblings, drift between them already visible).

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
├── Dockerfile            builds the front, then pinned strfry image + python3 for the policy plugin + Node for the directory gate
├── fly.toml              Fly.io deploy config (single region fra, 50 GB volume)
├── policy/
│   ├── oc-dtag-filter.py strfry write-policy plugin (Python) — kind + d-tag gate
│   ├── dir-gate/         kind-30114 claim gate + device-record check (Node sidecar the plugin runs)
│   ├── test_policy.py     asserts the gate accepts what shipped clients emit
│   └── test_dir_gate.py   runs the plugin and checks the 30114 bridge
├── sync/
│   └── backfill.sh       negentropy sync from public relays, cold-start + quarterly
├── front/
│   └── main.go           oc-relay-front: the daily pseudonym, /health, runs strfry
└── boot/
    └── oc-relay-boot.sh  rewrites the store once per volume, then starts the front
```

## Deployment

Hosted on **Fly.io**, single region `fra` (Frankfurt). Fly handles TLS termination at the edge and proxies wss://relay.ochk.io → oc-relay-front on :7777, which forwards to strfry on 127.0.0.1:7778. Persistent storage is a 50 GiB Fly Volume mounted at `/data/strfry/db`.

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
- **On-call:** the orangecheck operator; year one accepts "may stay down until next business day" because the BYPASS invariant means public relays still serve everything.
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
- **Monitoring:** analytics.ochk.io reads `/health` on its snapshot cron and alerts when the relay does not answer (`relay.down`), when a request came without a usable `Fly-Client-IP` in the last hour (`relay.source_unknown`), and when the write limits refused more than a handful of senders today (`relay.rate_limited_sources`). Fly's own check reads `/health` every 30 s.
- **Write limits:** the write-policy plugin limits each sender (strfry's source: the front's daily pseudonym) to 30 events at once and one more every 2 s, and 1,000 events or 4 MiB a UTC day; 60 refused events in an hour refuse the sender for an hour. Imports and syncs are exempt. Its counts by reason and the number of senders limited, per day, are in `rate-limit-counts.json`, and `/health` carries today's as `rate_limited`.
- **Negentropy sync:** quarterly cron, runs `sync/backfill.sh`, ensures relay holds the family's public-relay history.
- **Directory gate:** a Node sidecar (`policy/dir-gate/`) checks every kind-30114 write and every `oc-lock:device:` record. While it is down or slow, those writes answer `rate-limited: …` and nothing else changes; clients publish to public relays too. It has no health route of its own (Fly checks the front's `/health`); it reads this relay from strfry on 127.0.0.1:7778, never through the front; its answers are counted by reason per day in `dir-gate-counts.json`.

## License

MIT. See LICENSE.

## See also

- [`hoytech/strfry`](https://github.com/hoytech/strfry) — the relay binary
- [`relayable-org/strfry-policies`](https://github.com/relayable-org/strfry-policies) — Deno policy plugin pattern
- The [research doc](https://github.com/orangecheck/oc-relay-infra/blob/main/docs/2026-05-relay-decision.md) capturing the decision (when migrated)
