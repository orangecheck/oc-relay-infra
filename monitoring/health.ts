#!/usr/bin/env -S deno run --allow-net=0.0.0.0:8080 --allow-run --allow-read
//
// NOT DEPLOYED. The Dockerfile does not copy this file into the image, port
// 8080 is not exposed, and fly.toml health-checks TCP 7777 directly — so
// nothing serves /health today. README used to say it was "consumed by
// status.ochk.io", which is not a site that exists. Kept because it is the
// right shape for a status surface to consume later; wire the COPY, the port
// and a services.http_checks block together when that happens.
//
// /health — JSON probe for relay.ochk.io
//
// Consumed by:
//   - UptimeRobot (5-min ping; alerts on 5xx or kind_distribution.30078=0)
//   - status.ochk.io (status page row)
//   - ochk.io's family-vitals widget once Phase 2 lands (replaces the
//     single-relay nos.lol COUNT)
//
// Output shape (stable, version-pinned):
//   {
//     "ok": true,
//     "event_count": 12345,
//     "last_event_at": "2026-05-07T21:00:00Z",
//     "lmdb_size_bytes": 671088640,
//     "kind_distribution": {
//       "30078": 2342,
//       "30080": 14,
//       ...
//     },
//     "ts": "2026-05-07T21:00:00Z"
//   }
//
// Implementation: shells out to `strfry stats` (single read txn over the
// LMDB), parses the JSON-ish output, returns. No persistent state in this
// service — strfry's LMDB is the only authority.

const STRFRY_CONFIG = Deno.env.get("STRFRY_CONFIG") ?? "/etc/strfry.conf";

const FAMILY_KINDS = [30078, 30080, 30081, 30082, 30083, 30084, 30085, 30086, 30087];

interface HealthSnapshot {
    ok: boolean;
    event_count: number;
    last_event_at: string | null;
    lmdb_size_bytes: number | null;
    kind_distribution: Record<string, number>;
    ts: string;
    error?: string;
}

async function strfryStats(): Promise<HealthSnapshot> {
    const ts = new Date().toISOString().replace(/\.\d+Z$/, "Z");
    const dist: Record<string, number> = {};
    let total = 0;
    let lastSeen = 0;

    for (const kind of FAMILY_KINDS) {
        const cmd = new Deno.Command("strfry", {
            args: ["--config", STRFRY_CONFIG, "scan", JSON.stringify({ kinds: [kind] })],
            stdout: "piped",
            stderr: "piped",
        });
        const { code, stdout } = await cmd.output();
        if (code !== 0) {
            return {
                ok: false,
                event_count: 0,
                last_event_at: null,
                lmdb_size_bytes: null,
                kind_distribution: {},
                ts,
                error: `strfry scan exit ${code}`,
            };
        }
        const lines = new TextDecoder().decode(stdout).split("\n").filter(Boolean);
        dist[String(kind)] = lines.length;
        total += lines.length;
        for (const line of lines) {
            try {
                const ev = JSON.parse(line) as { created_at?: number };
                if (typeof ev.created_at === "number" && ev.created_at > lastSeen) {
                    lastSeen = ev.created_at;
                }
            } catch {
                // ignore malformed line, never happens in practice
            }
        }
    }

    let lmdbSize: number | null = null;
    try {
        const stat = await Deno.stat("/data/strfry/db/data.mdb");
        lmdbSize = stat.size;
    } catch {
        // permissions or path drift; non-fatal
    }

    return {
        ok: true,
        event_count: total,
        last_event_at: lastSeen
            ? new Date(lastSeen * 1000).toISOString().replace(/\.\d+Z$/, "Z")
            : null,
        lmdb_size_bytes: lmdbSize,
        kind_distribution: dist,
        ts,
    };
}

const server = Deno.serve({ hostname: "0.0.0.0", port: 8080 }, async (req) => {
    const url = new URL(req.url);
    if (url.pathname !== "/health") {
        return new Response("not found\n", { status: 404 });
    }
    const snap = await strfryStats();
    return new Response(JSON.stringify(snap, null, 2), {
        status: snap.ok ? 200 : 503,
        headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "public, max-age=30",
        },
    });
});

console.error(`[health] listening on :8080 (config=${STRFRY_CONFIG})`);
await server.finished;
