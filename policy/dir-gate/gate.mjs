// The kind-30114 sidecar of oc-dtag-filter.py: one JSON line in per event
// ({id, event, sourceType, sourceInfo}), one line out ({id, action, msg?}).
// Chain facts come from an Esplora API (mempool.space unless OC_DIR_GATE_ESPLORA
// says otherwise); device records and stored listings from this relay itself.

import { createInterface } from 'node:readline';

import { verifySignature } from '@orangecheck/bip322';
import { esploraCoinReader } from '@orangecheck/lock-core/directory';
import { mempoolHeaderSource } from '@orangecheck/stamp-ots';

import { createGate } from './rules.mjs';

const ESPLORA = (process.env.OC_DIR_GATE_ESPLORA || 'https://mempool.space/api').replace(/\/+$/, '');
const RELAY = process.env.OC_DIR_GATE_RELAY || 'ws://127.0.0.1:7777';
const HTTP_TIMEOUT_MS = 2000;
const RELAY_TIMEOUT_MS = 1500;

const timedFetch = (url, init = {}) => fetch(url, { ...init, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });

/** Every event this relay returns for one filter, paged by `until`, or 'no-answer'. */
async function query(filter, { pages = 1 } = {}) {
    const all = new Map();
    let until;
    for (let page = 0; page < pages; page++) {
        const got = await new Promise((resolve) => {
            const out = [];
            let ws;
            const done = (v) => {
                clearTimeout(timer);
                try {
                    ws?.close();
                } catch {}
                resolve(v);
            };
            const timer = setTimeout(() => done('no-answer'), RELAY_TIMEOUT_MS);
            try {
                ws = new WebSocket(RELAY);
            } catch {
                return done('no-answer');
            }
            ws.onopen = () => ws.send(JSON.stringify(['REQ', 'g', until === undefined ? filter : { ...filter, until }]));
            ws.onerror = () => done('no-answer');
            ws.onmessage = (m) => {
                let frame;
                try {
                    frame = JSON.parse(m.data);
                } catch {
                    return;
                }
                if (frame[0] === 'EVENT' && frame[1] === 'g') out.push(frame[2]);
                else if (frame[0] === 'EOSE' && frame[1] === 'g') done(out);
                else if (frame[0] === 'CLOSED' && frame[1] === 'g') done('no-answer');
            };
        });
        if (got === 'no-answer') return got;
        let added = 0;
        for (const ev of got) {
            if (!all.has(ev.id)) {
                all.set(ev.id, ev);
                added++;
            }
            until = until === undefined ? ev.created_at : Math.min(until, ev.created_at);
        }
        // A short page is the end; a full page that adds nothing, or no pages left, is an incomplete read.
        if (got.length < filter.limit) break;
        if (added === 0 || page === pages - 1) return 'no-answer';
    }
    return [...all.values()];
}

const coinReader = esploraCoinReader({ baseUrl: ESPLORA, fetch: timedFetch, timeoutMs: HTTP_TIMEOUT_MS });

const gate = createGate({
    async tip() {
        const r = await timedFetch(`${ESPLORA}/blocks/tip/height`);
        if (!r.ok) throw new Error(`tip: HTTP ${r.status}`);
        const text = (await r.text()).trim();
        if (!/^[0-9]{1,9}$/.test(text)) throw new Error('tip: unexpected answer');
        return Number(text);
    },
    headers: mempoolHeaderSource({ baseUrl: ESPLORA, fetch: timedFetch }),
    coin: (outpoint) => coinReader(outpoint),
    deviceEvents: (address) => query({ kinds: [30078], '#d': [`oc-lock:device:${address}`], limit: 500 }, { pages: 4 }),
    stored: (d) => query({ kinds: [30114], '#d': [d], limit: 500 }),
    allStored: () => query({ kinds: [30114], limit: 500 }, { pages: 40 }),
    verifyBip322: ({ address, message, signature }) => verifySignature(address, message, signature),
    now: () => Date.now(),
});

// strfry sends one event at a time and waits; answers go out in arrival order.
let chain = Promise.resolve();
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
lines.on('line', (line) => {
    chain = chain.then(async () => {
        let msg;
        try {
            msg = JSON.parse(line);
        } catch {
            return;
        }
        const id = typeof msg?.event?.id === 'string' ? msg.event.id : msg?.id;
        const started = Date.now();
        const out = await gate.check(msg);
        const d = (msg?.event?.tags ?? []).find((t) => Array.isArray(t) && t[0] === 'd')?.[1] ?? '';
        process.stderr.write(`dir-gate: ${out.action}${out.msg ? ` (${out.msg})` : ''} d=${String(d).slice(0, 30)} ${Date.now() - started}ms\n`);
        process.stdout.write(JSON.stringify({ id: msg.id ?? id, ...out }) + '\n');
    });
});
lines.on('close', () => chain.then(() => process.exit(0)));
