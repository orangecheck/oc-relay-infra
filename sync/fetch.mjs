// Dump every event of the given kinds from one relay as a JSON array on stdout.
// Pages backwards with `until`, one kind per REQ, until a page comes back short.
// `until` names a second, so a second holding more than a page cannot be read past:
// a full page that adds nothing exits 1 with nothing on stdout, and the archive is
// not rewritten from part of the set. relay.ochk.io's strfry answers 500 to a page
// (its default maxFilterLimit), the limit asked.
//   node sync/fetch.mjs wss://relay.ochk.io 30078,30080,...
const [, , relay, kindList] = process.argv;
const kinds = kindList.split(',').map(Number);

const ws = new WebSocket(relay);
await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error(`cannot connect to ${relay}`));
});

function page(filter) {
    const sub = 'a' + Math.random().toString(36).slice(2, 8);
    return new Promise((resolve, reject) => {
        const events = [];
        const timer = setTimeout(() => reject(new Error(`no EOSE from ${relay} for ${JSON.stringify(filter)}`)), 30000);
        ws.onmessage = (m) => {
            const msg = JSON.parse(m.data);
            if (msg[1] !== sub) return;
            if (msg[0] === 'EVENT') events.push(msg[2]);
            if (msg[0] === 'EOSE' || msg[0] === 'CLOSED') {
                clearTimeout(timer);
                ws.send(JSON.stringify(['CLOSE', sub]));
                if (msg[0] === 'CLOSED') reject(new Error(`relay closed the query: ${msg[2]}`));
                else resolve(events);
            }
        };
        ws.send(JSON.stringify(['REQ', sub, filter]));
    });
}

const LIMIT = 500;
const all = new Map();
for (const kind of kinds) {
    let until;
    for (;;) {
        const filter = { kinds: [kind], limit: LIMIT, ...(until === undefined ? {} : { until }) };
        const events = await page(filter);
        let added = 0;
        for (const e of events) if (!all.has(e.id)) (all.set(e.id, e), added++);
        if (events.length < LIMIT) break;
        if (added === 0) {
            ws.close();
            process.stderr.write(`incomplete: kind ${kind} has more than ${LIMIT} events at created_at ${until}, which a page cannot read past\n`);
            process.exit(1);
        }
        // The next page starts at the oldest second again, so the rest of that second is read.
        until = Math.min(...events.map((e) => e.created_at));
    }
}
ws.close();
process.stdout.write(JSON.stringify([...all.values()]));
