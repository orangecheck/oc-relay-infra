// Dump every event of the given kinds from one relay as a JSON array on stdout.
// Pages backwards with `until`, one kind per REQ, until a page adds nothing new.
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

const all = new Map();
for (const kind of kinds) {
    let until;
    for (;;) {
        const filter = { kinds: [kind], limit: 500, ...(until === undefined ? {} : { until }) };
        const events = await page(filter);
        let added = 0;
        for (const e of events) if (!all.has(e.id)) (all.set(e.id, e), added++);
        if (added === 0) break;
        const oldest = Math.min(...events.map((e) => e.created_at));
        until = until === oldest ? oldest - 1 : oldest;
    }
}
ws.close();
process.stdout.write(JSON.stringify([...all.values()]));
