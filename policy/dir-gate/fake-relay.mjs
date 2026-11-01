// A relay for the tests, on a local socket: it answers each REQ as strfry does, newest
// first, `until` and `limit` kept, never more than 500 events, then EOSE, and keeps the
// filters it was asked. With no events it answers EOSE alone.
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';

const CAP = 500;

function matches(ev, filter) {
    if (filter.kinds && !filter.kinds.includes(ev.kind)) return false;
    if (filter.authors && !filter.authors.includes(ev.pubkey)) return false;
    if (filter.until !== undefined && ev.created_at > filter.until) return false;
    for (const [key, values] of Object.entries(filter)) {
        if (!key.startsWith('#')) continue;
        if (!ev.tags.some((t) => t[0] === key.slice(1) && values.includes(t[1]))) return false;
    }
    return true;
}

const newestFirst = (a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

function frame(obj) {
    const body = Buffer.from(JSON.stringify(obj));
    if (body.length < 126) return Buffer.concat([Buffer.from([0x81, body.length]), body]);
    if (body.length < 65536) return Buffer.concat([Buffer.from([0x81, 126, body.length >> 8, body.length & 0xff]), body]);
    const head = Buffer.alloc(10);
    head[0] = 0x81;
    head[1] = 127;
    head.writeBigUInt64BE(BigInt(body.length), 2);
    return Buffer.concat([head, body]);
}

export async function fakeRelay(events = []) {
    const filters = [];
    const server = createServer();
    server.on('upgrade', (req, socket) => {
        const accept = createHash('sha1').update(`${req.headers['sec-websocket-key']}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
        socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
        let buf = Buffer.alloc(0);
        socket.on('error', () => {});
        socket.on('data', (chunk) => {
            buf = Buffer.concat([buf, chunk]);
            for (;;) {
                if (buf.length < 2) return;
                let len = buf[1] & 0x7f;
                let off = 2;
                if (len === 126) {
                    if (buf.length < 4) return;
                    len = buf.readUInt16BE(2);
                    off = 4;
                }
                const mask = buf.subarray(off, off + 4);
                off += 4;
                if (buf.length < off + len) return;
                const data = Buffer.from(buf.subarray(off, off + len)).map((b, i) => b ^ mask[i % 4]);
                const op = buf[0] & 0x0f;
                buf = buf.subarray(off + len);
                if (op === 8) return socket.end();
                const msg = JSON.parse(data.toString());
                if (msg[0] !== 'REQ') continue;
                const filter = msg[2];
                filters.push(filter);
                const page = events
                    .filter((e) => matches(e, filter))
                    .sort(newestFirst)
                    .slice(0, Math.min(filter.limit ?? CAP, CAP));
                for (const e of page) socket.write(frame(['EVENT', msg[1], e]));
                socket.write(frame(['EOSE', msg[1]]));
            }
        });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return {
        url: `ws://127.0.0.1:${server.address().port}`,
        filters,
        close: () => server.close(),
    };
}

let n = 0;
/** `count` events of `kind` under `tags`, dated from `from` downward, `perSecond` to a second. */
export function filler(kind, tags, count, from, perSecond = 1) {
    return Array.from({ length: count }, (_, i) => ({
        id: (++n).toString(16).padStart(64, '0'),
        pubkey: 'f'.repeat(64),
        created_at: from - Math.floor(i / perSecond),
        kind,
        tags,
        content: 'filler',
        sig: '00'.repeat(64),
    }));
}
