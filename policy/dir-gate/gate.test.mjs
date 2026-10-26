// gate.mjs as the plugin runs it: one line in, one line out, in order, each
// answer logged with its reason and counted, and the reads it asks of this relay.
// No chain read and no public relay is touched.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { directoryDtag } from '@orangecheck/lock-core/directory';
import { buildRevocationStatement, finalizeDeviceEvent } from '@orangecheck/lock-device';

const here = dirname(fileURLToPath(import.meta.url));
const line = (id, content) =>
    JSON.stringify({
        id,
        event: { id, kind: 30114, pubkey: 'ab'.repeat(32), content, tags: [['d', directoryDtag('alice')]] },
        sourceType: 'IP4',
        sourceInfo: '203.0.113.1',
    });

describe('gate.mjs', () => {
    it('answers each line in order, and logs and counts every answer by reason', () => {
        const counts = join(mkdtempSync(join(tmpdir(), 'gate-')), 'counts.json');
        const v1 = JSON.stringify({ v: 1, handle: 'alice', address: 'bc1q', inbox_pubkey: 'ab'.repeat(32), opted_in: true, created_at: 1 });
        const input = [line('e1', v1), 'not json', line('e2', '{'), line('e3', v1)].join('\n') + '\n';
        const out = spawnSync(process.execPath, [join(here, 'gate.mjs')], {
            input,
            encoding: 'utf8',
            env: { ...process.env, OC_DIR_GATE_COUNTS: counts, OC_DIR_GATE_RELAY: 'ws://127.0.0.1:9' },
            timeout: 20_000,
        });
        const answers = out.stdout.trim().split('\n').map((l) => JSON.parse(l));
        assert.deepEqual(
            answers.map((a) => [a.id, a.action]),
            [['e1', 'reject'], ['e2', 'reject'], ['e3', 'reject']]
        );
        const v1Reason = answers[0].msg;
        assert.match(v1Reason, /^blocked: v1 directory records are not accepted here/);
        assert.match(out.stderr, /dir-gate: blocked: v1 directory records are not accepted here; publish v2 \(OC Chat 0\.4 §8\.2\.1\) \(2 today\)/);
        const days = JSON.parse(readFileSync(counts, 'utf8'));
        assert.deepEqual(Object.values(days)[0], { [v1Reason]: 2, 'invalid: content is not JSON': 1 });
    });

    it('reads a revoking key\'s own records by its author, apart from the rest of the slot', async () => {
        const relay = await fakeRelay();
        const address = 'bc1qmr7qn2t0ahj56ztpdswt54kn2r863ukd8wadj8';
        const advice = finalizeDeviceEvent({
            deviceSk: new Uint8Array(32).fill(1),
            address,
            device_id: 'dev1',
            device_pk: 'revoked',
            bindingStatement: buildRevocationStatement({ address, device_id: 'dev1', revoked_at: '2026-10-03T00:00:00Z' }),
            bindingSigBase64: '',
            createdAtUnix: 1_790_000_200,
        });
        const input = JSON.stringify({ id: advice.id, event: advice, sourceType: 'IP4', sourceInfo: '203.0.113.1' }) + '\n';
        const env = {
            ...process.env,
            OC_DIR_GATE_COUNTS: join(mkdtempSync(join(tmpdir(), 'gate-')), 'counts.json'),
            OC_DIR_GATE_RELAY: relay.url,
            OC_DIR_GATE_PUBLIC_RELAYS: '',
        };
        try {
            const out = await run(input, env);
            assert.equal(JSON.parse(out.trim()).action, 'reject');
            assert.deepEqual(relay.filters, [{ kinds: [30078], '#d': [`oc-lock:device:${address}`], authors: [advice.pubkey], limit: 50 }]);
        } finally {
            relay.close();
        }
    });
});

/** gate.mjs fed `input`, its stdout once it exits. */
function run(input, env) {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [join(here, 'gate.mjs')], { env });
        let out = '';
        child.stdout.on('data', (b) => (out += b));
        child.on('error', reject);
        child.on('close', () => resolve(out));
        child.stdin.end(input);
    });
}

/** A relay that answers every REQ with EOSE and nothing else, keeping the filters it was asked. */
async function fakeRelay() {
    const filters = [];
    const frame = (obj) => {
        const body = Buffer.from(JSON.stringify(obj));
        const head = body.length < 126 ? Buffer.from([0x81, body.length]) : Buffer.from([0x81, 126, body.length >> 8, body.length & 0xff]);
        return Buffer.concat([head, body]);
    };
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
                if (msg[0] === 'REQ') {
                    filters.push(msg[2]);
                    socket.write(frame(['EOSE', msg[1]]));
                }
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

describe('the relay gate.mjs reads', () => {
    it("is strfry's own address from strfry.conf, not the front's", () => {
        const conf = readFileSync(join(here, '..', '..', 'strfry.conf'), 'utf8');
        const relay = conf.slice(conf.indexOf('\nrelay {'));
        const bind = relay.match(/^\s*bind = "([^"]+)"/m)?.[1];
        const port = relay.match(/^\s*port = (\d+)/m)?.[1];
        const source = readFileSync(join(here, 'gate.mjs'), 'utf8');
        assert.ok(bind && port, 'strfry.conf names a bind and a port');
        assert.match(source, new RegExp(`\\|\\| 'ws://${bind.replaceAll('.', '\\.')}:${port}';`));
    });
});
