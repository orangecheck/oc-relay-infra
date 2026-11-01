// gate.mjs as the plugin runs it: one line in, one line out, in order, each
// answer logged with its reason and counted, and the reads it asks of this relay.
// No chain read and no public relay is touched.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { directoryDtag } from '@orangecheck/lock-core/directory';
import { buildRevocationStatement, finalizeDeviceEvent } from '@orangecheck/lock-device';

import { fakeRelay, filler } from './fake-relay.mjs';

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

describe('gate.mjs public relay reads', () => {
    const address = 'bc1qmr7qn2t0ahj56ztpdswt54kn2r863ukd8wadj8';
    const slot = `oc-lock:device:${address}`;
    // A tombstone by a key this relay does not bind: the gate reads the public relays for it.
    const tombstone = () => {
        const content = { v: 2, handle: 'alice', address, opted_in: false, ends: 'cd'.repeat(32), created_at: 1_790_000_300 };
        const event = { id: 'e9'.repeat(32), kind: 30114, pubkey: 'ab'.repeat(32), created_at: 1_790_000_300, content: JSON.stringify(content), tags: [['d', directoryDtag('alice')]] };
        return JSON.stringify({ id: event.id, event, sourceType: 'IP4', sourceInfo: '203.0.113.1' }) + '\n';
    };
    const envFor = (local, publicRelays) => ({
        ...process.env,
        OC_DIR_GATE_COUNTS: join(mkdtempSync(join(tmpdir(), 'gate-')), 'counts.json'),
        OC_DIR_GATE_RELAY: local.url,
        OC_DIR_GATE_PUBLIC_RELAYS: publicRelays.map((r) => r.url).join(','),
    });

    it('pages a public relay past 500 records in the slot, and answers from the whole of it', async () => {
        const local = await fakeRelay();
        const pub = await fakeRelay(filler(30078, [['d', slot]], 600, 1_790_000_000));
        try {
            const answer = JSON.parse((await run(tombstone(), envFor(local, [pub]))).trim());
            const reads = pub.filters.filter((f) => f['#d']?.[0] === slot);
            assert.equal(reads.length, 2);
            assert.equal(reads[1].until, 1_790_000_000 - 499);
            // Read in full, the slot binds no one: refused as unbound, not as a relay that did not answer.
            assert.match(answer.msg, /^invalid: the signing key is not bound/);
        } finally {
            local.close();
            pub.close();
        }
    });

    it('a public relay whose slot is stuck on one second is no answer: refused, never admitted', async () => {
        const local = await fakeRelay();
        const pub = await fakeRelay(filler(30078, [['d', slot]], 600, 1_790_000_000, 600));
        try {
            const answer = JSON.parse((await run(tombstone(), envFor(local, [pub]))).trim());
            assert.match(answer.msg, /^rate-limited: /);
        } finally {
            local.close();
            pub.close();
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
