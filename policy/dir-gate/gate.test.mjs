// gate.mjs as the plugin runs it: one line in, one line out, in order, each
// answer logged with its reason and counted. These records are refused before
// any chain or relay read, so no network is touched.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { directoryDtag } from '@orangecheck/lock-core/directory';

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
        assert.match(v1Reason, /^blocked: a v1 listing holds no handle/);
        assert.match(out.stderr, /dir-gate: blocked: a v1 listing holds no handle; publish v2 \(OC Chat 0\.4 §8\.2\.1\) \(2 today\)/);
        const days = JSON.parse(readFileSync(counts, 'utf8'));
        assert.deepEqual(Object.values(days)[0], { [v1Reason]: 2, 'invalid: content is not JSON': 1 });
    });
});
