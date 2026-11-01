// fetch.mjs as archive.py runs it, against a relay that answers as strfry does (500 to a
// page, newest first). A kind is read to its oldest event, or the run fails: a page it
// cannot read past means the archive would not be the whole set.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { fakeRelay, filler } from '../policy/dir-gate/fake-relay.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const T = 1_790_000_000;
const D = [['d', 'oc-attest:x']];

/** fetch.mjs run against `events` for kind 30078: its exit code, stdout and stderr. */
async function fetchAll(events) {
    const relay = await fakeRelay(events);
    try {
        return await new Promise((resolve, reject) => {
            const child = spawn(process.execPath, [join(here, 'fetch.mjs'), relay.url, '30078']);
            let out = '';
            let err = '';
            child.stdout.on('data', (b) => (out += b));
            child.stderr.on('data', (b) => (err += b));
            child.on('error', reject);
            child.on('close', (code) => resolve({ code, out, err }));
        });
    } finally {
        relay.close();
    }
}

describe('fetch.mjs', () => {
    it('reads a kind past several pages, to its oldest event', async () => {
        const { code, out } = await fetchAll(filler(30078, D, 1200, T));
        assert.equal(code, 0);
        assert.equal(JSON.parse(out).length, 1200);
    });

    it('fails the run on a full page that adds nothing, rather than write part of the set', async () => {
        const events = [...filler(30078, D, 600, T, 600), ...filler(30078, D, 50, T - 1)];
        const { code, out, err } = await fetchAll(events);
        assert.notEqual(code, 0);
        assert.equal(out, '');
        assert.match(err, /incomplete: kind 30078/);
    });

    it('fails the run, rather than skip the rest of a second a page boundary splits', async () => {
        // 10 newer, then 520 in one second: the second page reads 500 of them, and the
        // rest cannot be paged to, since `until` names a second, not a place in it.
        const events = [...filler(30078, D, 10, T + 10), ...filler(30078, D, 520, T, 520), ...filler(30078, D, 20, T - 1)];
        const { code, out } = await fetchAll(events);
        assert.notEqual(code, 0);
        assert.equal(out, '');
    });

    it('reads every event of a second that a page boundary splits, when the second fits a page', async () => {
        const events = [...filler(30078, D, 498, T + 498), ...filler(30078, D, 4, T, 4), ...filler(30078, D, 10, T - 1)];
        const { code, out } = await fetchAll(events);
        assert.equal(code, 0);
        assert.equal(JSON.parse(out).length, 512);
    });
});
