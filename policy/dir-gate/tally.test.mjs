// The gate's answer counts: per reason, per UTC day, kept across restarts.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';

import { createTally } from './tally.mjs';

const at = (iso) => () => Date.parse(iso);

describe('createTally', () => {
    it('counts each reason per day and keeps the counts across a restart', () => {
        const file = join(mkdtempSync(join(tmpdir(), 'tally-')), 'counts.json');
        const a = createTally({ file, now: at('2026-10-26T10:00:00Z') });
        assert.equal(a.count('accept'), 1);
        assert.equal(a.count('rate-limited: x'), 1);
        assert.equal(a.count('accept'), 2);
        const b = createTally({ file, now: at('2026-10-26T23:59:00Z') });
        assert.equal(b.count('accept'), 3);
        const c = createTally({ file, now: at('2026-10-27T00:00:01Z') });
        assert.equal(c.count('accept'), 1);
        assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), {
            '2026-10-26': { accept: 3, 'rate-limited: x': 1 },
            '2026-10-27': { accept: 1 },
        });
    });

    it('keeps two weeks and a bounded set of reasons', () => {
        const file = join(mkdtempSync(join(tmpdir(), 'tally-')), 'counts.json');
        for (let d = 1; d <= 20; d++) createTally({ file, now: at(`2026-11-${String(d).padStart(2, '0')}T00:00:00Z`) }).count('accept');
        assert.deepEqual(Object.keys(JSON.parse(readFileSync(file, 'utf8'))).length, 14);
        const t = createTally({ now: at('2026-12-01T00:00:00Z') });
        for (let i = 0; i < 70; i++) t.count(`reason ${i}`);
        assert.equal(Object.keys(t.snapshot()['2026-12-01']).length, 65);
        assert.equal(t.snapshot()['2026-12-01'].other, 6);
    });

    it('a broken file or an unwritable path never stops counting', () => {
        const file = join(mkdtempSync(join(tmpdir(), 'tally-')), 'counts.json');
        writeFileSync(file, 'not json');
        assert.equal(createTally({ file }).count('accept'), 1);
        assert.equal(createTally({ file: '/nonexistent/dir/counts.json' }).count('accept'), 1);
    });
});
