// Counts of the gate's answers by reason, per UTC day, in a small JSON file on the
// relay's volume, so they outlive a restarted sidecar and a deploy. Reasons are the
// gate's own fixed strings; they carry nothing from the event or its sender.

import { readFileSync, renameSync, writeFileSync } from 'node:fs';

const KEEP_DAYS = 14;
const MAX_REASONS = 64;

export function createTally({ file, now = () => Date.now() } = {}) {
    let days = {};
    if (file) {
        try {
            const read = JSON.parse(readFileSync(file, 'utf8'));
            if (read && typeof read === 'object' && !Array.isArray(read)) days = read;
        } catch {
            // No file yet, or an unreadable one: start counting again.
        }
    }
    const save = () => {
        if (!file) return;
        const kept = Object.keys(days).sort().slice(-KEEP_DAYS);
        days = Object.fromEntries(kept.map((k) => [k, days[k]]));
        try {
            writeFileSync(file + '.tmp', JSON.stringify(days));
            renameSync(file + '.tmp', file);
        } catch {
            // Counting must never stop the gate.
        }
    };
    return {
        /** Count one answer; returns today's count for its reason. */
        count(reason) {
            const day = new Date(now()).toISOString().slice(0, 10);
            const today = (days[day] ??= {});
            const key = reason in today || Object.keys(today).length < MAX_REASONS ? reason : 'other';
            today[key] = (today[key] ?? 0) + 1;
            save();
            return today[key];
        },
        snapshot: () => days,
    };
}
