// The kind-30114 write gate against signed records and a fake chain: what it
// admits, what it refuses, and that every unanswered read refuses.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';

import { channelClaimId, channelDirectoryDtag, channelId, claimId, directoryDtag, repointId } from '@orangecheck/lock-core/directory';
import {
    BINDING_VERSION,
    buildBindingStatement,
    buildRevocationStatement,
    deriveNostrKey,
    finalizeDeviceEvent,
    signNostrEvent,
} from '@orangecheck/lock-device';
import { base64Encode, serializeTimestamp } from '@orangecheck/stamp-ots';

import { createGate, LIMITS } from './rules.mjs';

const ADDR = 'bc1qmr7qn2t0ahj56ztpdswt54kn2r863ukd8wadj8';
const TIP = 930_000;
const ANCHOR = TIP - 10;
const sha = (s) => createHash('sha256').update(s).digest('hex');
const sk = (n) => new Uint8Array(32).fill(n);
const nostr = (n) => deriveNostrKey(sk(n));

/** A stub wallet: "sig:<address>" signs that address's statements. */
const verifyBip322 = ({ address, message, signature }) => signature === `sig:${address}` && message.includes(`address: ${address}`);

function device(n, address = ADDR) {
    return finalizeDeviceEvent({
        deviceSk: sk(n),
        address,
        device_id: `dev${n}`,
        device_pk: 'aa'.repeat(32),
        bindingStatement: buildBindingStatement({
            address,
            device_pk: 'aa'.repeat(32),
            device_id: `dev${n}`,
            created_at: '2026-10-01T00:00:00Z',
            nostr_pk: nostr(n).nostrPk,
        }),
        bindingSigBase64: `sig:${address}`,
        createdAtUnix: 1_790_000_000,
    });
}

function revocation(n, address = ADDR) {
    const { nostrSk, nostrPk } = nostr(99);
    return signNostrEvent(
        {
            pubkey: nostrPk,
            kind: 30078,
            created_at: 1_790_000_100,
            content: buildRevocationStatement({ address, device_id: `dev${n}`, revoked_at: '2026-10-02T00:00:00Z' }),
            tags: [
                ['d', `oc-lock:device:${address}`],
                ['binding_sig', `sig:${address}`],
            ],
        },
        nostrSk
    );
}

/** A bare OpenTimestamps proof whose one Bitcoin attestation commits to `idHex` as a Merkle root. */
const proof = (idHex, height) =>
    base64Encode(serializeTimestamp({ msg: Buffer.from(idHex, 'hex'), attestations: [{ kind: 'bitcoin', height }], ops: [] }));
const header = (rootHex) => {
    const h = Buffer.alloc(80);
    Buffer.from(rootHex, 'hex').copy(h, 36);
    return new Uint8Array(h);
};

/** One claim per block here: the bare proof makes the claim id the block's Merkle root. */
function claimFor(handle, { outpoint = `${'ab'.repeat(32)}:0`, nonce = sha('nonce ' + handle), address = ADDR, height = ANCHOR, idOf = claimId } = {}) {
    const id = idOf({ handle, address, outpoint, nonce });
    return { id, height, claim: { outpoint, nonce, ots: proof(id, height) } };
}

function listingEvent(handle, { n = 1, claim = claimFor(handle), extra = {}, d = directoryDtag(handle) } = {}) {
    const { nostrSk, nostrPk } = nostr(n);
    const content = { v: 2, handle, address: ADDR, inbox_pubkey: nostrPk, claim: claim.claim, opted_in: true, created_at: 1_790_000_200, ...extra };
    return signNostrEvent({ pubkey: nostrPk, kind: 30114, created_at: 1_790_000_200, content: JSON.stringify(content), tags: [['d', d]] }, nostrSk);
}

function tombstoneEvent(handle, ends, n = 1) {
    const { nostrSk, nostrPk } = nostr(n);
    const content = { v: 2, handle, address: ADDR, opted_in: false, ends, created_at: 1_790_000_300 };
    return signNostrEvent(
        { pubkey: nostrPk, kind: 30114, created_at: 1_790_000_300, content: JSON.stringify(content), tags: [['d', directoryDtag(handle)]] },
        nostrSk
    );
}

/** A world: chain facts, this relay's stored events, a clock. Every read is counted. */
function world(over = {}) {
    const w = {
        t: Date.parse('2026-10-25T00:00:00Z'),
        reads: { tip: 0, header: 0, coin: 0, device: 0, stored: 0 },
        roots: new Map(),
        coins: new Map(),
        devices: [device(1)],
        stored: [],
        ...over,
    };
    const deps = {
        tip: async () => (w.reads.tip++, w.tipFails ? Promise.reject(new Error('down')) : TIP),
        headers: {
            getHeaderAt: async (h) => {
                w.reads.header++;
                if (w.headerFails) throw new Error('down');
                return w.roots.has(h) ? header(w.roots.get(h)) : null;
            },
        },
        coin: async (op) => (w.reads.coin++, w.coinHangs ? new Promise(() => {}) : (w.coins.get(op) ?? 'no-answer')),
        deviceEvents: async () => (w.reads.device++, w.deviceFails ? 'no-answer' : w.devices),
        deviceEventsBy: async (_a, pk) => (w.ownFails ? 'no-answer' : w.devices.filter((e) => e.pubkey === pk)),
        publicDeviceEvents: async () => ({ events: w.publicDevices ?? [], allAnswered: !w.publicFails }),
        stored: async (d) => (w.reads.stored++, w.stored.filter((e) => e.tags.some((t) => t[0] === 'd' && t[1] === d))),
        allStored: async () => w.stored,
        verifyBip322,
        now: () => w.t,
    };
    return { w, deps };
}

/** Anchor a claim's proof at ANCHOR and give its coin the facts asked for. */
function chainFor(w, claim, coin = { confirmedAt: ANCHOR - 200, value: 546, paysTo: ADDR, spendHeight: null }) {
    w.roots.set(claim.height, claim.id);
    w.coins.set(claim.claim.outpoint, coin);
}

const msg = (event, sourceInfo = '203.0.113.1', sourceType = 'IP4') => ({ id: event.id, event, sourceType, sourceInfo });

describe('a listing', () => {
    it('is admitted when it passes the four checks', async () => {
        const { w, deps } = world();
        const ev = listingEvent('alice');
        chainFor(w, claimFor('alice'));
        assert.deepEqual(await createGate(deps).check(msg(ev)), { action: 'accept' });
    });

    it('is refused before any read for its shape, its d tag or its signer', async () => {
        const { w, deps } = world();
        const gate = createGate(deps);
        const v1 = listingEvent('alice', { extra: { v: 1 } });
        assert.match((await gate.check(msg(v1))).msg, /^blocked: v1 directory records are not accepted here/);
        assert.match((await gate.check(msg(listingEvent('alice', { d: directoryDtag('bob') })))).msg, /^invalid: the d tag/);
        assert.match((await gate.check(msg(listingEvent('alice', { extra: { inbox_pubkey: nostr(2).nostrPk } })))).msg, /^invalid: a listing is signed by its inbox key/);
        assert.match((await gate.check(msg(listingEvent('alice', { extra: { claim: { outpoint: 'x' } } })))).msg, /^invalid: not a v2/);
        assert.deepEqual(w.reads, { tip: 0, header: 0, coin: 0, device: 0, stored: 0 });
    });

    it('is refused with a second d tag, before any read', async () => {
        const { w, deps } = world();
        const ev = listingEvent('alice');
        chainFor(w, claimFor('alice'));
        const twice = signNostrEvent(
            { pubkey: ev.pubkey, kind: 30114, created_at: ev.created_at, content: ev.content, tags: [...ev.tags, ['d', directoryDtag('bob')]] },
            nostr(1).nostrSk
        );
        assert.match((await createGate(deps).check(msg(twice))).msg, /^invalid: a record carries exactly one d tag/);
        assert.deepEqual(w.reads, { tip: 0, header: 0, coin: 0, device: 0, stored: 0 });
        assert.deepEqual(await createGate(deps).check(msg(ev)), { action: 'accept' });
    });

    it('is refused when unanchored or anchored fewer than 6 blocks deep', async () => {
        const { w, deps } = world();
        assert.match((await createGate(deps).check(msg(listingEvent('alice')))).msg, /^invalid: the claim is not anchored/);
        const near = claimFor('alice');
        near.claim.ots = proof(near.id, TIP - 4);
        w.roots.set(TIP - 4, near.id);
        const gate = createGate(deps);
        const before = w.reads.header;
        assert.match((await gate.check(msg(listingEvent('alice', { claim: near })))).msg, /6 confirmations/);
        // A header this near the tip is never cached: it can still change.
        assert.match((await gate.check(msg(listingEvent('alice', { claim: near })))).msg, /6 confirmations/);
        assert.equal(w.reads.header - before, 2);
        assert.equal(w.reads.device, 0);
    });

    /** A bare proof committing to `idHex` with one Bitcoin attestation per height. */
    const proofAt = (idHex, heights) =>
        base64Encode(
            serializeTimestamp({ msg: Buffer.from(idHex, 'hex'), attestations: heights.map((height) => ({ kind: 'bitcoin', height })), ops: [] })
        );

    it("is refused when its proof also carries attestations its blocks do not confirm, below its anchor or above it", async () => {
        for (const fakes of [[ANCHOR - 900, ANCHOR - 800, ANCHOR - 700, ANCHOR - 600, ANCHOR - 500, ANCHOR - 400, ANCHOR - 300], [ANCHOR + 2]]) {
            const { w, deps } = world();
            const c = claimFor('alice');
            chainFor(w, c);
            for (const h of fakes) w.roots.set(h, sha('another block ' + h));
            c.claim.ots = proofAt(c.id, [...fakes, ANCHOR]);
            assert.match(
                (await createGate(deps).check(msg(listingEvent('alice', { claim: c })))).msg,
                /^invalid: the claim's proof carries an attestation its block does not confirm/,
                String(fakes)
            );
        }
    });

    it('is admitted when every attestation its proof carries is confirmed, each header read once', async () => {
        const { w, deps } = world();
        const c = claimFor('alice');
        chainFor(w, c);
        w.roots.set(ANCHOR + 1, c.id);
        c.claim.ots = proofAt(c.id, [ANCHOR, ANCHOR + 1]);
        assert.deepEqual(await createGate(deps).check(msg(listingEvent('alice', { claim: c }))), { action: 'accept' });
        assert.equal(w.reads.header, 2);
    });

    it("is refused when a re-point's proof carries an attestation its block does not confirm", async () => {
        const { w, deps } = world();
        const c = claimFor('alice');
        chainFor(w, c);
        const r = { prev: c.claim.outpoint, outpoint: `${'cd'.repeat(32)}:1`, nonce: sha('re-point nonce') };
        const rid = repointId({ claim: c.id, ...r });
        w.roots.set(ANCHOR + 1, rid);
        w.roots.set(ANCHOR - 50, sha('another block'));
        c.claim.repoints = [{ ...r, ots: proofAt(rid, [ANCHOR - 50, ANCHOR + 1]) }];
        assert.match(
            (await createGate(deps).check(msg(listingEvent('alice', { claim: c })))).msg,
            /^invalid: a re-point's proof carries an attestation its block does not confirm/
        );
    });

    it('is refused unanchored when its proof carries more than 8 Bitcoin attestations, with no header read', async () => {
        const { w, deps } = world();
        const c = claimFor('alice');
        const idBytes = Buffer.from(c.id, 'hex');
        const ops = Array.from({ length: 9 }, (_, i) => {
            const salt = createHash('sha256').update('cap ' + i).digest().subarray(0, 16);
            const appended = Buffer.concat([idBytes, salt]);
            const root = createHash('sha256').update(appended).digest();
            w.roots.set(ANCHOR - i, root.toString('hex'));
            return {
                op: { kind: 'append', arg: new Uint8Array(salt) },
                child: { msg: new Uint8Array(appended), attestations: [], ops: [{ op: { kind: 'sha256' }, child: { msg: new Uint8Array(root), attestations: [{ kind: 'bitcoin', height: ANCHOR - i }], ops: [] } }] },
            };
        });
        c.claim.ots = base64Encode(serializeTimestamp({ msg: new Uint8Array(idBytes), attestations: [], ops }));
        w.coins.set(c.claim.outpoint, { confirmedAt: ANCHOR - 300, value: 546, paysTo: ADDR, spendHeight: null });
        assert.match((await createGate(deps).check(msg(listingEvent('alice', { claim: c })))).msg, /^invalid: the claim is not anchored/);
        assert.equal(w.reads.header, 0);
    });

    it('is refused when its key is not bound, or is bound by a revoked record', async () => {
        const { w, deps } = world({ devices: [device(2)] });
        chainFor(w, claimFor('alice'));
        assert.match((await createGate(deps).check(msg(listingEvent('alice')))).msg, /not bound to the address/);
        w.devices = [device(1), revocation(1)];
        assert.match((await createGate(deps).check(msg(listingEvent('alice')))).msg, /not bound to the address/);
    });

    it('is refused when its coin does not clear the floor at the anchor', async () => {
        const { w, deps } = world();
        chainFor(w, claimFor('alice'), { confirmedAt: ANCHOR - 143, value: 546, paysTo: ADDR, spendHeight: null });
        assert.match((await createGate(deps).check(msg(listingEvent('alice')))).msg, /coin does not hold it/);
    });

    it('a channel listing goes through the same gate under its founder fields', async () => {
        const { w, deps } = world();
        const { nostrSk, nostrPk } = nostr(1);
        // A channel's claim names its namespace (OC Chat §8.3.6).
        const c = claimFor('builders', { idOf: channelClaimId });
        chainFor(w, c);
        const content = (cid) => ({
            v: 2,
            handle: 'builders',
            slug: 'bitcoin-talk',
            channel_id: cid,
            founder_address: ADDR,
            founder_inbox_pubkey: nostrPk,
            title: 'Bitcoin talk',
            claim: c.claim,
            opted_in: true,
            created_at: 1_790_000_200,
        });
        const ev = (cid) =>
            signNostrEvent(
                { pubkey: nostrPk, kind: 30114, created_at: 1_790_000_200, content: JSON.stringify(content(cid)), tags: [['d', channelDirectoryDtag('builders')]] },
                nostrSk
            );
        assert.deepEqual(await createGate(deps).check(msg(ev(channelId(ADDR, 'bitcoin-talk')))), { action: 'accept' });
        assert.match((await createGate(deps).check(msg(ev(channelId(ADDR, 'other'))))).msg, /^invalid: not a v2/);
    });
});

describe('a read without an answer refuses, never admits', () => {
    for (const [name, set] of [
        ['the tip', (w) => (w.tipFails = true)],
        ['a header', (w) => (w.headerFails = true)],
        ['the coin', (w) => w.coins.clear()],
        ['the device records', (w) => ((w.deviceFails = true), (w.ownFails = true))],
        ['a public relay, for a key not bound here', (w) => ((w.devices = []), (w.publicFails = true))],
    ]) {
        it(name, async () => {
            const { w, deps } = world();
            chainFor(w, claimFor('alice'));
            set(w);
            assert.match((await createGate(deps).check(msg(listingEvent('alice')))).msg, /^rate-limited: /);
            // Cheapest first: an anchor that cannot be read costs no binding read.
            if (name === 'the tip' || name === 'a header') assert.equal(w.reads.device, 0);
        });
    }

    it('a hung read is cut off at the deadline', { timeout: 2000 }, async () => {
        const { w, deps } = world();
        chainFor(w, claimFor('alice'));
        w.coinHangs = true;
        const started = Date.now();
        const out = await createGate(deps, { ...LIMITS, deadlineMs: 50 }).check(msg(listingEvent('alice')));
        assert.match(out.msg, /^rate-limited: the directory check took too long/);
        assert.ok(Date.now() - started < 1000);
    });
});

describe('where bindings are read', () => {
    it('a slot this relay did not read in full refuses, though the signer binds itself: a revocation may sit there', async () => {
        const { w, deps } = world({ devices: [device(1), revocation(1)] });
        chainFor(w, claimFor('alice'));
        w.deviceFails = true; // the full read of the slot gives up; the signer's own read still binds it
        const out = await createGate(deps).check(msg(listingEvent('alice')));
        assert.match(out.msg, /^rate-limited: /);
        const tomb = await createGate(deps).check(msg(tombstoneEvent('alice', claimFor('alice').id)));
        assert.match(tomb.msg, /^rate-limited: /);
    });

    it('a device record published only to public relays binds too', async () => {
        const { w, deps } = world({ devices: [] });
        chainFor(w, claimFor('alice'));
        w.publicDevices = [device(1)];
        assert.deepEqual(await createGate(deps).check(msg(listingEvent('alice'))), { action: 'accept' });
    });

    it('a key bound only on public relays is refused while one of them did not answer in full: a revocation may sit there', async () => {
        const { w, deps } = world({ devices: [] });
        chainFor(w, claimFor('alice'));
        w.publicDevices = [device(1)];
        w.publicFails = true;
        assert.match((await createGate(deps).check(msg(listingEvent('alice')))).msg, /^rate-limited: /);
        const tomb = await createGate(deps).check(msg(tombstoneEvent('alice', claimFor('alice').id)));
        assert.match(tomb.msg, /^rate-limited: /);
    });

    it('a revocation read on a public relay retires a key this relay does not bind', async () => {
        const { w, deps } = world({ devices: [] });
        chainFor(w, claimFor('alice'));
        w.publicDevices = [device(1), revocation(1)];
        assert.match((await createGate(deps).check(msg(listingEvent('alice')))).msg, /not bound to the address/);
    });

    it('public relays are not waited on once this relay binds the signer', { timeout: 2000 }, async () => {
        const { w, deps } = world();
        chainFor(w, claimFor('alice'));
        deps.publicDeviceEvents = () => new Promise(() => {});
        assert.deepEqual(await createGate(deps, { ...LIMITS, deadlineMs: 500 }).check(msg(listingEvent('alice'))), { action: 'accept' });
    });
});

/** A legacy v2 bind: its statement names no Nostr key, so any key can carry it. */
const v2bind = (n) =>
    finalizeDeviceEvent({
        deviceSk: sk(n),
        address: ADDR,
        device_id: `dev${n}`,
        device_pk: 'aa'.repeat(32),
        bindingStatement: buildBindingStatement({ address: ADDR, device_pk: 'aa'.repeat(32), device_id: `dev${n}`, created_at: '2026-10-01T00:00:00Z' }),
        bindingSigBase64: `sig:${ADDR}`,
        createdAtUnix: 1_790_000_000,
    });
/** `ev`'s statement and binding_sig, carried by nostr(k), under `tags` (its own by default). */
const carriedBy = (ev, k, tags = ev.tags) => {
    const { nostrSk, nostrPk } = nostr(k);
    return signNostrEvent({ pubkey: nostrPk, kind: 30078, created_at: ev.created_at, content: ev.content, tags }, nostrSk);
};

describe('a v2 bind and the public relays', () => {
    it('a copy filed here first binds nobody when the original sits on a public relay', async () => {
        const { w, deps } = world({ devices: [carriedBy(v2bind(2), 50)] });
        w.publicDevices = [v2bind(2)];
        chainFor(w, claimFor('alice'));
        assert.match((await createGate(deps).check(msg(listingEvent('alice', { n: 50 })))).msg, /not bound to the address/);
        assert.match((await createGate(deps).check(msg(tombstoneEvent('alice', claimFor('alice').id, 50)))).msg, /not bound to the address/);
    });

    it('a key bound here by a v2 bind waits for every public relay: one unanswered refuses as busy', async () => {
        const { w, deps } = world({ devices: [v2bind(2)] });
        chainFor(w, claimFor('alice'));
        assert.deepEqual(await createGate(deps).check(msg(listingEvent('alice', { n: 2 }))), { action: 'accept' });
        w.publicFails = true;
        assert.match((await createGate(deps).check(msg(listingEvent('alice', { n: 2 })))).msg, /^rate-limited: /);
    });

    it('a key bound here by a v3 bind is not held up by the public relays', { timeout: 2000 }, async () => {
        const { w, deps } = world({ devices: [device(1), v2bind(2)] });
        chainFor(w, claimFor('alice'));
        w.publicFails = true;
        assert.deepEqual(await createGate(deps).check(msg(listingEvent('alice'))), { action: 'accept' });
    });

    it('a v3 key revoked here is refused as unbound, with the public relays down too', async () => {
        const { w, deps } = world({ devices: [device(1), revocation(1)] });
        chainFor(w, claimFor('alice'));
        w.publicFails = true;
        assert.match((await createGate(deps).check(msg(listingEvent('alice')))).msg, /not bound to the address/);
    });
});

describe('what a public relay serves under the id of another record', () => {
    // Two lies about one id: other content under it, or its own content with a signature that fails.
    const otherContent = (ev) => ({ ...ev, content: 'junk' });
    const badSignature = (ev) => ({ ...ev, sig: '00'.repeat(64) });

    it('replaces no revocation held here: the revoked key stays unbound', async () => {
        for (const lie of [otherContent, badSignature]) {
            const { w, deps } = world({ devices: [revocation(1)] });
            chainFor(w, claimFor('alice'));
            w.publicDevices = [device(1), lie(revocation(1))];
            assert.match((await createGate(deps).check(msg(listingEvent('alice')))).msg, /not bound to the address/, lie.name);
            assert.match((await createGate(deps).check(msg(tombstoneEvent('alice', claimFor('alice').id)))).msg, /not bound to the address/, lie.name);
        }
    });

    it('replaces no v2 bind held here, so its copy never becomes the only carrier', async () => {
        for (const lie of [otherContent, badSignature]) {
            const { w, deps } = world({ devices: [v2bind(2), carriedBy(v2bind(2), 50)] });
            chainFor(w, claimFor('alice'));
            w.publicDevices = [lie(v2bind(2))];
            assert.match((await createGate(deps).check(msg(listingEvent('alice', { n: 50 })))).msg, /not bound to the address/, lie.name);
            assert.match((await createGate(deps).check(msg(tombstoneEvent('alice', claimFor('alice').id, 50)))).msg, /not bound to the address/, lie.name);
        }
    });

    it('replaces no v2 bind another public relay serves, whichever relay answers first', async () => {
        for (const lie of [otherContent, badSignature]) {
            for (const order of [(a, b) => [a, b], (a, b) => [b, a]]) {
                const { w, deps } = world({ devices: [carriedBy(v2bind(2), 50)] });
                chainFor(w, claimFor('alice'));
                w.publicDevices = order(v2bind(2), lie(v2bind(2)));
                assert.match((await createGate(deps).check(msg(listingEvent('alice', { n: 50 })))).msg, /not bound to the address/, lie.name);
            }
        }
    });

    it('binds nobody with a record filed outside the address\'s slot, though a public relay serves it for that slot', async () => {
        const { w, deps } = world({ devices: [] });
        chainFor(w, claimFor('alice'));
        const elsewhere = device(1).tags.map((t) => (t[0] === 'd' ? ['d', `oc-lock:device:${ADDR}:dev1`] : t));
        w.publicDevices = [carriedBy(device(1), 1, elsewhere)];
        assert.match((await createGate(deps).check(msg(listingEvent('alice')))).msg, /not bound to the address/);
        // Filed in the slot, the same bind binds.
        w.publicDevices = [device(1)];
        assert.deepEqual(await createGate(deps).check(msg(listingEvent('alice'))), { action: 'accept' });
    });
});

describe('a device record', () => {
    const write = (ev) => createGate(world().deps).check({ ...msg(ev), event: ev });

    it('is admitted with a BIP-322 signature by the address its slot names, a revocation too', async () => {
        assert.deepEqual(await write(device(3)), { action: 'accept' });
        assert.deepEqual(await write(revocation(3)), { action: 'accept' });
    });

    it('is refused without one', async () => {
        const other = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';
        // Signed for another address, filed under ADDR.
        const misfiled = device(4, other);
        const { nostrSk } = nostr(4);
        const moved = signNostrEvent(
            { pubkey: misfiled.pubkey, kind: 30078, created_at: misfiled.created_at, content: misfiled.content, tags: misfiled.tags.map((t) => (t[0] === 'd' ? ['d', `oc-lock:device:${ADDR}`] : t)) },
            nostrSk
        );
        assert.match((await write(moved)).msg, /^invalid: a device record needs a BIP-322 signature/);
        // A wrong signature.
        const forged = signNostrEvent(
            { pubkey: misfiled.pubkey, kind: 30078, created_at: 1_790_000_000, content: device(4).content, tags: device(4).tags.map((t) => (t[0] === 'binding_sig' ? ['binding_sig', 'sig:nobody'] : t)) },
            nostrSk
        );
        assert.match((await write(forged)).msg, /^invalid: a device record needs a BIP-322 signature/);
    });

    it('is refused with a second d tag, which would file it in another address\'s slot too', async () => {
        const other = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';
        const own = device(3);
        const twice = signNostrEvent(
            { pubkey: own.pubkey, kind: 30078, created_at: own.created_at, content: own.content, tags: [...own.tags, ['d', `oc-lock:device:${other}`]] },
            nostr(3).nostrSk
        );
        assert.deepEqual(await write(own), { action: 'accept' });
        assert.match((await write(twice)).msg, /^invalid: a record carries exactly one d tag/);
    });

    it('a revocation signed for one address is refused under another address\'s slot', async () => {
        const other = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';
        const { nostrSk, nostrPk } = nostr(6);
        const crossed = signNostrEvent(
            {
                pubkey: nostrPk,
                kind: 30078,
                created_at: 1_790_000_100,
                content: buildRevocationStatement({ address: other, device_id: 'dev6', revoked_at: '2026-10-02T00:00:00Z' }),
                tags: [
                    ['d', `oc-lock:device:${ADDR}`],
                    ['binding_sig', `sig:${other}`],
                ],
            },
            nostrSk
        );
        assert.match((await write(crossed)).msg, /^invalid: a device record needs a BIP-322 signature/);
    });

    /** OC Lock's unsigned advice, as oc-lock-web's DeviceManager builds it when no wallet signs. */
    const advice = (n, statement = buildRevocationStatement({ address: ADDR, device_id: `dev${n}`, revoked_at: '2026-10-03T00:00:00Z' })) =>
        finalizeDeviceEvent({
            deviceSk: sk(n),
            address: ADDR,
            device_id: `dev${n}`,
            device_pk: 'revoked',
            bindingStatement: statement,
            bindingSigBase64: '',
            createdAtUnix: 1_790_000_200,
        });

    it('a key that holds a record in the slot may retract it with an unsigned revocation', async () => {
        const { w, deps } = world({ devices: [device(1)] });
        assert.deepEqual(await createGate(deps).check(msg(advice(1))), { action: 'accept' });
        // A key with no record there cannot.
        assert.match((await createGate(deps).check(msg(advice(7)))).msg, /^invalid: a device record needs a BIP-322 signature/);
        // Its own read without an answer is busy, never an admission.
        w.ownFails = true;
        assert.match((await createGate(deps).check(msg(advice(1)))).msg, /^rate-limited: /);
    });

    const revokes = (deviceId, address = ADDR) =>
        buildRevocationStatement({ address, device_id: deviceId, revoked_at: '2026-10-03T00:00:00Z' });

    it('an unsigned revocation retracts only the signer\'s own device; one naming a sibling is refused', async () => {
        const { deps } = world({ devices: [device(1), device(2)] });
        assert.match((await createGate(deps).check(msg(advice(1, revokes('dev2'))))).msg, /^invalid: a device record needs a BIP-322 signature/);
        assert.deepEqual(await createGate(deps).check(msg(advice(1, revokes('dev1')))), { action: 'accept' });
    });

    it('counts only the signer\'s own record, though the read returns the whole slot', async () => {
        const { w, deps } = world({ devices: [device(2)] });
        deps.deviceEventsBy = async () => w.devices;
        assert.match((await createGate(deps).check(msg(advice(7, revokes('dev2'))))).msg, /^invalid: a device record needs a BIP-322 signature/);
    });

    it('reads the address and device_id lines whole, and the first of each, as lock-device does', async () => {
        const OTHER = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';
        const head = `oc-lock:device-revoke:${BINDING_VERSION}`;
        const stmt = (...lines) => [head, ...lines, 'revoked_at: 2026-10-03T00:00:00Z'].join('\n') + '\n';
        // Key 8's record in this slot binds no device of this address; key 9's names none.
        const misfiled = { ...device(8, OTHER), tags: [['d', `oc-lock:device:${ADDR}`]] };
        const { nostrSk, nostrPk } = nostr(9);
        const unnamed = signNostrEvent(
            { pubkey: nostrPk, kind: 30078, created_at: 1_790_000_000, content: `oc-lock:device-bind:${BINDING_VERSION}\naddress: ${ADDR}\n`, tags: [['d', `oc-lock:device:${ADDR}`]] },
            nostrSk
        );
        const { deps } = world({ devices: [device(1), device(2), misfiled, unnamed] });
        for (const [n, content] of [
            [1, stmt(`address: ${ADDR}x`, 'device_id: dev1')],
            [1, stmt(`address: ${OTHER}`, `address: ${ADDR}`, 'device_id: dev1')],
            [1, stmt(`address: ${ADDR}`, 'device_id: dev2', 'device_id: dev1')],
            [8, stmt(`address: ${ADDR}`, 'device_id: dev8')],
            [9, stmt(`address: ${ADDR}`)],
        ]) {
            assert.match((await createGate(deps).check(msg(advice(n, content)))).msg, /^invalid: a device record needs a BIP-322 signature/, content);
        }
    });

    it('anything else unsigned from a key in the slot, a re-bind included, goes through the BIP-322 path', async () => {
        const { deps } = world({ devices: [device(1)] });
        const rebind = buildBindingStatement({
            address: ADDR,
            device_pk: 'bb'.repeat(32),
            device_id: 'dev1',
            created_at: '2026-10-03T00:00:00Z',
            nostr_pk: nostr(1).nostrPk,
        });
        const unsignedRebind = finalizeDeviceEvent({
            deviceSk: sk(1),
            address: ADDR,
            device_id: 'dev1',
            device_pk: 'bb'.repeat(32),
            bindingStatement: rebind,
            bindingSigBase64: '',
            createdAtUnix: 1_790_000_200,
        });
        assert.match((await createGate(deps).check(msg(unsignedRebind))).msg, /^invalid: a device record needs a BIP-322 signature/);
        // An unsigned revocation for another address, filed here, is not this slot's.
        const elsewhere = advice(1, buildRevocationStatement({ address: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', device_id: 'dev1', revoked_at: '2026-10-03T00:00:00Z' }));
        assert.match((await createGate(deps).check(msg(elsewhere))).msg, /^invalid: a device record needs a BIP-322 signature/);
    });

    it('costs no chain read and one read of its slot, and is limited per source apart from listings', async () => {
        const { w, deps } = world();
        const gate = createGate(deps);
        for (let i = 0; i < LIMITS.perIp; i++) assert.equal((await gate.check(msg(device(5)))).action, 'accept');
        assert.match((await gate.check(msg(device(5)))).msg, /^rate-limited: too many device records/);
        // The refusal over the limit reads nothing.
        assert.deepEqual(w.reads, { tip: 0, header: 0, coin: 0, device: LIMITS.perIp, stored: 0 });
        chainFor(w, claimFor('alice'));
        assert.equal((await gate.check(msg(listingEvent('alice')))).action, 'accept');
    });
});

describe('limits', () => {
    it('six 30114 writes a minute per IP; other sources count apart', async () => {
        const { w, deps } = world();
        chainFor(w, claimFor('alice'));
        const gate = createGate(deps);
        const ev = listingEvent('alice');
        for (let i = 0; i < 6; i++) assert.equal((await gate.check(msg(ev))).action, 'accept');
        assert.match((await gate.check(msg(ev))).msg, /^rate-limited: too many directory writes/);
        assert.equal((await gate.check(msg(ev, '203.0.113.2'))).action, 'accept');
        assert.equal((await gate.check(msg(ev, 'wss://elsewhere', 'Sync'))).action, 'accept');
        w.t += 60_000;
        assert.equal((await gate.check(msg(ev))).action, 'accept');
    });

    it('a spent chain budget refuses, and cached facts cost nothing', async () => {
        const { w, deps } = world();
        chainFor(w, claimFor('alice'));
        const gate = createGate(deps, { ...LIMITS, chainReads: 3, perIp: 100 });
        assert.equal((await gate.check(msg(listingEvent('alice')))).action, 'accept');
        assert.equal((await gate.check(msg(listingEvent('alice')))).action, 'accept');
        assert.deepEqual([w.reads.tip, w.reads.header, w.reads.coin], [1, 1, 1]);
        const other = claimFor('bob', { outpoint: `${'cd'.repeat(32)}:1`, height: ANCHOR - 1 });
        w.coins.set(other.claim.outpoint, { confirmedAt: ANCHOR - 200, value: 546, paysTo: ADDR, spendHeight: null });
        assert.match((await gate.check(msg(listingEvent('bob', { claim: other })))).msg, /^rate-limited: /);
    });

    it('one source spends at most its share of the chain budget', async () => {
        const { w, deps } = world();
        const gate = createGate(deps, { ...LIMITS, chainReadsPerSource: 3, perIp: 100 });
        const fresh = (i) => {
            const cl = claimFor('han' + i, { outpoint: `${String(i).padStart(2, '0').repeat(32)}:0`, height: ANCHOR - i });
            chainFor(w, cl);
            return listingEvent('han' + i, { claim: cl });
        };
        // 3 reads (tip, header, coin) spend the first source's share; its next claim needs more.
        assert.deepEqual(await gate.check(msg(fresh(1), '203.0.113.7')), { action: 'accept' });
        assert.match((await gate.check(msg(fresh(2), '203.0.113.7'))).msg, /^rate-limited: /);
        assert.equal((await gate.check(msg(fresh(3), '203.0.113.8'))).action, 'accept');
    });

    it('one live claim per coin; a tombstoned one frees it', async () => {
        const { w, deps } = world();
        const a = claimFor('alice');
        chainFor(w, a);
        const gate = createGate(deps);
        const first = listingEvent('alice', { claim: a });
        assert.equal((await gate.check(msg(first))).action, 'accept');
        w.stored.push(first);
        const b = claimFor('alice2', { height: ANCHOR - 1 });
        w.roots.set(b.height, b.id);
        const second = listingEvent('alice2', { claim: b });
        assert.match((await gate.check(msg(second))).msg, /^blocked: this coin already backs another live claim/);
        w.stored.push(tombstoneEvent('alice', a.id));
        assert.equal((await gate.check(msg(second))).action, 'accept');
    });
});

describe('a tombstone', () => {
    it('is admitted when a bound key signs it and it ends a claim this relay holds', async () => {
        const { w, deps } = world();
        const a = claimFor('alice');
        w.stored.push(listingEvent('alice', { claim: a }));
        const gate = createGate(deps);
        assert.deepEqual(await gate.check(msg(tombstoneEvent('alice', a.id))), { action: 'accept' });
        assert.match((await gate.check(msg(tombstoneEvent('alice', sha('other'))))).msg, /must end a claim this relay holds/);
        assert.match((await gate.check(msg(tombstoneEvent('alice', a.id, 3)))).msg, /not bound to the address/);
        assert.equal(w.reads.tip + w.reads.coin + w.reads.header, 0);
    });
});

describe('copies of one signed statement', () => {
    /** A Nostr key per index, past the 255 that sk(n) can tell apart. */
    const carrier = (i) => {
        const b = new Uint8Array(32);
        b[0] = 7;
        b[30] = i >> 8;
        b[31] = i & 0xff;
        return deriveNostrKey(b);
    };
    /** `ev`'s signed statement and binding_sig, filed under carrier `i`. */
    const copy = (ev, i, createdAt = ev.created_at) => {
        const { nostrSk, nostrPk } = carrier(i);
        return signNostrEvent({ pubkey: nostrPk, kind: 30078, created_at: createdAt, content: ev.content, tags: ev.tags }, nostrSk);
    };
    /** Each event checked in turn and, once admitted, kept in the slot under its key, as strfry keeps 30078. */
    async function file(w, deps, events) {
        const gate = createGate(deps, { ...LIMITS, perIp: Infinity });
        const answers = [];
        for (const ev of events) {
            const answer = await gate.check(msg(ev));
            if (answer.action === 'accept') w.devices = [...w.devices.filter((e) => e.pubkey !== ev.pubkey), ev];
            answers.push(answer);
        }
        return answers;
    }
    const carrying = (w, ev) => w.devices.filter((e) => e.content === ev.content).length;

    it('a plant of 501 copies of a revocation is refused from the fourth, so the slot holds three', async () => {
        const { w, deps } = world({ devices: [device(1)] });
        const original = revocation(1);
        const plant = Array.from({ length: 500 }, (_, i) => copy(original, i, 1_790_000_300));
        const answers = await file(w, deps, [original, ...plant]);
        assert.deepEqual(answers.slice(0, 3), Array(3).fill({ action: 'accept' }));
        assert.equal(answers.filter((a) => a.action === 'accept').length, 3);
        assert.match(answers[3].msg, /^duplicate: 3 records here already carry this statement/);
        assert.equal(carrying(w, original), 3);
    });

    it("an honest second signing and a retry are admitted: chat's or lock-web's remote revocation, signed twice in one dialog, then resent", async () => {
        const { w, deps } = world({ devices: [device(1)] });
        const first = copy(revocation(1), 600);
        const second = copy(revocation(1), 601);
        // A retry sends the same signed record again; vault's, with a bind dated ahead, a third
        // carrier. With three held, a carrier's own resend replaces its record and is admitted.
        const answers = await file(w, deps, [first, second, second, copy(revocation(1), 602), first]);
        assert.deepEqual(answers, Array(5).fill({ action: 'accept' }));
        assert.equal(carrying(w, first), 3);
    });

    it('counts by the signed statement, not its signature: a taproot wallet signs one statement differently each time', async () => {
        const { w, deps } = world({ devices: [device(1)] });
        deps.verifyBip322 = ({ address, message, signature }) =>
            (signature === `sig:${address}` || signature === `sig2:${address}`) && message.includes(`address: ${address}`);
        const resigned = (i) => {
            const { nostrSk, nostrPk } = carrier(i);
            const ev = revocation(1);
            const tags = ev.tags.map((t) => (t[0] === 'binding_sig' ? ['binding_sig', `sig2:${ADDR}`] : t));
            return signNostrEvent({ pubkey: nostrPk, kind: 30078, created_at: ev.created_at, content: ev.content, tags }, nostrSk);
        };
        const answers = await file(w, deps, [revocation(1), copy(revocation(1), 700), resigned(701), resigned(702)]);
        assert.deepEqual(answers.slice(0, 3), Array(3).fill({ action: 'accept' }));
        assert.match(answers[3].msg, /^duplicate: /);
    });

    /** A legacy v2 bind: its statement names no Nostr key, so any key can carry it. */
    const v2bind = (n) =>
        finalizeDeviceEvent({
            deviceSk: sk(n),
            address: ADDR,
            device_id: `dev${n}`,
            device_pk: 'aa'.repeat(32),
            bindingStatement: buildBindingStatement({ address: ADDR, device_pk: 'aa'.repeat(32), device_id: `dev${n}`, created_at: '2026-10-01T00:00:00Z' }),
            bindingSigBase64: `sig:${ADDR}`,
            createdAtUnix: 1_790_000_000,
        });
    const listingBy = (pk, n) => {
        const ev = listingEvent('alice', { n });
        assert.equal(ev.pubkey, pk);
        return ev;
    };

    it('a v2 bind copied in first never leaves the copier as its only carrier: nobody is authorized', async () => {
        // The owner alone binds its key (before the v2 sunset).
        {
            const { w, deps } = world({ devices: [] });
            chainFor(w, claimFor('alice'));
            await file(w, deps, [v2bind(2)]);
            assert.deepEqual(await createGate(deps).check(msg(listingBy(nostr(2).nostrPk, 2))), { action: 'accept' });
        }
        // One copy first, the owner second: both held, two carriers, nobody authorized.
        {
            const { w, deps } = world({ devices: [] });
            chainFor(w, claimFor('alice'));
            const own = v2bind(2);
            const { nostrSk, nostrPk } = nostr(50);
            const planted = signNostrEvent({ pubkey: nostrPk, kind: 30078, created_at: own.created_at, content: own.content, tags: own.tags }, nostrSk);
            assert.deepEqual(await file(w, deps, [planted, own]), Array(2).fill({ action: 'accept' }));
            assert.match((await createGate(deps).check(msg(listingBy(nostr(2).nostrPk, 2)))).msg, /not bound to the address/);
            assert.match((await createGate(deps).check(msg(listingBy(nostr(50).nostrPk, 50)))).msg, /not bound to the address/);
        }
        // Three copies first: the owner's own record is refused, and still nobody is authorized.
        {
            const { w, deps } = world({ devices: [] });
            chainFor(w, claimFor('alice'));
            const own = v2bind(2);
            const planted = [50, 51, 52].map((k) => {
                const { nostrSk, nostrPk } = nostr(k);
                return signNostrEvent({ pubkey: nostrPk, kind: 30078, created_at: own.created_at, content: own.content, tags: own.tags }, nostrSk);
            });
            const answers = await file(w, deps, [...planted, own]);
            assert.deepEqual(answers.slice(0, 3), Array(3).fill({ action: 'accept' }));
            assert.match(answers[3].msg, /^duplicate: /);
            for (const k of [2, 50, 51, 52]) {
                assert.match((await createGate(deps).check(msg(listingBy(nostr(k).nostrPk, k)))).msg, /not bound to the address/, `key ${k}`);
            }
        }
    });

    it('a slot read without an answer refuses the record as busy, never admits it', async () => {
        const { w, deps } = world({ devices: [device(1)] });
        w.deviceFails = true;
        assert.match((await createGate(deps).check(msg(device(3)))).msg, /^rate-limited: /);
        assert.match((await createGate(deps).check(msg(revocation(1)))).msg, /^rate-limited: /);
    });
});
