// The kind-30114 write gate against signed records and a fake chain: what it
// admits, what it refuses, and that every unanswered read refuses.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';

import { channelClaimId, channelDirectoryDtag, channelId, claimId, directoryDtag } from '@orangecheck/lock-core/directory';
import {
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

describe('a device record', () => {
    const write = (ev) => createGate(world().deps).check({ ...msg(ev), event: ev });

    it('is admitted with a BIP-322 signature by the address its slot names, a revocation too', async () => {
        assert.deepEqual(await write(device(3)), { action: 'accept' });
        assert.deepEqual(await write(revocation(3)), { action: 'accept' });
    });

    it('is refused without one, so no one else can fill an address slot', async () => {
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

    it('costs no chain or relay read, and is limited per source apart from listings', async () => {
        const { w, deps } = world();
        const gate = createGate(deps);
        for (let i = 0; i < LIMITS.perIp; i++) assert.equal((await gate.check(msg(device(5)))).action, 'accept');
        assert.match((await gate.check(msg(device(5)))).msg, /^rate-limited: too many device records/);
        assert.deepEqual(w.reads, { tip: 0, header: 0, coin: 0, device: 0, stored: 0 });
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
