// The directory relay's write gate for kind 30114 (oc-chat-protocol SPEC §8.2.6).
// A listing is admitted only if it passes §8.2.2 (1)–(4); a tombstone only if it
// is signed by a key bound to its address and its `ends` names a claim this relay
// holds. Cheapest checks first. A read that does not answer, or a spent budget,
// refuses with "rate-limited:", never admits. The rule itself is lock-core's.
// A kind-30078 device record (oc-lock:device:<address>) is admitted only with a
// BIP-322 signature by that address, or as a revocation of its own device by a key
// that already holds a record there. The signature covers the statement, not the
// Nostr event that carries it, so anyone can file copies of an address's
// revocations and v2 binds in its slot under keys of their own; at most three
// records carry one statement here.

import {
    channelDirectoryDtag,
    directoryAnchor,
    directoryDtag,
    parseChannelDirectoryContent,
    parseDirectoryContent,
    repointId,
    resolveDirectory,
} from '@orangecheck/lock-core/directory';
import { BINDING_VERSION, boundNostrKeys, verifyDeviceRecords, verifyNostrEvent } from '@orangecheck/lock-device';
import { base64Decode, bitcoinAnchors, hexDecode, parseProof } from '@orangecheck/stamp-ots';

export const LIMITS = {
    /** 30114 writes per source IP per minute. */
    perIp: 6,
    /** 30114 writes per minute from one non-IP source (Sync, Stream, Import). */
    perSource: 30,
    /** Chain reads (tip, headers, coins) per minute, all writers together. */
    chainReads: 120,
    /** Of those, what one source may spend in a minute. */
    chainReadsPerSource: 30,
    /** Answer within this, or refuse: strfry waits on every check. */
    deadlineMs: 2500,
    /** Records in an address's slot that may carry one signed statement. */
    copiesPerStatement: 3,
};

const DEVICE_PREFIX = 'oc-lock:device:';

const NAMESPACES = [
    { prefix: 'oc-lock-chat-dir:', dtag: directoryDtag, parse: parseDirectoryContent },
    { prefix: 'oc-lock-chat-chdir:', dtag: channelDirectoryDtag, parse: parseChannelDirectoryContent },
];

const TIP_TTL_MS = 60_000;
const COIN_TTL_MS = 60_000;
const CACHE_MAX = 4096;
const DEEP = 6;

const reject = (msg) => ({ action: 'reject', msg });
const busy = (why) => reject(`rate-limited: ${why}, try again`);
const dTag = (ev) => (Array.isArray(ev?.tags) ? ev.tags.find((t) => Array.isArray(t) && t[0] === 'd')?.[1] : undefined);
const dTagCount = (ev) => (Array.isArray(ev?.tags) ? ev.tags.filter((t) => Array.isArray(t) && t[0] === 'd').length : 0);

class NoAnswer extends Error {}

const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * A proof's anchor as directoryAnchor reads it, or 'padded' when the proof also carries a Bitcoin
 * attestation its block's header does not confirm. Clients order their header reads by the lowest
 * attestation a proof claims, so one naming another block's root would let junk be read first.
 */
async function anchorOf(proofB64, idHex, headers) {
    // Each height is read once, by lock-core's walk and by the check after it alike.
    const read = new Map();
    const once = { getHeaderAt: (height) => (read.has(height) ? read : read.set(height, headers.getHeaderAt(height))).get(height) };
    const anchor = await directoryAnchor(proofB64, idHex, once);
    if (typeof anchor !== 'number') return anchor;
    for (const a of bitcoinAnchors(parseProof(base64Decode(proofB64), hexDecode(idHex)))) {
        let h;
        try {
            h = await once.getHeaderAt(a.blockHeight);
        } catch {
            throw new NoAnswer();
        }
        if (!(h instanceof Uint8Array) || h.byteLength !== 80 || !sameBytes(h.subarray(36, 68), a.merkleRoot)) return 'padded';
    }
    return anchor;
}

function remember(map, key, value) {
    if (map.size >= CACHE_MAX) map.delete(map.keys().next().value);
    map.set(key, value);
}

/** Per-key counts in one-minute windows. */
function windows(now) {
    const seen = new Map();
    return (key, limit) => {
        const t = now();
        const w = seen.get(key);
        if (!w || t - w.start >= 60_000) {
            if (seen.size >= CACHE_MAX) for (const [k, v] of seen) if (t - v.start >= 60_000) seen.delete(k);
            seen.set(key, { start: t, n: 1 });
            return true;
        }
        if (w.n >= limit) return false;
        w.n++;
        return true;
    };
}

/**
 * deps:
 *   tip(): Promise<number>, throws when the chain source does not answer
 *   headers: { getHeaderAt(height): Promise<Uint8Array | null> }, throws likewise
 *   coin(outpoint): Promise<CoinFacts | 'no-answer'>
 *   deviceEvents(address): Promise<NostrEvent[] | 'no-answer'>, kind-30078 records on this relay
 *   deviceEventsBy(address, pubkey): the same, signed by `pubkey` only (a few records, never flooded out)
 *   publicDeviceEvents(address): Promise<{ events: NostrEvent[]; allAnswered: boolean }>, from public relays
 *   stored(dtag): Promise<NostrEvent[] | 'no-answer'>, kind-30114 events on this relay at a d tag
 *   allStored(): Promise<NostrEvent[] | 'no-answer'>, every kind-30114 event on this relay
 *   verifyBip322({ address, message, signature }): boolean | Promise<boolean>
 *   now(): number (ms)
 */
export function createGate(deps, limits = LIMITS) {
    const take = windows(deps.now);
    const takeChain = windows(deps.now);
    let spent = { start: -Infinity, n: 0 };
    // A chain read is charged to the global budget and to the source that caused it.
    const budget = (source) => {
        const t = deps.now();
        if (t - spent.start >= 60_000) spent = { start: t, n: 0 };
        if (spent.n >= limits.chainReads) return false;
        if (!takeChain(source, limits.chainReadsPerSource)) return false;
        spent.n++;
        return true;
    };

    let tipCache = null;
    const tip = async (source) => {
        if (tipCache && deps.now() - tipCache.at < TIP_TTL_MS) return tipCache.height;
        if (!budget(source)) throw new NoAnswer();
        const height = await deps.tip();
        if (!Number.isSafeInteger(height) || height <= 0) throw new NoAnswer();
        tipCache = { height, at: deps.now() };
        return height;
    };

    const headerCache = new Map();
    const headersFor = (source) => ({
        async getHeaderAt(height) {
            if (headerCache.has(height)) return headerCache.get(height);
            if (!budget(source)) throw new NoAnswer();
            const h = await deps.headers.getHeaderAt(height);
            // Only a header buried 6 deep is kept; anything nearer the tip can still change.
            if (h && tipCache && height <= tipCache.height - DEEP) remember(headerCache, height, h);
            return h;
        },
    });

    const coinCache = new Map();
    const coin = async (outpoint, source) => {
        const c = coinCache.get(outpoint);
        if (c && (c.final || deps.now() - c.at < COIN_TTL_MS)) return c.facts;
        if (!budget(source)) return 'no-answer';
        const facts = await deps.coin(outpoint);
        if (facts === 'no-answer') return facts;
        // A spend buried 6 deep does not change; the rest is kept a minute.
        const final = facts.spendHeight !== null && tipCache !== null && facts.spendHeight <= tipCache.height - DEEP;
        remember(coinCache, outpoint, { facts, at: deps.now(), final });
        return facts;
    };

    // The keys bound to `address`. The signer's own records are read apart, so records others
    // pile into the slot cannot hide them; a revocation may be signed by any key, so it is read
    // from the full slot. Bound counts only once the full slot on this relay answered. Public
    // relays are read when this relay does not bind the signer by a v3 bind: a revocation held
    // only there is not seen while a v3 bind here binds it. A v2 bind names no key, and binds its
    // carrier only while no other key carries that device, so a copy filed here first would bind
    // its copier until the original, on a public relay, is read beside it. A key the public
    // relays bind, or a v2 bind here, counts only once every one of them answered in full.
    const boundKeys = async (address, signer) => {
        const pubRead = deps.publicDeviceEvents(address).catch(() => ({ events: [], allAnswered: false }));
        const [all, own] = await Promise.all([deps.deviceEvents(address), deps.deviceEventsBy(address, signer)]);
        if (all === 'no-answer') return 'no-answer';
        const now = new Date(deps.now());
        // A public relay can serve anything under the id of a record held here or on another relay,
        // so only an event whose id and signature check out, filed in this address's slot, may stand
        // for its id; the first such copy does, and one that fails replaces nothing.
        const verifiedFrom = async (events) => {
            const byId = new Map();
            for (const e of events) {
                if (!e || typeof e.id !== 'string' || byId.has(e.id)) continue;
                if (dTag(e) === DEVICE_PREFIX + address && verifyNostrEvent(e)) byId.set(e.id, e);
            }
            return verifyDeviceRecords([...byId.values()], address, { verifyBip322: deps.verifyBip322 });
        };
        const local = [...all, ...(own === 'no-answer' ? [] : own)];
        const here = await verifiedFrom(local);
        // A signer with a v3 bind here is decided here, its revocations held here included.
        const v3Binds = here.filter((r) => !r.revoked && r.bindingVersion === 'v3');
        if (boundNostrKeys(v3Binds, { now }).includes(signer)) return boundNostrKeys(here, { now });
        const pub = await pubRead;
        if (own === 'no-answer' || !pub.allAnswered) return 'no-answer';
        return boundNostrKeys(await verifiedFrom([...local, ...pub.events]), { now });
    };

    // One live claim per current coin per namespace (§8.2.6): coin -> the claim it backs.
    let coinIndex = null;
    const index = async () => {
        if (coinIndex) return coinIndex;
        const all = await deps.allStored();
        if (all === 'no-answer') throw new NoAnswer();
        const built = new Map();
        for (const ev of all) {
            const parsed = parseStored(ev);
            if (!parsed || parsed.rec.kind !== 'listing') continue;
            const { rec, ns, d } = parsed;
            const last = rec.claim.repoints.length ? rec.claim.repoints[rec.claim.repoints.length - 1].outpoint : rec.claim.outpoint;
            const key = ns.prefix + '\n' + last;
            if (!built.has(key)) built.set(key, { claimId: rec.claimId, address: rec.address, d });
        }
        coinIndex = built;
        return coinIndex;
    };
    const stillLive = async (prior) => {
        const held = await deps.stored(prior.d);
        if (held === 'no-answer') throw new NoAnswer();
        const recs = held.map(parseStored).filter((p) => p && p.rec.address === prior.address).map((p) => p.rec);
        const carried = recs.some((r) => r.kind === 'listing' && r.claimId === prior.claimId);
        const ended = recs.some((r) => r.kind === 'tombstone' && r.ends === prior.claimId);
        return carried && !ended;
    };

    async function listing(ev, rec, d, ns, source) {
        const height = await tip(source);
        const headers = headersFor(source);
        const anchor = await anchorOf(rec.claim.ots, rec.claimId, headers);
        if (anchor === 'padded') return reject('invalid: the claim\'s proof carries an attestation its block does not confirm (OC Chat §8.2.1)');
        if (anchor === null) return reject('invalid: the claim is not anchored (OC Chat §8.2.1)');
        if (typeof anchor !== 'number') throw new NoAnswer();
        if (height - anchor + 1 < DEEP) return reject('invalid: the claim needs 6 confirmations on its anchor (OC Chat §8.2.1)');
        const repoints = [];
        for (const r of rec.claim.repoints) {
            const id = repointId({ claim: rec.claimId, prev: r.prev, outpoint: r.outpoint, nonce: r.nonce });
            const at = await anchorOf(r.ots, id, headers);
            if (at === 'padded') return reject('invalid: a re-point\'s proof carries an attestation its block does not confirm (OC Chat §8.2.1)');
            repoints.push({ repointId: id, prev: r.prev, outpoint: r.outpoint, anchor: at });
        }
        let keys = null;
        const reader = {
            boundKeys: async (address) => (keys = await boundKeys(address, ev.pubkey)),
            coin: (outpoint) => coin(outpoint, source),
        };
        const record = {
            kind: 'listing',
            address: rec.address,
            key: ev.pubkey,
            createdAt: rec.createdAt,
            claimId: rec.claimId,
            outpoint: rec.claim.outpoint,
            anchor,
            repoints,
            source: 'directory',
        };
        const out = await resolveDirectory([record], height, reader);
        if (out.result === 'E_DIR_UNRESOLVED') throw new NoAnswer();
        if (out.result !== 'holds') {
            return Array.isArray(keys) && !keys.includes(ev.pubkey)
                ? reject('invalid: the signing key is not bound to the address by a device record on this relay (OC Lock §3)')
                : reject("invalid: the claim's coin does not hold it (OC Chat §8.2.2 (3))");
        }
        const idx = await index();
        const key = ns.prefix + '\n' + out.coin;
        const prior = idx.get(key);
        if (prior && prior.claimId !== rec.claimId && (await stillLive(prior))) {
            return reject('blocked: this coin already backs another live claim here (OC Chat §8.2.6)');
        }
        idx.set(key, { claimId: rec.claimId, address: rec.address, d });
        return { action: 'accept' };
    }

    async function tombstone(ev, rec, d) {
        const keys = await boundKeys(rec.address, ev.pubkey);
        if (keys === 'no-answer') throw new NoAnswer();
        if (!keys.includes(ev.pubkey)) {
            return reject('invalid: the signing key is not bound to the address by a device record on this relay (OC Lock §3)');
        }
        const held = await deps.stored(d);
        if (held === 'no-answer') throw new NoAnswer();
        const known = held
            .map(parseStored)
            .some((p) => p && p.rec.kind === 'listing' && p.rec.address === rec.address && p.rec.claimId === rec.ends);
        if (!known) return reject('invalid: a tombstone must end a claim this relay holds (OC Chat §8.2.6)');
        return { action: 'accept' };
    }

    // A device record counts only with a BIP-322 signature by the address its slot names (OC Lock §3).
    async function deviceRecord(ev, d, source, ip) {
        if (!take(`dev:${source}`, ip ? limits.perIp : limits.perSource)) {
            return reject('rate-limited: too many device records from here, try again in a minute');
        }
        const address = d.slice(DEVICE_PREFIX.length);
        const verified = await verifyDeviceRecords([ev], address, { verifyBip322: deps.verifyBip322 });
        if (verified.length === 1) {
            // Copies under other keys are capped, so they cannot crowd the slot past its paged
            // read. Three keep every family writer (a second signing, a retry), and two or more
            // carriers of a v2 bind authorize no one, so a refusal never leaves a copier as its
            // only carrier. A record under this event's own key is the one it replaces.
            const slot = await deps.deviceEvents(address);
            if (slot === 'no-answer') return busy('a relay read did not answer');
            const carried = slot.filter((e) => e?.content === ev.content && e.pubkey !== ev.pubkey).length;
            if (carried >= limits.copiesPerStatement) {
                return reject(`duplicate: ${limits.copiesPerStatement} records here already carry this statement`);
            }
            return { action: 'accept' };
        }
        // A key that already holds a record in the slot may replace it with a revocation of its
        // own device, signed or not (OC Lock's unsigned advice). That replaces its record; it adds none.
        const revoked = statementOf(ev.content);
        if (verifyNostrEvent(ev) && revoked.header === REVOKE_HEADER && revoked.address === address && revoked.deviceId) {
            const own = await deps.deviceEventsBy(address, ev.pubkey);
            if (own === 'no-answer') return busy('a relay read did not answer');
            const ownDevice = (e) => {
                const st = statementOf(e?.content);
                return e?.pubkey === ev.pubkey && st.address === address && st.deviceId === revoked.deviceId;
            };
            if (own.some(ownDevice)) return { action: 'accept' };
        }
        return reject('invalid: a device record needs a BIP-322 signature by the address its d tag names (OC Lock §3)');
    }

    async function decide(msg) {
        const ev = msg?.event;
        // Without the network: the record's shape, its d tag, its signer.
        // Every check reads the first d, and strfry matches #d against every d value, so a
        // second d would put the record in another slot unchecked.
        if (dTagCount(ev) > 1) return reject('invalid: a record carries exactly one d tag');
        const d = dTag(ev);
        if (ev?.kind === 30078 && typeof d === 'string' && d.startsWith(DEVICE_PREFIX)) {
            const ip = msg.sourceType === 'IP4' || msg.sourceType === 'IP6';
            return deviceRecord(ev, d, ip ? `ip:${msg.sourceInfo}` : `src:${msg.sourceType}:${msg.sourceInfo ?? ''}`, ip);
        }
        const ns = typeof d === 'string' ? NAMESPACES.find((n) => d.startsWith(n.prefix)) : undefined;
        if (!ns || ev.kind !== 30114) return reject('invalid: not an OC Chat directory record');
        let content;
        try {
            content = JSON.parse(ev.content);
        } catch {
            return reject('invalid: content is not JSON');
        }
        if (content && typeof content === 'object' && content.v === 1) {
            return reject('blocked: v1 directory records are not accepted here; publish v2 (OC Chat 0.4 §8.2.1)');
        }
        const handle = typeof content?.handle === 'string' ? content.handle : '';
        const rec = ns.parse(content, handle);
        if (!rec) return reject('invalid: not a v2 directory record (OC Chat §8.2.1, §8.2.5 (1))');
        if (ns.dtag(handle) !== d) return reject("invalid: the d tag is not this handle's (OC Chat §8.2.1)");
        if (rec.kind === 'listing' && ev.pubkey !== rec.inboxPubkey) {
            return reject('invalid: a listing is signed by its inbox key (OC Chat §8.2.2 (1))');
        }
        const ip = msg.sourceType === 'IP4' || msg.sourceType === 'IP6';
        const source = ip ? `ip:${msg.sourceInfo}` : `src:${msg.sourceType}:${msg.sourceInfo ?? ''}`;
        if (!take(source, ip ? limits.perIp : limits.perSource)) {
            return reject('rate-limited: too many directory writes from here, try again in a minute');
        }
        try {
            return rec.kind === 'tombstone' ? await tombstone(ev, rec, d) : await listing(ev, rec, d, ns, source);
        } catch (err) {
            if (err instanceof NoAnswer) return busy('a chain or relay read did not answer');
            throw err;
        }
    }

    return {
        async check(msg) {
            let timer;
            const late = new Promise((resolve) => {
                timer = setTimeout(() => resolve(busy('the directory check took too long')), limits.deadlineMs);
            });
            try {
                return await Promise.race([decide(msg).catch(() => busy('the directory check failed')), late]);
            } finally {
                clearTimeout(timer);
            }
        },
    };
}

const REVOKE_HEADER = `oc-lock:device-revoke:${BINDING_VERSION}`;

/** A device statement's header and its address and device_id, each the first line naming it, as lock-device reads them (OC Lock §3.5). */
function statementOf(content) {
    const lines = typeof content === 'string' ? content.split('\n') : [];
    const field = (name) => {
        const line = lines.slice(1).find((l) => l.startsWith(`${name}: `));
        return line === undefined ? null : line.slice(name.length + 2);
    };
    return { header: lines[0], address: field('address'), deviceId: field('device_id') };
}

/** A stored 30114 event as the namespace it sits in, its d tag and its parsed record. */
function parseStored(ev) {
    const d = dTag(ev);
    const ns = typeof d === 'string' ? NAMESPACES.find((n) => d.startsWith(n.prefix)) : undefined;
    if (!ns) return null;
    let content;
    try {
        content = JSON.parse(ev.content);
    } catch {
        return null;
    }
    const handle = typeof content?.handle === 'string' ? content.handle : '';
    const rec = ns.parse(content, handle);
    if (!rec || ns.dtag(handle) !== d) return null;
    return { rec, ns, d };
}
