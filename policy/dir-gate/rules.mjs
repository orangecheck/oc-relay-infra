// The directory relay's write gate for kind 30114 (oc-chat-protocol SPEC §8.2.6).
// A listing is admitted only if it passes §8.2.2 (1)–(4); a tombstone only if it
// is signed by a key bound to its address and its `ends` names a claim this relay
// holds. Cheapest checks first. A read that does not answer, or a spent budget,
// refuses with "rate-limited:", never admits. The rule itself is lock-core's.

import {
    channelDirectoryDtag,
    directoryAnchor,
    directoryDtag,
    parseChannelDirectoryContent,
    parseDirectoryContent,
    repointId,
    resolveDirectory,
} from '@orangecheck/lock-core/directory';
import { boundNostrKeys, verifyDeviceRecords } from '@orangecheck/lock-device';

export const LIMITS = {
    /** 30114 writes per source IP per minute. */
    perIp: 6,
    /** 30114 writes per minute from one non-IP source (Sync, Stream, Import). */
    perSource: 30,
    /** Chain reads (tip, headers, coins) per minute, all writers together. */
    chainReads: 120,
    /** Answer within this, or refuse: strfry waits on every check. */
    deadlineMs: 2500,
};

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

class NoAnswer extends Error {}

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
 *   stored(dtag): Promise<NostrEvent[] | 'no-answer'>, kind-30114 events on this relay at a d tag
 *   allStored(): Promise<NostrEvent[] | 'no-answer'>, every kind-30114 event on this relay
 *   verifyBip322({ address, message, signature }): boolean | Promise<boolean>
 *   now(): number (ms)
 */
export function createGate(deps, limits = LIMITS) {
    const take = windows(deps.now);
    let spent = { start: -Infinity, n: 0 };
    const budget = () => {
        const t = deps.now();
        if (t - spent.start >= 60_000) spent = { start: t, n: 0 };
        if (spent.n >= limits.chainReads) return false;
        spent.n++;
        return true;
    };

    let tipCache = null;
    const tip = async () => {
        if (tipCache && deps.now() - tipCache.at < TIP_TTL_MS) return tipCache.height;
        if (!budget()) throw new NoAnswer();
        const height = await deps.tip();
        if (!Number.isSafeInteger(height) || height <= 0) throw new NoAnswer();
        tipCache = { height, at: deps.now() };
        return height;
    };

    const headerCache = new Map();
    const headers = {
        async getHeaderAt(height) {
            if (headerCache.has(height)) return headerCache.get(height);
            if (!budget()) throw new NoAnswer();
            const h = await deps.headers.getHeaderAt(height);
            // Only a header buried 6 deep is kept; anything nearer the tip can still change.
            if (h && tipCache && height <= tipCache.height - DEEP) remember(headerCache, height, h);
            return h;
        },
    };

    const coinCache = new Map();
    const coin = async (outpoint) => {
        const c = coinCache.get(outpoint);
        if (c && (c.final || deps.now() - c.at < COIN_TTL_MS)) return c.facts;
        if (!budget()) return 'no-answer';
        const facts = await deps.coin(outpoint);
        if (facts === 'no-answer') return facts;
        // A spend buried 6 deep does not change; the rest is kept a minute.
        const final = facts.spendHeight !== null && tipCache !== null && facts.spendHeight <= tipCache.height - DEEP;
        remember(coinCache, outpoint, { facts, at: deps.now(), final });
        return facts;
    };

    const boundKeys = async (address) => {
        const events = await deps.deviceEvents(address);
        if (events === 'no-answer') return 'no-answer';
        const verified = await verifyDeviceRecords(events, address, { verifyBip322: deps.verifyBip322 });
        return boundNostrKeys(verified, { now: new Date(deps.now()) });
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

    async function listing(ev, rec, d, ns) {
        const height = await tip();
        const anchor = await directoryAnchor(rec.claim.ots, rec.claimId, headers);
        if (anchor === null) return reject('invalid: the claim is not anchored (OC Chat §8.2.1)');
        if (typeof anchor !== 'number') throw new NoAnswer();
        if (height - anchor + 1 < DEEP) return reject('invalid: the claim needs 6 confirmations on its anchor (OC Chat §8.2.1)');
        const repoints = [];
        for (const r of rec.claim.repoints) {
            const id = repointId({ claim: rec.claimId, prev: r.prev, outpoint: r.outpoint, nonce: r.nonce });
            repoints.push({ repointId: id, prev: r.prev, outpoint: r.outpoint, anchor: await directoryAnchor(r.ots, id, headers) });
        }
        let keys = null;
        const reader = {
            boundKeys: async (address) => (keys = await boundKeys(address)),
            coin,
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
        const keys = await boundKeys(rec.address);
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

    async function decide(msg) {
        const ev = msg?.event;
        // Without the network: the record's shape, its d tag, its signer.
        const d = dTag(ev);
        const ns = typeof d === 'string' ? NAMESPACES.find((n) => d.startsWith(n.prefix)) : undefined;
        if (!ns || ev.kind !== 30114) return reject('invalid: not an OC Chat directory record');
        let content;
        try {
            content = JSON.parse(ev.content);
        } catch {
            return reject('invalid: content is not JSON');
        }
        if (content && typeof content === 'object' && content.v === 1) {
            return reject('blocked: a v1 listing holds no handle; publish v2 (OC Chat 0.4 §8.2.1)');
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
            return rec.kind === 'tombstone' ? await tombstone(ev, rec, d) : await listing(ev, rec, d, ns);
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
