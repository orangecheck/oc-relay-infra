#!/usr/bin/env python3
"""Archive every family event on relay.ochk.io to a JSONL file outside Fly.

Public relays prune: on 2026-10-07 none of the family's events existed on any
of them, so relay.ochk.io was the only copy (see BYPASS.md). This keeps a
second, verifiable copy in git. Each event's id is recomputed (NIP-01) and its
BIP-340 signature checked before it is written; the kinds and d-tag namespaces
come from the write policy itself, so the archive can never drift from what the
relay accepts. Any event that fails verification fails the run.

    python3 sync/archive.py <out.jsonl> [relay]
"""
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("policy", HERE.parent / "policy" / "oc-dtag-filter.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def point_mul(pt, k):
    r = None
    for i in range(256):
        if (k >> i) & 1:
            r = point_add(r, pt)
        pt = point_add(pt, pt)
    return r


def lift_x(x):
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if pow(y, 2, P) != y2:
        return None
    return (x, y if y % 2 == 0 else P - y)


def schnorr_ok(msg, pub, sig):
    pt = lift_x(int.from_bytes(pub, "big"))
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N:
        return False
    t = hashlib.sha256(b"BIP0340/challenge").digest()
    e = int.from_bytes(hashlib.sha256(t + t + sig[:32] + pub + msg).digest(), "big") % N
    R = point_add(point_mul(G, s), point_mul(pt, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def event_id(ev):
    ser = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]],
                     separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(ser.encode()).hexdigest()


def main():
    out = pathlib.Path(sys.argv[1])
    relay = sys.argv[2] if len(sys.argv) > 2 else "wss://relay.ochk.io"
    kinds = ",".join(str(k) for k in sorted(policy.ALLOWED_PREFIXES))
    raw = subprocess.run(["node", str(HERE / "fetch.mjs"), relay, kinds],
                         check=True, capture_output=True, text=True).stdout
    events = json.loads(raw)
    bad = []
    keep = []
    for ev in events:
        if event_id(ev) != ev["id"] or not schnorr_ok(bytes.fromhex(ev["id"]), bytes.fromhex(ev["pubkey"]),
                                                      bytes.fromhex(ev["sig"])):
            bad.append(ev["id"])
        elif policy.decide(ev)["action"] == "accept":
            keep.append(ev)
    if bad:
        sys.exit("refusing to archive: %d event(s) fail id/signature checks: %s" % (len(bad), bad[:5]))
    keep.sort(key=lambda e: (e["kind"], e["created_at"], e["id"]))
    out.write_text("".join(json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n" for e in keep))
    print("archived %d of %d events from %s" % (len(keep), len(events), relay))


if __name__ == "__main__":
    main()
