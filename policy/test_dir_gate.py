#!/usr/bin/env python3
"""Run the plugin the way strfry does and check its kind-30114 bridge.

Kinds other than 30114, and 30078 records outside oc-lock:device:, never reach
the sidecar, and their answers are the same bytes as before. A 30114 event is admitted only on the sidecar's accept;
a hung, dead, garbled or mismatched sidecar is a refusal within the timeout,
and the events after it are still answered.

    python3 policy/test_dir_gate.py
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).parent
PLUGIN = HERE / "oc-dtag-filter.py"
FAKE = HERE / "testdata" / "fake_gate.py"
DIR_D = "oc-lock-chat-dir:ZfLP2s-FrLVE152xghZld2DYd-YMs9P1Eu4qBv28mc4"


def line(eid, kind, d):
    return json.dumps({"type": "new", "event": {"id": eid, "kind": kind, "tags": [["d", d]], "content": "{}"},
                       "receivedAt": 0, "sourceType": "IP4", "sourceInfo": "203.0.113.1"})


COUNTS = pathlib.Path(tempfile.mkdtemp()) / "bridge-counts.json"


def counted():
    days = json.loads(COUNTS.read_text()) if COUNTS.exists() else {}
    COUNTS.unlink(missing_ok=True)
    return next(iter(days.values()), {})


def run(lines, mode, timeout="0.5", cmd=None):
    env = dict(os.environ, OC_DIR_GATE_CMD=json.dumps(cmd or [sys.executable, str(FAKE)]),
               OC_DIR_GATE_TIMEOUT_S=timeout, FAKE_GATE_MODE=mode, OC_DIR_GATE_BRIDGE_COUNTS=str(COUNTS))
    started = time.monotonic()
    out = subprocess.run([sys.executable, str(PLUGIN)], input="\n".join(lines) + "\n", capture_output=True,
                         text=True, env=env, timeout=30)
    run.stderr = out.stderr
    return [json.loads(x) for x in out.stdout.splitlines()], time.monotonic() - started


failures = []
STAMP = line("s1", 30083, "oc-stamp:" + "a" * 64)
DIR = line("d1", 30114, DIR_D)
AFTER = line("s2", 30083, "oc-stamp:" + "b" * 64)
BUSY = "rate-limited: directory check busy, try again"

got, _ = run([STAMP, DIR, AFTER], "accept")
if [g["action"] for g in got] != ["accept", "accept", "accept"]:
    failures.append(f"accept: {got}")

got, _ = run([DIR, line("d2", 30114, "not-a-directory-tag")], "accept")
if got[1].get("action") != "reject" or "not an oc namespace" not in got[1].get("msg", ""):
    failures.append(f"a 30114 that fails the prefix gate never reaches the sidecar: {got}")

got, _ = run([DIR], "reject")
if got != [{"id": "d1", "action": "reject", "msg": "invalid: fake"}]:
    failures.append(f"reject passes through: {got}")

# An OC Lock device record goes to the sidecar too; other 30078 records never do.
ADDR = "bc1qmr7qn2t0ahj56ztpdswt54kn2r863ukd8wadj8"
DEVICE = line("v1", 30078, "oc-lock:device:" + ADDR)
ATTEST = line("a1", 30078, "c" * 64)
SESSION = line("c1", 30078, "oc-chat:device:did:oc:351d9e47fc5bc8d667900a0b1ecf296f")
got, _ = run([DEVICE, ATTEST, SESSION], "reject")
if got != [{"id": "v1", "action": "reject", "msg": "invalid: fake"},
           {"id": "a1", "action": "accept"}, {"id": "c1", "action": "accept"}]:
    failures.append(f"only oc-lock:device records reach the sidecar: {got}")
got, _ = run([DEVICE], "accept")
if got != [{"id": "v1", "action": "accept"}]:
    failures.append(f"a device record is admitted on the sidecar's accept: {got}")

# Every refusal is counted under its reason, and logged with today's count.
WHY = {"hang": "timeout", "die": "sidecar exited", "garble": "garbled answer", "wrongid": "timeout"}
counted()
for mode in ("hang", "die", "garble", "wrongid"):
    got, took = run([STAMP, DIR, AFTER, DIR], mode)
    if counted() != {WHY[mode]: 2} or f"refused ({WHY[mode]}, 2 today)" not in run.stderr:
        failures.append(f"{mode}: refusals not counted as {WHY[mode]!r}: {run.stderr!r}")
    want = [{"id": "s1", "action": "accept"}, {"id": "d1", "action": "reject", "msg": BUSY},
            {"id": "s2", "action": "accept"}, {"id": "d1", "action": "reject", "msg": BUSY}]
    if got != want:
        failures.append(f"{mode}: {got}")
    if took > 5:
        failures.append(f"{mode}: took {took:.1f}s for two 0.5s boxes")

# A stuck sidecar is replaced, so the next directory write is checked again.
got, _ = run([line("hangme", 30114, DIR_D), line("d2", 30114, DIR_D)], "accept")
if got != [{"id": "hangme", "action": "reject", "msg": BUSY}, {"id": "d2", "action": "accept"}]:
    failures.append(f"stuck sidecar not replaced: {got}")

# With the sidecar missing altogether, 30114 is refused and nothing else changes.
counted()
got, _ = run([STAMP, DIR], "accept", cmd=["/nonexistent/node"])
if got != [{"id": "s1", "action": "accept"}, {"id": "d1", "action": "reject", "msg": BUSY}]:
    failures.append(f"missing sidecar: {got}")
if counted() != {"sidecar did not start": 1}:
    failures.append("missing sidecar: refusal not counted")

if failures:
    print("FAIL\n" + "\n".join(failures))
    sys.exit(1)
print("dir gate bridge: 30114 and oc-lock:device records admitted only on the sidecar's accept; hang, death, garble and a wrong id refuse")
