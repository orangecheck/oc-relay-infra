#!/usr/bin/env python3
"""Per-source write limits in the write-policy plugin.

A source (strfry's sourceInfo: the front's daily pseudonym, one per IPv6 /64)
may send 30 events at once and one more every 2 seconds, 1,000 events and
4 MiB of event JSON a UTC day; 60 events refused on their merits within an
hour refuse all it sends for the next hour. Import, Stream and Sync never
count. The counts file holds totals and a number of sources, never a source.

    python3 policy/test_limits.py
"""
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import types

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("policy", HERE / "oc-dtag-filter.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

T0 = 1793059200.0  # 2026-10-27T00:00:00Z
A = "fd2d:9cab:bbe3:c159:76e1:55be:2462:553f"
B = "fd8c:fb65:9743:9ff7:1963:4425:5624:c8e"
failures = []
quiet, sys.stderr = sys.stderr, io.StringIO()  # the plugin logs each first limit


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


def fresh(t=T0):
    clock = Clock(t)
    path = str(pathlib.Path(tempfile.mkdtemp()) / "rate-limit-counts.json")
    return policy.SourceLimits(path=path, now=clock), clock, path


def msg(src, source_type="IP6", kind="new"):
    return {"type": kind, "sourceType": source_type, "sourceInfo": src}


def expect(what, got, want):
    if got != want:
        failures.append(f"{what}: got {got!r}, want {want!r}")


# Burst: 30 at once, then one every 2 s; another source has its own bucket.
lim, clock, path = fresh()
expect("30 at once", [lim.check(msg(A), 500) for _ in range(30)], [None] * 30)
expect("the 31st", lim.check(msg(A), 500), "burst")
expect("another source", lim.check(msg(B), 500), None)
clock.t += 1.9
expect("1.9 s later", lim.check(msg(A), 500), "burst")
clock.t += 0.1
expect("2 s later", lim.check(msg(A), 500), None)
expect("and only one", lim.check(msg(A), 500), "burst")
clock.t += 600
expect("a full bucket holds 30, not more",
       [lim.check(msg(A), 500) for _ in range(31)], [None] * 30 + ["burst"])

# The shared bucket for a request with no usable client address is limited like any source.
lim, clock, _ = fresh()
expect("fd00:: has the same burst", [lim.check(msg("fd00::"), 500) for _ in range(31)][-2:], [None, "burst"])

# Day: 1,000 events, then none until 00:00 UTC.
lim, clock, _ = fresh()
got = []
for _ in range(1001):
    got.append(lim.check(msg(A), 300))
    clock.t += 2
expect("1,000 a day", (got[:1000].count(None), got[1000]), (1000, "day"))
clock.t = T0 + 86400
expect("a new UTC day", lim.check(msg(A), 300), None)

# Bytes: 4 MiB of event JSON a day; a small event still fits after a large one does not.
lim, clock, _ = fresh()
MiB = 1024 * 1024
got = []
for size in (MiB, MiB, MiB, MiB - 100, 200, 100):
    got.append(lim.check(msg(A), size))
    clock.t += 2
expect("4 MiB a day", got, [None, None, None, None, "bytes", None])

# Every event counts, whatever is decided about it afterwards.
lim, clock, _ = fresh()
for _ in range(30):
    lim.check(msg(A), 500)
    lim.refused(msg(A))
expect("refused events spend the bucket", lim.check(msg(A), 500), "burst")

# Brake: 60 refused on their merits within an hour; 59 do nothing; it lifts an hour later.
lim, clock, _ = fresh()
for _ in range(59):
    lim.refused(msg(A))
    clock.t += 30
expect("59 refusals", lim.check(msg(A), 500), None)
lim.refused(msg(A))
expect("the 60th within the hour", lim.check(msg(A), 500), "refusals")
expect("other sources", lim.check(msg(B), 500), None)
clock.t += 3599
expect("59 min 59 s later", lim.check(msg(A), 500), "refusals")
clock.t += 1
expect("an hour later", lim.check(msg(A), 500), None)
lim, clock, _ = fresh()
for _ in range(60):
    lim.refused(msg(A))
    clock.t += 62  # the 60th comes 59 x 62 s = 3,658 s after the first
expect("60 refusals spread over more than an hour", lim.check(msg(A), 500), None)

# Only network writes count.
lim, clock, _ = fresh()
for st in ("Import", "Stream", "Sync", None):
    expect(f"{st} is never limited", [lim.check(msg(A, st), 500) for _ in range(40)], [None] * 40)
    for _ in range(70):
        lim.refused(msg(A, st))
expect("lookback is never limited", [lim.check(msg(A, "IP6", "lookback"), 500) for _ in range(40)], [None] * 40)
expect("and none of it spent the network bucket", lim.check(msg(A), 500), None)

# The counts file: totals by reason and a number of sources; no source in it.
lim, clock, path = fresh()
for _ in range(32):
    lim.check(msg(A), 500)
for _ in range(31):
    lim.check(msg(B), 500)
clock.t += 1
lim.check(msg(B), 500)
raw = pathlib.Path(path).read_text()
expect("counts file", json.loads(raw), {"2026-10-27": {"burst": 4, "sources": 2}})
for src in (A, B, A.split(":")[1], B.split(":")[1]):
    if src in raw:
        failures.append(f"the counts file names a source: {raw}")
# A restarted plugin keeps the day's totals.
again = policy.SourceLimits(path=path, now=clock)
again.check(msg("fd11::1"), 500)
for _ in range(31):
    again.check(msg("fd11::1"), 500)
expect("after a restart, a second limit in the same second waits", json.loads(pathlib.Path(path).read_text()),
       {"2026-10-27": {"burst": 5, "sources": 3}})
clock.t += 1
again.check(msg("fd12::1"), 500)  # any later event writes what waits
expect("after a restart", json.loads(pathlib.Path(path).read_text()),
       {"2026-10-27": {"burst": 6, "sources": 3}})

# The counts file is written at most once a second (and on a source's first
# limit): 10,000 limited events over 10 seconds write it about 11 times.
lim, clock, path = fresh()
writes, real_replace = [], os.replace
os.replace = lambda a, b: (writes.append(b), real_replace(a, b))
try:
    said = []
    for _ in range(10_030):
        said.append(lim.check(msg(A), 500))
        clock.t += 0.001
    clock.t += 1
    lim.check(msg(B), 500)
finally:
    os.replace = real_replace
expect("writes for 10,000 limited events", len(writes) <= 12, True)
expect("and every one counted", json.loads(pathlib.Path(path).read_text())["2026-10-27"]["burst"], said.count("burst"))

# The day that ends keeps the counts it had not written yet.
lim, clock, path = fresh(T0 + 86399)
for _ in range(36):
    lim.check(msg(A), 500)
expect("unwritten before midnight", json.loads(pathlib.Path(path).read_text())["2026-10-27"]["burst"], 1)
clock.t = T0 + 86400.2
lim.check(msg(B), 500)
expect("written at the new day", json.loads(pathlib.Path(path).read_text())["2026-10-27"]["burst"], 6)

# A lone surrogate is counted, not a crash.
expect("event_size of a lone surrogate", policy.event_size({"content": "\ud800"}), len('{"content":"') + 3 + 2)

# The table of sources is bounded; the least recently seen goes first.
saved, policy.MAX_SOURCES = policy.MAX_SOURCES, 3
lim, clock, _ = fresh()
for _ in range(30):
    lim.check(msg("fd01::"), 500)
for src in ("fd02::", "fd03::", "fd04::"):
    lim.check(msg(src), 500)
expect("table size", len(lim.sources), 3)
expect("the forgotten source starts again", lim.check(msg("fd01::"), 500), None)
lim, clock, _ = fresh()
for _ in range(30):
    lim.check(msg("fd01::"), 500)
lim.check(msg("fd02::"), 500)
lim.check(msg("fd03::"), 500)
lim.check(msg("fd01::"), 500)  # seen again: now the most recent
lim.check(msg("fd04::"), 500)  # so fd02 goes
expect("a source seen again is kept", lim.check(msg("fd01::"), 500), "burst")
expect("the least recently seen went", "fd02::" in lim.sources, False)
lim, clock, path = fresh()
logged = sys.stderr.getvalue().count("sources today)")
for src in ("fd01::", "fd02::", "fd03::", "fd04::"):
    for _ in range(31):
        lim.check(msg(src), 500)
expect("the set of limited sources is bounded too", len(lim.limited), 3)
expect("and the count stops there", json.loads(pathlib.Path(path).read_text())["2026-10-27"]["sources"], 3)
expect("one line per source told apart", sys.stderr.getvalue().count("sources today)") - logged, 3)
policy.MAX_SOURCES = saved

sys.stderr = quiet

# The same, the way strfry runs the plugin. A limited event never reaches the
# directory gate (here one that hangs), and is answered with the reason text.
tmp = pathlib.Path(tempfile.mkdtemp())


def line(eid, kind, d, src, source_type="IP6"):
    return json.dumps({"type": "new", "event": {"id": eid, "kind": kind, "tags": [["d", d]], "content": "{}"},
                       "receivedAt": 0, "sourceType": source_type, "sourceInfo": src})


STAMP = "oc-stamp:" + "a" * 64
lines = [line(f"s{i}", 30083, STAMP, A) for i in range(31)]
lines.append(line("d1", 30114, "oc-lock-chat-dir:ZfLP2s-FrLVE152xghZld2DYd-YMs9P1Eu4qBv28mc4", A))
lines.append(line("b1", 30083, STAMP, B))
lines.append(line("i1", 30083, STAMP, "", "Import"))
env = dict(os.environ, OC_DIR_GATE_CMD=json.dumps([sys.executable, str(HERE / "testdata" / "fake_gate.py")]),
           OC_DIR_GATE_TIMEOUT_S="0.5", FAKE_GATE_MODE="hang", OC_DIR_GATE_BRIDGE_COUNTS=str(tmp / "bridge.json"),
           OC_LIMIT_COUNTS=str(tmp / "limits.json"))
proc = subprocess.Popen([sys.executable, str(HERE / "oc-dtag-filter.py")], stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
proc.stdin.write("\n".join(lines) + "\n")
proc.stdin.flush()
time.sleep(1.2)  # the second limit waits for the next event a second on
proc.stdin.write(line("b2", 30083, STAMP, B) + "\n")
stdout, stderr = proc.communicate(timeout=30)
out = types.SimpleNamespace(stdout=stdout, stderr=stderr)
got = [json.loads(x) for x in out.stdout.splitlines()]
expect("plugin: the late event", got[34:], [{"id": "b2", "action": "accept"}])
limited = {"action": "reject", "msg": "rate-limited: too many events from this address, try again later"}
expect("plugin: 30 accepted", [g["action"] for g in got[:30]], ["accept"] * 30)
expect("plugin: the 31st", got[30], dict(limited, id="s30"))
expect("plugin: a limited directory record", got[31], dict(limited, id="d1"))
expect("plugin: another source", got[32], {"id": "b1", "action": "accept"})
expect("plugin: an import", got[33], {"id": "i1", "action": "accept"})
expect("plugin: the gate was never asked", (tmp / "bridge.json").exists(), False)
expect("plugin: counts", list(json.loads((tmp / "limits.json").read_text()).values()), [{"burst": 2, "sources": 1}])
if "a source hit the write limit (burst; 1 sources today)" not in out.stderr or A in out.stderr:
    failures.append(f"plugin: stderr {out.stderr!r}")

# Which answers count toward the brake: a refusal on the merits (the prefix
# gate's or the directory gate's), never an acceptance or a busy gate.
class Recorder(policy.SourceLimits):
    calls = []
    checked = []

    def check(self, msg, size):
        Recorder.checked.append(msg["event"]["id"])
        return "burst" if msg["event"]["id"] == "rl" else None

    def refused(self, msg):
        Recorder.calls.append(msg["event"]["id"])


DEVICE = "oc-lock:device:bc1qmr7qn2t0ahj56ztpdswt54kn2r863ukd8wadj8"
saved = (policy.SourceLimits, policy.GATE_CMD, policy.GATE_TIMEOUT_S, sys.stdin, sys.stdout)
os.environ["FAKE_GATE_MODE"] = "reject"
policy.SourceLimits, policy.GATE_TIMEOUT_S = Recorder, 0.5
policy.GATE_CMD = [sys.executable, str(HERE / "testdata" / "fake_gate.py")]
sys.stdin = io.StringIO("\n".join([line("ok", 30083, STAMP, A), line("k1", 1, "x", A),
                                   line("dev", 30078, DEVICE, A), line("hangme", 30078, DEVICE, A),
                                   line("rl", 1, "x", A)]) + "\n")
sys.stdout = io.StringIO()
quiet, sys.stderr = sys.stderr, io.StringIO()
policy.main()
answers = [json.loads(x)["action"] for x in sys.stdout.getvalue().splitlines()]
policy.SourceLimits, policy.GATE_CMD, policy.GATE_TIMEOUT_S, sys.stdin, sys.stdout = saved
sys.stderr = quiet
expect("main: answers", answers, ["accept", "reject", "reject", "reject", "reject"])
expect("main: every event counted before it is judged", Recorder.checked, ["ok", "k1", "dev", "hangme", "rl"])
expect("main: refusals counted toward the brake", Recorder.calls, ["k1", "dev"])

if failures:
    print("FAIL\n" + "\n".join(failures))
    sys.exit(1)
print("write limits: 30 at once then 1 per 2 s, 1,000 events and 4 MiB a day, a 60-refusal brake for an hour, "
      "per source; Import/Stream/Sync exempt; counts hold no source")
