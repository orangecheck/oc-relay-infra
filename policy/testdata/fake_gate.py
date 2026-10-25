#!/usr/bin/env python3
# A stand-in for dir-gate/gate.mjs in test_dir_gate.py: answers each line the
# way FAKE_GATE_MODE says (accept, reject, hang, garble, die, wrongid).
import json
import os
import sys
import time

mode = os.environ.get("FAKE_GATE_MODE", "accept")
for line in sys.stdin:
    msg = json.loads(line)
    if mode == "hang" or msg["id"] == "hangme":
        time.sleep(3600)
    if mode == "die":
        sys.exit(1)
    if mode == "garble":
        out = {"id": msg["id"], "action": "maybe"}
    elif mode == "wrongid":
        out = {"id": "someone-else", "action": "accept"}
    elif mode == "reject":
        out = {"id": msg["id"], "action": "reject", "msg": "invalid: fake"}
    else:
        out = {"id": msg["id"], "action": "accept"}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
