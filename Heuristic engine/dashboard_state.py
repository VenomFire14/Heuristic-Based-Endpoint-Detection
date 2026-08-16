#!/usr/bin/env python3
"""
Zero-Day Shield :: dashboard_state.py

Turns the heuristics engine's per-event output into the AGGREGATED, table
shaped JSON a frontend renders. The engine answers "is this event bad?"; this
module answers "what does the system look like right now?"

Kept separate from heuristics_engine.py on purpose -- detection logic should
not know or care that a UI exists.

Each panel ships its own `columns` spec alongside its `rows`, so the frontend
renders generically. Adding a detection rule or a column never requires a
frontend change.

Demo (reuses the engine's synthetic events):

    python3 dashboard_state.py --demo
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from heuristics_engine import Assessment

# Engine severity -> UI threat level, matching the NONE / LOW / High vocabulary
# used by the existing dashboard panels.
THREAT_LEVEL = {
    "CRITICAL": "Critical",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
    "INFO":     "None",
    None:       "None",
}

SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _worse(a: str | None, b: str | None) -> str | None:
    return max([x for x in (a, b) if x], key=lambda s: SEVERITY_RANK.get(s, 0),
               default=None)


def _humanize(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{seconds / 60:.0f}m {seconds % 60:.0f}s"
    return f"{seconds / 3600:.1f}h"


# =============================================================================
# Row models
# =============================================================================

@dataclass
class ProcessRow:
    pid: int
    ppid: int = 0
    uid: int = 0
    command: str = ""
    exe: str = ""
    started: float = field(default_factory=time.time)
    ended: float | None = None
    exit_code: int | None = None
    severity: str | None = None
    rules: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    terminated_by_shield: bool = False

    @property
    def duration(self) -> float:
        return (self.ended or time.time()) - self.started

    @property
    def status(self) -> str:
        if self.terminated_by_shield:
            return "Terminated"
        if self.ended is None:
            # Honest default. Becomes Success/Failed once a sched_process_exit
            # sensor exists -- until then the engine genuinely does not know.
            return "Running"
        return "Success" if self.exit_code == 0 else "Failed"


@dataclass
class DestinationRow:
    address: str
    port: int = 0
    connections: int = 0
    processes: set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    severity: str | None = None
    rules: set[str] = field(default_factory=set)

    def rate_per_min(self) -> float:
        window = max(self.last_seen - self.first_seen, 1.0)
        return self.connections / (window / 60.0)


# =============================================================================
# State
# =============================================================================

class DashboardState:
    """Rolling aggregate of everything the sensors have reported.

    Bounded the same way ProcessContext is -- a dashboard that grows without
    limit during an overnight capture is a memory leak with a nice UI.
    """

    PROCESS_TTL = 1800      # keep exited processes visible for 30 min
    MAX_ALERTS = 200
    MAX_ROWS = 500

    def __init__(self, hostname: str | None = None):
        self.hostname = hostname or os.uname().nodename
        self.processes: dict[int, ProcessRow] = {}
        self.destinations: dict[tuple, DestinationRow] = {}
        self.alerts: list[dict] = []
        self.counts: dict[str, int] = defaultdict(int)
        self.started = time.time()
        self._last_prune = time.time()

    # -- ingestion ------------------------------------------------------------

    def ingest(self, ev: dict, result: Assessment | None = None) -> None:
        """Feed every event here, whether or not the engine flagged it.
        Clean events still populate the process table."""
        sensor = ev.get("sensor")

        if sensor == "execve":
            self._ingest_exec(ev, result)
        elif sensor == "connect":
            self._ingest_connect(ev, result)

        if result is not None:
            self._ingest_alert(ev, result)

        self._maybe_prune()

    def _ingest_exec(self, ev, result):
        pid = ev.get("pid", 0)
        row = self.processes.get(pid)
        if row is None:
            row = ProcessRow(pid=pid, started=ev.get("ts") or time.time())
            self.processes[pid] = row

        row.ppid = ev.get("ppid", row.ppid)
        row.uid = ev.get("uid", row.uid)
        row.exe = ev.get("exe") or ev.get("filename") or row.exe
        argv = ev.get("argv") or []
        row.command = " ".join(argv) if argv else (ev.get("filename") or "")

        if result:
            row.severity = _worse(row.severity, result.severity)
            row.rules.update(v.rule_id for v in result.verdicts)
            row.techniques.update(result.techniques)

    def _ingest_connect(self, ev, result):
        addr = ev.get("daddr") or ""
        if not addr:
            return
        key = (addr, ev.get("dport", 0))
        row = self.destinations.get(key)
        if row is None:
            row = DestinationRow(address=addr, port=ev.get("dport", 0),
                                 first_seen=ev.get("ts") or time.time())
            self.destinations[key] = row

        row.connections += 1
        row.last_seen = ev.get("ts") or time.time()
        if ev.get("comm"):
            row.processes.add(ev["comm"])
        if result:
            row.severity = _worse(row.severity, result.severity)
            row.rules.update(v.rule_id for v in result.verdicts)

    def _ingest_alert(self, ev, result: Assessment):
        alert = result.to_alert()
        alert["id"] = f"{ev.get('sensor')}-{ev.get('pid')}-{int(time.time()*1000)}"
        alert["threat_level"] = THREAT_LEVEL.get(result.severity, "None")
        alert["observed_at"] = datetime.fromtimestamp(
            ev.get("ts") or time.time(), tz=timezone.utc).isoformat()
        self.alerts.insert(0, alert)
        del self.alerts[self.MAX_ALERTS:]
        self.counts[result.severity] += 1

    def note_exit(self, pid: int, exit_code: int, ts: float | None = None):
        """Call this from a sched_process_exit sensor once one exists.
        Until then Duration keeps counting and Status stays 'Running'."""
        row = self.processes.get(pid)
        if row:
            row.ended = ts or time.time()
            row.exit_code = exit_code

    def note_termination(self, pid: int):
        """Called by the mitigation layer after a successful kill."""
        row = self.processes.get(pid)
        if row:
            row.terminated_by_shield = True
            row.ended = time.time()

    def _maybe_prune(self):
        now = time.time()
        if now - self._last_prune < 30:
            return
        self._last_prune = now
        for pid, row in list(self.processes.items()):
            if row.ended and now - row.ended > self.PROCESS_TTL:
                del self.processes[pid]
        if len(self.processes) > self.MAX_ROWS:
            for pid, _ in sorted(self.processes.items(),
                                 key=lambda kv: kv[1].started
                                 )[:len(self.processes) - self.MAX_ROWS]:
                self.processes.pop(pid, None)

    # -- panels ---------------------------------------------------------------

    def panel_processes(self, limit=25) -> dict:
        rows = sorted(self.processes.values(),
                      key=lambda r: (SEVERITY_RANK.get(r.severity, 0), r.started),
                      reverse=True)[:limit]
        return {
            "title": "Monitored Process Executions",
            "icon": "terminal",
            "columns": [
                {"key": "pid",          "label": "PID",          "type": "badge"},
                {"key": "command",      "label": "Command",      "type": "code"},
                {"key": "duration",     "label": "Duration",     "type": "text"},
                {"key": "status",       "label": "Status",       "type": "status"},
                {"key": "threat_level", "label": "Threat Level", "type": "threat"},
            ],
            "rows": [{
                "pid": r.pid,
                "ppid": r.ppid,
                "uid": r.uid,
                "command": r.command,
                "exe": r.exe,
                "duration": _humanize(r.duration),
                "duration_seconds": round(r.duration, 3),
                "status": r.status,
                "threat_level": THREAT_LEVEL.get(r.severity, "None"),
                "severity": r.severity,
                "rules": sorted(r.rules),
                "techniques": sorted(r.techniques),
            } for r in rows],
        }

    def panel_destinations(self, limit=25) -> dict:
        rows = sorted(self.destinations.values(),
                      key=lambda r: (SEVERITY_RANK.get(r.severity, 0),
                                     r.connections),
                      reverse=True)[:limit]
        return {
            "title": "Top Outbound Destinations",
            "icon": "network",
            "columns": [
                {"key": "address",      "label": "Destination IP", "type": "badge"},
                {"key": "process",      "label": "Process",        "type": "text"},
                {"key": "connections",  "label": "Connections",    "type": "rate"},
                {"key": "threat_level", "label": "Threat Level",   "type": "threat"},
            ],
            "rows": [{
                "address": r.address,
                "port": r.port,
                "process": ", ".join(sorted(r.processes)) or "unknown",
                "connections": r.connections,
                "rate_per_min": round(r.rate_per_min(), 1),
                "threat_level": THREAT_LEVEL.get(r.severity, "None"),
                "severity": r.severity,
                "rules": sorted(r.rules),
                "last_seen": datetime.fromtimestamp(
                    r.last_seen, tz=timezone.utc).isoformat(),
            } for r in rows],
        }

    def panel_alerts(self, limit=50) -> dict:
        return {
            "title": "Behavioural Detections",
            "icon": "shield",
            "columns": [
                {"key": "observed_at",        "label": "Time",     "type": "time"},
                {"key": "severity",           "label": "Severity", "type": "threat"},
                {"key": "comm",               "label": "Process",  "type": "text"},
                {"key": "rules_fired",        "label": "Rules",    "type": "tags"},
                {"key": "attack_techniques",  "label": "ATT&CK",   "type": "tags"},
                {"key": "recommended_action", "label": "Action",   "type": "action"},
            ],
            "rows": self.alerts[:limit],
        }

    def panel_summary(self) -> dict:
        return {
            "title": "Engine Status",
            "hostname": self.hostname,
            "uptime_seconds": round(time.time() - self.started, 1),
            "processes_observed": len(self.processes),
            "destinations_observed": len(self.destinations),
            "alerts_total": sum(self.counts.values()),
            "by_severity": {k: self.counts.get(k, 0) for k in
                            ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
            "pending_terminations": sum(
                1 for a in self.alerts if a.get("recommended_action") == "TERMINATE"),
        }

    def snapshot(self) -> dict:
        return {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": self.panel_summary(),
            "panels": {
                "processes": self.panel_processes(),
                "destinations": self.panel_destinations(),
                "alerts": self.panel_alerts(),
            },
        }

    def write_snapshot(self, path="dashboard_state.json"):
        """Atomic write -- the frontend polls this file and must never read a
        half-written document. Write to a temp file on the same filesystem,
        then rename; rename is atomic on POSIX."""
        d = os.path.dirname(os.path.abspath(path))
        fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.snapshot(), fh, default=str)
            # mkstemp() always creates at 0600 regardless of umask -- correct
            # for a secret file, wrong here: main.py runs as root (eBPF
            # requires it), but the frontend reading this file does not and
            # must not need to. Without this, the file is root-only and
            # unreadable by whatever process renders the dashboard.
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except Exception:
            os.path.exists(tmp) and os.unlink(tmp)
            raise


# =============================================================================
# Demo
# =============================================================================

def demo():
    from heuristics_engine import (HeuristicsEngine, SELFTEST_EVENTS,
                                   _fake_stdio_probe)

    engine = HeuristicsEngine(stdio_probe=_fake_stdio_probe)
    state = DashboardState(hostname="zds-lab-vm")

    for ev in SELFTEST_EVENTS:
        ev.setdefault("ts", time.time())
        state.ingest(ev, engine.evaluate(ev))

    # Simulate what a sched_process_exit sensor would deliver.
    state.note_exit(4004, exit_code=0)
    state.note_exit(4030, exit_code=1)
    state.note_termination(4003)

    snap = state.snapshot()
    print(json.dumps(snap, indent=2, default=str)[:2400])
    print("\n... truncated ...\n")

    print("PROCESS PANEL (first 6 rows, as the frontend receives them)")
    print("-" * 78)
    for r in snap["panels"]["processes"]["rows"][:6]:
        print(f"  {r['pid']:<6} {r['command'][:44]:<46} "
              f"{r['duration']:<8} {r['status']:<11} {r['threat_level']}")

    print("\nDESTINATION PANEL")
    print("-" * 78)
    for r in snap["panels"]["destinations"]["rows"]:
        print(f"  {r['address']:<16} {r['process']:<12} "
              f"{r['connections']:<4} conns   {r['threat_level']}")

    print("\nSUMMARY")
    print("-" * 78)
    for k, v in snap["summary"].items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Zero-Day Shield dashboard state")
    ap.add_argument("--demo", action="store_true",
                    help="render synthetic events into dashboard JSON")
    a = ap.parse_args()
    if a.demo:
        demo()
    else:
        ap.print_help()
