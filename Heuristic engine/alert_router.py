#!/usr/bin/env python3
"""
alert_router.py - forensic log sink for HeuristicsEngine Assessments.

Deliberately dumb: one JSON line per alert, flushed + fsynced immediately,
so a crash or `kill -9` never loses the most recent finding. Kept separate
from dashboard_state.py because the two have different retention
semantics: this log is an append-only, never-pruned forensic record; the
dashboard is a rolling, bounded, pruned in-memory view.

Default min_severity is MEDIUM+. It was deliberately INFO (log everything)
through the false-positive baseline pass and the TrustedProfile ML tuning
pass, since both needed visibility into every firing rule/verdict,
including ones that would otherwise be filtered as noise. Both are done
and their thresholds are trusted now, so the log defaults to MEDIUM+ to
keep security_alerts.log a genuine forensic signal instead of a firehose
that includes routine LOW/INFO chatter (e.g. every /tmp execution, every
ML-001 LOW/MONITOR finding).
"""
from __future__ import annotations

import json
import os
import time

from heuristics_engine import Assessment

SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


class AlertRouter:
    def __init__(self, path: str = "security_alerts.log", min_severity: str = "MEDIUM"):
        self.path = path
        self.min_rank = SEVERITY_RANK.get(min_severity, 1)

    def route(self, assessment: Assessment) -> None:
        if SEVERITY_RANK.get(assessment.severity, 0) < self.min_rank:
            return
        alert = assessment.to_alert()
        alert["logged_at"] = time.time()
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert, default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
            # main.py runs as root; readers of this log (the student, a
            # tail -f, a teammate's tooling) generally do not and should
            # not need to be. Set explicitly rather than trust root's umask.
            os.fchmod(fh.fileno(), 0o644)
