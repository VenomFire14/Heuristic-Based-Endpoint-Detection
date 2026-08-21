import os
import re
import time
import json
import socket
import shutil
import platform
from datetime import datetime
from threading import Thread
from flask import Flask, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import psutil

LOG_FILES = {
    'execve': 'execve_sensor.log',
    'net': 'connect_sensor.log',
    'alert': 'ptrace_sensor.log'
}

LOG_FILE = "./system_data.json"
ALERT_FILE = "./system_alert.json"
ALERT_ARCHIVE_DIR = "./alerts"

MAX_ALERT_ENTRIES = 10
INTERVAL = 1
LOG_INTERVAL = 15

CPU_THRESHOLD = 90
RAM_THRESHOLD = 90
DISK_THRESHOLD = 100
NETWORK_THRESHOLD_MB = 100

app = Flask(__name__)
app.config['SECRET_KEY'] = 'trinity-secret!'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

latest_data = {}

PATTERNS = {
    'alert': re.compile(
        r'\[(?P<logtime>[^\]]+)\]\s+'
        r'PID=(?P<pid>\d+)\s+'
        r'PPID=(?P<ppid>\d+)\s+'
        r'UID=(?P<uid>\d+)\s+'
        r'COMM=(?P<comm>\S+)\s+'
        r'REQUEST=(?P<request>\S+)\s+'
        r'TARGET_PID=(?P<target_pid>\d+)\s+'
        r'TARGET_COMM=(?P<target_comm>\S+)\s+'
        r'TARGET_EXE=(?P<target_exe>\S+)\s+'
        r'TARGETS_SENSOR=(?P<targets_sensor>\S+)'
    ),
    'execve': re.compile(
        r'\[(?P<logtime>[^\]]+)\]\s+'
        r'PID=(?P<pid>\d+)\s+'
        r'PPID=(?P<ppid>\d+)\s+'
        r'UID=(?P<uid>\d+)\s+'
        r'COMM=(?P<comm>\S+)\s+'
        r'FILE=(?P<file>\S+)\s+'
        r'ARGV=(?P<argv>.*?)\s+'
        r'CWD=(?P<cwd>.*?)\s+'
        r'EXE=(?P<exe>\S+)\s+'
        r'TRUNCATED=(?P<truncated>\S+)'
    ),
    'net': re.compile(
        r'\[(?P<logtime>[^\]]+)\]\s+'
        r'PID=(?P<pid>\d+)\s+'
        r'PPID=(?P<ppid>\d+)\s+'
        r'UID=(?P<uid>\d+)\s+'
        r'COMM=(?P<comm>\S+)\s+'
        r'FAMILY=(?P<family>\S+)\s+'
        r'DEST=(?P<dest>\S+)\s+'
        r'RET=(?P<ret>-?\d+)\s+'
        r'ESTABLISHED=(?P<established>\S+)'
    )
}

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def parse_log_line(line, forced_type=None):
    clean_line = strip_ansi(line).strip()
    if not clean_line:
        return None

    match = PATTERNS['alert'].search(clean_line)
    if match:
        return {'type': 'ALERT', 'severity': 'critical', 'data': match.groupdict(), 'raw': clean_line, 'timestamp': time.time()}

    match = PATTERNS['execve'].search(clean_line)
    if match:
        return {'type': 'EXECVE', 'severity': 'info', 'data': match.groupdict(), 'raw': clean_line, 'timestamp': time.time()}

    match = PATTERNS['net'].search(clean_line)
    if match:
        return {'type': 'NET', 'severity': 'warning', 'data': match.groupdict(), 'raw': clean_line, 'timestamp': time.time()}

    fallback_type = forced_type.upper() if forced_type else 'UNKNOWN'
    return {'type': fallback_type, 'severity': 'info', 'data': {'message': clean_line}, 'raw': clean_line, 'timestamp': time.time()}

def get_initial_history(lines_per_file=15):
    history = []
    for log_type, filepath in LOG_FILES.items():
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                for line in lines[-lines_per_file:]:
                    parsed = parse_log_line(line, forced_type=log_type)
                    if parsed:
                        history.append(parsed)
    history.sort(key=lambda x: x['timestamp'])
    return history

def get_security_history(lines_per_file=15):
    history = []

    filepath = "security_alerts.log"

    if not os.path.isfile(filepath):
        return history

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

        for line in lines[-lines_per_file:]:
            parsed = parse_security_log_line(line)
            if parsed:
                history.append(parsed)

    return history

def tail_single_file(log_type, filepath):
    if not os.path.isfile(filepath):
        print(f"[ERROR] Log file not found: {filepath}")
        return
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            parsed_data = parse_log_line(line, forced_type=log_type)
            if parsed_data:
                socketio.emit('new_log_data', parsed_data)

def parse_security_log_line(line):
    """Parses JSON-formatted security log lines into structured dictionaries."""
    clean_line = strip_ansi(line).strip()
    if not clean_line:
        return None
    
    try:
        # First attempt JSON parsing for structured security logs
        data = json.loads(clean_line)
        return {
            'sensor': data.get('sensor'),
            'severity': data.get('severity'),
            'engine': data.get('engine'),
            'risk_score': data.get('risk_score'),
            'recommended_action': data.get('recommended_action'),
            'attack_techniques': data.get('attack_techniques', []),
            'rules_fired': data.get('rules_fired', []),
            'rationale': data.get('rationale', []),
            'pid': data.get('pid'),
            'ppid': data.get('ppid'),
            'uid': data.get('uid'),
            'comm': data.get('comm'),
            'detail': data.get('detail', {}),
            'logged_at': data.get('logged_at'),
            'raw': clean_line,
            'timestamp': time.time()
        }
    except json.JSONDecodeError:
        # Fallback if raw text/unformatted line is logged instead of JSON
        parsed_regex = parse_log_line(clean_line, forced_type='security_alert')
        return parsed_regex


from collections import deque

def tail_security_alerts(filepath="security_alerts.log"):
    if not os.path.isfile(filepath):
        print(f"[ERROR] Security log file not found: {filepath}")
        return

    last_logs = deque(maxlen=5)

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()

            if line:
                payload = parse_security_log_line(line)

                if payload:
                    last_logs.append(payload)
                    print(payload)
                    socketio.emit("security_alert", payload)

            else:
                socketio.sleep(2)

                if last_logs:
                    socketio.emit("security_history", list(last_logs))

class SystemMonitor:
    def __init__(self):
        self.prev_net = psutil.net_io_counters()
        self.prev_time = time.time()

    def get_network_speed(self):
        now = time.time()
        current = psutil.net_io_counters()
        elapsed = now - self.prev_time
        if elapsed <= 0:
            elapsed = 1
        upload_speed = (current.bytes_sent - self.prev_net.bytes_sent) / elapsed
        download_speed = (current.bytes_recv - self.prev_net.bytes_recv) / elapsed
        self.prev_net = current
        self.prev_time = now
        return {
            "bytes_sent": current.bytes_sent,
            "bytes_recv": current.bytes_recv,
            "upload_speed": round(upload_speed, 2),
            "download_speed": round(download_speed, 2)
        }

    def get_cpu(self):
        return {
            "usage_percent": psutil.cpu_percent(interval=None),
            "logical_cores": psutil.cpu_count(),
            "physical_cores": psutil.cpu_count(logical=False),
            "frequency_mhz": psutil.cpu_freq().current if psutil.cpu_freq() else 0
        }

    def get_memory(self):
        ram = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return {
            "ram_total": ram.total,
            "ram_used": ram.used,
            "ram_available": ram.available,
            "ram_percent": ram.percent,
            "swap_total": swap.total,
            "swap_used": swap.used,
            "swap_percent": swap.percent
        }

    def get_disk(self):
        disk = psutil.disk_usage("/")
        prev = psutil.disk_io_counters()
        time.sleep(1)
        curr = psutil.disk_io_counters()
        read_speed = (curr.read_bytes - prev.read_bytes) / 1024 / 1024
        write_speed = (curr.write_bytes - prev.write_bytes) / 1024 / 1024
        return {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "read": read_speed,
            "write": write_speed
        }

    def get_load(self):
        if hasattr(os, "getloadavg"):
            load = os.getloadavg()
            return {"1min": load[0], "5min": load[1], "15min": load[2]}
        return {}

    def get_system(self):
        boot = datetime.fromtimestamp(psutil.boot_time())
        return {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "boot_time": boot.strftime("%Y-%m-%d %H:%M:%S")
        }

    def collect(self):
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "system": self.get_system(),
            "cpu": self.get_cpu(),
            "memory": self.get_memory(),
            "disk": self.get_disk(),
            "network": self.get_network_speed(),
            "load_average": self.get_load()
        }

def is_system_under_load(data):
    cpu_peak = data["cpu"]["usage_percent"] >= CPU_THRESHOLD
    ram_peak = data["memory"]["ram_percent"] >= RAM_THRESHOLD
    disk_peak = (data["disk"]["write"] >= DISK_THRESHOLD or data["disk"]["read"] >= DISK_THRESHOLD)
    network_peak = (
        data["network"]["upload_speed"] / 1024 / 1024 >= NETWORK_THRESHOLD_MB or
        data["network"]["download_speed"] / 1024 / 1024 >= NETWORK_THRESHOLD_MB
    )
    return cpu_peak or ram_peak or disk_peak or network_peak

os.makedirs(ALERT_ARCHIVE_DIR, exist_ok=True)

def rotate_alert_log():
    if not os.path.exists(ALERT_FILE):
        return
    with open(ALERT_FILE, "r") as f:
        lines = f.readlines()
    if len(lines) < MAX_ALERT_ENTRIES:
        return
    archive_file = os.path.join(ALERT_ARCHIVE_DIR, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_alerts_1-10.txt")
    shutil.copy(ALERT_FILE, archive_file)
    open(ALERT_FILE, "w").close()
    print(f"[INFO] Alert log rotated -> {archive_file}")

def write_log(data):
    global latest_data
    latest_data = data
    with open(LOG_FILE, "w") as f:
        json.dump(data, f, indent=4)

def append_system_log(data):
    with open(ALERT_FILE, "a") as f:
        json.dump(data, f)
        f.write("\n")
    rotate_alert_log()

def run_system_monitor():
    monitor = SystemMonitor()
    last_saved = 0
    print("System monitoring started...")
    while True:
        try:
            data = monitor.collect()
            write_log(data)
            socketio.emit('system_metrics', data)
            if is_system_under_load(data):
                now = time.time()
                if now - last_saved >= LOG_INTERVAL:
                    append_system_log(data)
                    socketio.emit('system_alert', data)
                    last_saved = now
                    print("[ALERT] High system load detected. Snapshot saved.")
            time.sleep(INTERVAL)
        except Exception as e:
            print("Error:", e)
            time.sleep(2)

@app.route("/api/system", methods=["GET"])
def get_system_data():
    return jsonify(latest_data)

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    if not os.path.exists(ALERT_FILE):
        return jsonify([])
    alerts = []
    with open(ALERT_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))
    return jsonify(alerts)

@socketio.on('connect')
def handle_connect():
    print('Client connected to SocketIO.')
    history = get_initial_history(lines_per_file=15)
    emit('log_history', history)

    security_history = get_security_history(lines_per_file=15)
    emit('security_history', security_history)

    if latest_data:
        emit('system_metrics', latest_data)

if __name__ == '__main__':
    missing_logs = [path for path in LOG_FILES.values() if not os.path.isfile(path)]
    if missing_logs:
        print("[ERROR] Required log file(s) not found:")
        for log in missing_logs:
            print(f"  - {log}")
        raise FileNotFoundError("One or more required log files are missing.")

    for log_type, filepath in LOG_FILES.items():
        Thread(target=tail_single_file, args=(log_type, filepath), daemon=True).start()
        print(f"Tracking [{log_type.upper()}] from {filepath}")

    Thread(target=tail_security_alerts, args=("security_alerts.log",), daemon=True).start()
    print("Tracking [SECURITY_ALERT] from security_alerts.log")

    Thread(target=run_system_monitor, daemon=True).start()

    socketio.run(app, host="0.0.0.0", port=5000, debug=True)