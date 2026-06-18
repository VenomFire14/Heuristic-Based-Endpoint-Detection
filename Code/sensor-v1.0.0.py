#!/usr/bin/env python3
import subprocess
import sys
import os
import platform

def check_privileges():
    if os.geteuid() != 0:
        print("Error: This script must be run as root (sudo).")
        sys.exit(1)

def check_kernel_version():
    version_str = platform.uname().release
    try:
        major, minor = map(int, version_str.split('.')[:2])
        if major < 5 or (major == 5 and minor < 8):
            print(f" Warning: Kernel {version_str} detected. Kernel 5.8+ is recommended.")
        else:
            print(f" Kernel version {version_str} OK.")
    except ValueError:
        print(f" Could not parse kernel version: {version_str}")

def ensure_dependencies():
    """Checks if BCC is installed. If not, installs it."""
    try:
        # Try importing directly. If successful, skip installation.
        from bcc import BPF
        print(" BCC library already installed. Skipping setup.")
        return True
    except ImportError:
        print(" BCC library not found. Installing dependencies...")
        
        packages = [
            "bpfcc-tools", 
            "python3-bpfcc", 
            f"linux-headers-{platform.uname().release}", 
            "build-essential", 
            "cmake", 
            "llvm", 
            "clang", 
            "libelf-dev"
        ]
        
        try:
            subprocess.run(["apt", "update"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"
            subprocess.run(["apt", "install", "-y"] + packages, check=True, env=env)
            
            # Verify installation immediately
            from bcc import BPF
            print(" Dependencies installed and verified successfully.\n")
            return True
        except Exception as e:
            print(f" Failed to install dependencies: {e}")
            sys.exit(1)

def run_ebpf_sensor():
    from bcc import BPF

    bpf_code = """
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

    try:
        # This line acts as the final "eBPF is working" check
        b = BPF(text=bpf_code)
        print(" ZD2 Sensor Active: Monitoring execve syscalls...")
        print(f"{'PID':<10} {'UID':<10} {'Command':<20} {'Full Path'}")
        print("-" * 80)
    except Exception as e:
        print(f" Failed to load eBPF program: {e}")
        print("Hint: Check if your kernel headers match the running kernel (`uname -r`).")
        sys.exit(1)

    def print_event(cpu, data, size):
        event = b["events"].event(data)
        filename = event.filename.decode('utf-8', errors='ignore')
        comm = event.comm.decode('utf-8', errors='ignore')
        print(f"{event.pid:<10} {event.uid:<10} {comm:<20} {filename}")

    b["events"].open_perf_buffer(print_event)
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n Sensor stopped.")
            exit()

if __name__ == "__main__":
    check_privileges()
    check_kernel_version()
    
    # Smart check: Only install if missing
    ensure_dependencies()
    
    # Start monitoring
    run_ebpf_sensor()   