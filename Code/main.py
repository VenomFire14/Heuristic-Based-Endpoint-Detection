#!/usr/bin/env python3
import os
import sys
from bcc import BPF
import resource

# Import sensor modules
import execve_sensor
import connect_sensor
import ptrace_sensor

COMMON_HEADERS = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <net/inet_sock.h>

static __always_inline bool should_ignore() {
    if (bpf_get_current_pid_tgid() >> 32 == 0) return true;
    return false;
}
"""

def ensure_dependencies():
    try:
        # Correct usage: (resource_type, soft_limit, hard_limit)
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        from bcc import BPF
        return True
    except ImportError as e:
        print(f" BCC not found: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f" Resource limit error: {e}")
        sys.exit(1)   

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: This script must be run as root (sudo).")
        sys.exit(1)

    kernel_ver = os.uname().release
    ensure_dependencies()

    print(f"Initializing ZD2 Sensor on Kernel {kernel_ver}...")
    
    try:
        combined_c_code = COMMON_HEADERS + \
                          execve_sensor.BPF_CODE + \
                          connect_sensor.BPF_CODE + \
                          ptrace_sensor.BPF_CODE

        b = BPF(text=combined_c_code)

        # Share the BPF instance with all sensors
        execve_sensor.b = connect_sensor.b = ptrace_sensor.b = b

        # Initialize each sensor
        execve_sensor.init_bpf(b)
        connect_sensor.init_bpf(b)
        ptrace_sensor.init_bpf(b)

        print("Sensor Active. Monitoring execve, connect, ptrace... (Ctrl+C to stop)")
        print("-" * 80)

        while True:
            b.perf_buffer_poll(timeout=100)

    except Exception as e:
        print(f"Failed to load eBPF program: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)   
