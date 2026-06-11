#!/usr/bin/env python3
from bcc import BPF

# 1. The eBPF C Code (Kernel Space)
# We use TRACEPOINT_PROBE(category, event) which automatically defines 'args'
bpf_code = """
#include <linux/sched.h>

// Define the data structure to send to Python
struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

// Define the Ring Buffer
BPF_PERF_OUTPUT(events);

// Use the MACRO instead of defining a function with a custom struct name
// Category: syscalls, Event: sys_enter_execve
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    
    // Capture basic info
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // CRITICAL: Read the full executable path from user space
    // 'args->filename' is automatically available inside TRACEPOINT_PROBE
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);

    // Send data to Ring Buffer
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# 2. Load and Attach (User Space)
try:
    b = BPF(text=bpf_code)
    print("ZD2 Sensor Active: Monitoring full command paths...")
    print(f"{'PID':<10} {'UID':<10} {'Command':<20} {'Full Path'}")
    print("-" * 80)
except Exception as e:
    print(f"Failed to load BPF: {e}")
    print("Hint: Ensure you are running as root (sudo) and have linux-headers installed.")
    exit(1)

# 3. Callback function to process events
def print_event(cpu, data, size):
    event = b["events"].event(data)
    filename = event.filename.decode('utf-8', errors='ignore')
    comm = event.comm.decode('utf-8', errors='ignore')
    print(f"{event.pid:<10} {event.uid:<10} {comm:<20} {filename}")

# 4. Start Polling the Ring Buffer
b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()   