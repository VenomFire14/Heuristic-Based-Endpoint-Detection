#!/usr/bin/env python3
"""
connect_sensor.py - Modular eBPF connect() tracer using tracepoints.
Monitors outbound TCP/UDP connections. Designed to be imported by main.py.
"""
import socket
import struct

# --- C Code (No standalone imports or main logic) ---
BPF_CODE = """
struct connect_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 daddr_v4;
    u32 daddr_v6[4];
    u16 dport;
    u16 family;
};

BPF_PERF_OUTPUT(connect_events);

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (should_ignore()) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct connect_event_t event = {};
    event.pid = pid;
    event.uid = uid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
    short family = 0;
    
    // Safely read family
    if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) != 0) return 0;
    event.family = family;

    if (family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        bpf_probe_read_user(&event.daddr_v4, sizeof(event.daddr_v4), &addr_in->sin_addr.s_addr);
        bpf_probe_read_user(&event.dport, sizeof(event.dport), &addr_in->sin_port);
        event.dport = ntohs(event.dport);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        bpf_probe_read_user(&event.daddr_v6, sizeof(event.daddr_v6), &addr_in6->sin6_addr.in6_u.u6_addr32);
        bpf_probe_read_user(&event.dport, sizeof(event.dport), &addr_in6->sin6_port);
        event.dport = ntohs(event.dport);
    } else {
        return 0; // Ignore Unix sockets
    }

    connect_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

b = None  # Will be assigned by main.py

def init_bpf(bpf_instance):
    """Attach tracepoints and open perf buffer using the shared BPF instance."""
    global b
    b = bpf_instance
    # Tracepoints are auto-attached by BCC if the function name matches TRACEPOINT_PROBE category/event
    # However, explicit loading ensures clarity. The C code above uses TRACEPOINT_PROBE(syscalls, sys_enter_connect)
    # which BCC automatically loads when the text is compiled.
    
    b["connect_events"].open_perf_buffer(print_event)

def print_event(cpu, data, size):
    """Callback to process and print connection events."""
    event = b["connect_events"].event(data)
    comm = event.comm.decode('utf-8', errors='ignore')
    
    ip_str = ""
    if event.family == socket.AF_INET:
        try:
            ip_str = socket.inet_ntoa(struct.pack('I', event.daddr_v4))
        except Exception:
            ip_str = "0.0.0.0"
    elif event.family == socket.AF_INET6:
        # Simple IPv6 formatting
        parts = [f"{x:02x}" for x in event.daddr_v6]
        ip_str = f"{parts[0]}{parts[1]}:{parts[2]}{parts[3]}:{parts[4]}{parts[5]}:{parts[6]}{parts[7]}"
    
    print(f"\033[94m[NET]\033[0m PID:{event.pid} UID:{event.uid} | {comm} -> {ip_str}:{event.dport}")   
