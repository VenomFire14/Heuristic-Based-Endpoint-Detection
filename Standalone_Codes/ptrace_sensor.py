# ptrace_sensor.py
BPF_CODE = """
struct ptrace_event_t {
    u32 pid; u32 uid; char comm[TASK_COMM_LEN]; u32 tracee_pid;
};
BPF_PERF_OUTPUT(ptrace_events);

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    if (should_ignore()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (args->request != 16 && args->request != 0x4206) return 0;
    struct ptrace_event_t event = {};
    event.pid = pid; event.uid = uid; event.tracee_pid = args->pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    ptrace_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

def init_bpf(b):
    b["ptrace_events"].open_perf_buffer(handle_event)

def handle_event(cpu, data, size):
    event = b["ptrace_events"].event(data)
    print(f"\033[91m[ALERT]\033[0m PTRACE DETECTED! PID:{event.pid} UID:{event.uid} ({event.comm.decode()}) attaching to {event.tracee_pid}")

b = None 