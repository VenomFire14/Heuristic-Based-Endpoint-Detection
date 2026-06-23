#!/usr/bin/env python3
"""
execve_sensor.py - Modular eBPF execve() tracer using kprobe.
Designed to be imported and combined with other sensors in a shared BPF instance.
"""

BPF_CODE = """
#define ARGSIZE 128
#define MAXARGS 20

struct data_t {
    u32 pid;
    u32 uid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char argv[ARGSIZE];
};

BPF_PERF_OUTPUT(execve_events);
BPF_PERCPU_ARRAY(argdata, struct data_t, 1);

static __always_inline int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data) {
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    execve_events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static __always_inline int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data) {
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__execve(struct pt_regs *ctx, const char __user *filename,
                    const char __user *const __user *__argv,
                    const char __user *const __user *__envp) {
    
    if (should_ignore()) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    u32 zero = 0;
    struct data_t *data = argdata.lookup(&zero);
    if (!data) return 0;
    __builtin_memset(data, 0, sizeof(*data));

    data->pid = pid;
    data->uid = uid;
    data->ppid = ppid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    __submit_arg(ctx, (void *)filename, data);

    #pragma unroll
    for (int i = 1; i < MAXARGS; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], data) == 0)
            break;
    }

    return 0;
}
"""

b = None  # Will be assigned by main.py

def init_bpf(bpf_instance):
    global b
    b = bpf_instance
    execve_fn = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fn, fn_name="syscall__execve")
    b["execve_events"].open_perf_buffer(print_event)

def print_event(cpu, data, size):
    event = b["execve_events"].event(data)
    print(f"[execve] PID:{event.pid} UID:{event.uid} PPID:{event.ppid} COMM:{event.comm.decode()}")
    print(f"         ARG: {event.argv.decode(errors='ignore')}")   
