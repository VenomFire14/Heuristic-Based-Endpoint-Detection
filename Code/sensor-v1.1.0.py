#!/usr/bin/env python3
"""
Working execve sensor using kprobe, based on the execsnoop pattern.
"""

from bcc import BPF
import os
import sys
import resource

BPF_CODE = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

#define ARGSIZE 128
#define MAXARGS 20

struct data_t {
    u32 pid;
    u32 uid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char argv[ARGSIZE];
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(argdata, struct data_t, 1);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data) {
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data) {
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

    // Submit filename first
    __submit_arg(ctx, (void *)filename, data);

    // Submit arguments
    #pragma unroll
    for (int i = 1; i < MAXARGS; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], data) == 0)
            break;
    }

    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID:{event.pid} UID:{event.uid} PPID:{event.ppid} COMM:{event.comm.decode()}")
    print(f"  ARG: {event.argv.decode(errors='ignore')}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: Must run as root")
        sys.exit(1)
        
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

    try:
        b = BPF(text=BPF_CODE)
        b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")
        
        print("Monitoring execve... (Run: /bin/ls -l /tmp)")
        b["events"].open_perf_buffer(print_event)
        
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)   