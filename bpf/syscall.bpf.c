#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} sample_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} sample_counter SEC(".maps");

static __always_inline int should_sample(void)
{
    u32 key = 0;
    u32 *rate = bpf_map_lookup_elem(&sample_rate, &key);
    if (rate && *rate > 1) {
        u32 *counter = bpf_map_lookup_elem(&sample_counter, &key);
        if (counter) {
            *counter = (*counter + 1) % *rate;
            if (*counter != 0)
                return 0;
        }
    }
    return 1;
}

static __always_inline int filter_self_pid(void)
{
    u32 key = 0;
    u32 *filtered = bpf_map_lookup_elem(&filter_pid, &key);
    if (filtered && *filtered != 0) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (pid == *filtered)
            return 0;
    }
    return 1;
}

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    if (!filter_self_pid() || !should_sample())
        return 0;

    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->syscall_id = ctx->id;
    e->ret = 0;
    e->type = EVENT_SYSCALL;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct event *e;

    if (!filter_self_pid() || !should_sample())
        return 0;

    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->syscall_id = ctx->id;
    e->ret = ctx->ret;
    e->type = EVENT_SYSCALL;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->syscall_id = 0;
    e->ret = 0;
    e->type = EVENT_PROCESS;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->syscall_id = 1;
    e->ret = ctx->child_pid;
    e->type = EVENT_PROCESS;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->syscall_id = 2;
    e->ret = 0;
    e->type = EVENT_PROCESS;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
