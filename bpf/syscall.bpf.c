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

SEC("raw_tp/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->syscall_id = ctx->id;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
