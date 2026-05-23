#ifndef __COMMON_H
#define __COMMON_H

struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 cgroup_id;
    __s32 syscall_id;
    char comm[16];
} __attribute__((packed));

#endif
