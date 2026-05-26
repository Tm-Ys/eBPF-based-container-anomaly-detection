#ifndef __COMMON_H
#define __COMMON_H

enum event_type {
    EVENT_SYSCALL = 0,
    EVENT_PROCESS = 1,
};

struct event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 cgroup_id;
    __s32 syscall_id;
    __s32 ret;
    __u8 type;
    char comm[16];
} __attribute__((packed));

#endif
