#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include "syscall.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t size)
{
    size_t written = fwrite(data, 1, size, stdout);
    fflush(stdout);
    return (written == size) ? 0 : -1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--rate N] [--pid PID]\n"
        "  --rate N    Sample every Nth syscall (default 1 = all)\n"
        "  --pid PID   Filter out this PID from events (default = auto)\n",
        prog);
}

int main(int argc, char *argv[])
{
    int sample_rate = 1;
    int filter_pid_val = getpid();

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--rate") == 0 && i + 1 < argc) {
            sample_rate = atoi(argv[++i]);
            if (sample_rate < 1) sample_rate = 1;
        } else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            filter_pid_val = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct syscall_bpf *skel = syscall_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF program\n");
        return 1;
    }

    uint32_t key = 0;

    int val = filter_pid_val;
    bpf_map__update_elem(skel->maps.filter_pid, &key, sizeof(key), &val, sizeof(val), BPF_ANY);

    val = sample_rate;
    bpf_map__update_elem(skel->maps.sample_rate, &key, sizeof(key), &val, sizeof(val), BPF_ANY);

    if (syscall_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.ringbuf),
        handle_event, NULL, NULL
    );
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    fprintf(stderr, "BPF Agent started (rate=1/%d, filter_pid=%d)\n",
            sample_rate, filter_pid_val);

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);

cleanup:
    syscall_bpf__destroy(skel);
    return 0;
}
