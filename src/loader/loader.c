#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
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

int main(int argc, char *argv[])
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct syscall_bpf *skel = syscall_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF program\n");
        return 1;
    }

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

    fprintf(stderr, "BPF Agent started\n");

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);

cleanup:
    syscall_bpf__destroy(skel);
    return 0;
}
