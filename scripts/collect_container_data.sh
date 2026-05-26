#!/usr/bin/env bash
# collect_container_data.sh — Collect eBPF data from real Docker containers.
# Usage: echo 123456 | sudo -S bash scripts/collect_container_data.sh [duration_seconds]
#
# Starts containers with realistic workloads, runs the eBPF monitor,
# saves CSV data to data/, then stops containers.

set -euo pipefail

DURATION="${1:-60}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_DIR/data"

mkdir -p "$DATA_DIR"

IMAGE="busybox-minimal:latest"
NETWORK="ebpf_mon_net"

echo "=== Container Data Collection ==="
echo "Duration: ${DURATION}s"
echo "Data dir: $DATA_DIR"
echo

# Ensure image exists
echo 123456 | sudo -S docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "$IMAGE" || {
    echo "Building minimal busybox image..."
    ROOTFS_TMP=$(mktemp -d)
    mkdir -p "$ROOTFS_TMP"/{bin,etc,proc,sys,dev,tmp,home,root}
    cp /usr/bin/busybox "$ROOTFS_TMP/bin/"
    for cmd in sh ls cat echo ps mount dd ping df sleep head tail date hostname mkdir cp mv rm touch grep cut sort uniq wc whoami id; do
        ln -sf /bin/busybox "$ROOTFS_TMP/bin/$cmd"
    done
    echo 'root:x:0:0:root:/root:/bin/sh' > "$ROOTFS_TMP/etc/passwd"
    echo 'root:x:0:' > "$ROOTFS_TMP/etc/group"
    (cd "$ROOTFS_TMP" && tar cf - .) | echo 123456 | sudo -S docker import - "$IMAGE"
    rm -rf "$ROOTFS_TMP"
}

# Create network for containers
echo 123456 | sudo -S docker network create "$NETWORK" 2>/dev/null || true

cleanup() {
    echo
    echo "=== Cleaning up containers ==="
    for c in "$@"; do
        echo 123456 | sudo -S docker rm -f "$c" 2>/dev/null || true
    done
    echo 123456 | sudo -S docker network rm "$NETWORK" 2>/dev/null || true
    echo "Done"
}
trap 'cleanup ${CONTAINERS[@]+"${CONTAINERS[@]}"}' EXIT

CONTAINERS=()

# Container 1: File I/O + process creation workload
C1=$(echo 123456 | sudo -S docker run -d --name ebpf_io --network "$NETWORK" "$IMAGE" \
    sh -c '
        i=0
        while true; do
            echo "log entry $i" >> /tmp/work.log
            cat /tmp/work.log > /dev/null 2>&1
            ls /bin > /dev/null 2>&1
            date > /dev/null
            i=$((i + 1))
            sleep 1
        done
    ')
CONTAINERS+=("$C1")
echo "Started: ebpf_io ($C1)"

# Container 2: Network activity (ping loopback + HTTP-like connections)
C2=$(echo 123456 | sudo -S docker run -d --name ebpf_net --network "$NETWORK" "$IMAGE" \
    sh -c '
        while true; do
            ping -c 1 -W 1 127.0.0.1 > /dev/null 2>&1 || true
            hostname > /dev/null
            cat /proc/net/tcp > /dev/null 2>&1 || true
            sleep 2
        done
    ')
CONTAINERS+=("$C2")
echo "Started: ebpf_net ($C2)"

# Container 3: Process spawning workload
C3=$(echo 123456 | sudo -S docker run -d --name ebpf_proc --network "$NETWORK" "$IMAGE" \
    sh -c '
        while true; do
            sh -c "echo spawned" > /dev/null 2>&1
            sleep 3
        done
    ')
CONTAINERS+=("$C3")
echo "Started: ebpf_proc ($C3)"

# Container 4: Memory/CPU workload
C4=$(echo 123456 | sudo -S docker run -d --name ebpf_cpu --network "$NETWORK" "$IMAGE" \
    sh -c '
        while true; do
            dd if=/dev/zero bs=4k count=500 2>/dev/null | sha256sum > /dev/null
            sleep 4
        done
    ')
CONTAINERS+=("$C4")
echo "Started: ebpf_cpu ($C4)"

echo
echo "=== Running eBPF monitor for ${DURATION}s ==="
echo 123456 | sudo -S timeout "$DURATION" python3 -m src.main --rate 1000 2>/dev/null || true

echo
echo "=== Data collected ==="
wc -l "$DATA_DIR"/*.csv 2>/dev/null || echo "(no CSV files)"

echo
echo "=== Container cgroup IDs ==="
for c in "${CONTAINERS[@]}"; do
    name=$(echo 123456 | sudo -S docker inspect --format '{{.Name}}' "$c" 2>/dev/null | sed 's|/||')
    pid=$(echo 123456 | sudo -S docker inspect --format '{{.State.Pid}}' "$c" 2>/dev/null)
    echo "  $name: PID=$pid"
done
