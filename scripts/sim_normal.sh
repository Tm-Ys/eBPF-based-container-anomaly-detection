#!/usr/bin/env bash
# sim_normal.sh — Simulate normal container behavior for training data generation.
# Run alongside: echo 123456 | sudo -S timeout 60 python3 -m src.main --rate 1000
set -euo pipefail

echo "[NORMAL] Starting normal behavior simulation (PID=$$)"

end=$((SECONDS + 55))

while [ $SECONDS -lt $end ]; do
    # 1. File I/O: read config files, write logs
    for i in 1 2 3; do
        cat /etc/passwd > /dev/null 2>&1 || true
        echo "normal log entry $(date)" >> /tmp/normal_$$.log
        head -c 1024 /dev/urandom > /dev/null 2>&1 || true
    done

    # 2. Process creation: run standard utilities
    date > /dev/null
    ps aux > /dev/null 2>&1 || true
    df -h > /dev/null 2>&1 || true

    # 3. Network activity: DNS resolution, HTTP fetch if available
    host localhost > /dev/null 2>&1 || true
    ping -c 1 -W 1 127.0.0.1 > /dev/null 2>&1 || true

    # 4. Memory activity
    dd if=/dev/zero of=/tmp/mmap_$$ bs=1M count=4 2>/dev/null || true
    cat /tmp/mmap_$$ > /dev/null 2>&1 || true

    sleep 1
done

rm -f /tmp/normal_$$.log /tmp/mmap_$$ 2>/dev/null || true
echo "[NORMAL] Done"
