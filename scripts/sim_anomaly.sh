#!/usr/bin/env bash
# sim_anomaly.sh — Simulate anomalous container behavior for training data.
# Run alongside: echo 123456 | sudo -S timeout 60 python3 -m src.main --rate 1000
set -euo pipefail

echo "[ANOMALY] Starting anomalous behavior simulation (PID=$$)"

end=$((SECONDS + 55))

while [ $SECONDS -lt $end ]; do
    phase=$((SECONDS % 4))

    case $phase in
        0)
            # Fork bomb simulation (limited): rapid process creation
            echo "[ANOMALY] Phase: rapid fork"
            for i in $(seq 1 50); do
                (true &) 2>/dev/null
            done
            wait 2>/dev/null || true
            ;;
        1)
            # Excessive file writes
            echo "[ANOMALY] Phase: file write storm"
            for i in $(seq 1 20); do
                dd if=/dev/urandom of="/tmp/evil_$$_$i" bs=1M count=1 2>/dev/null || true
            done
            ;;
        2)
            # Network scan simulation (connect to many ports)
            echo "[ANOMALY] Phase: port scan"
            for port in 22 80 443 8080 3306 6379 27017 11211; do
                timeout 0.1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null || true
            done
            ;;
        3)
            # Crypto miner-like CPU spike
            echo "[ANOMALY] Phase: CPU spike"
            dd if=/dev/zero bs=4k count=10000 2>/dev/null | sha256sum > /dev/null
            dd if=/dev/zero bs=4k count=10000 2>/dev/null | sha256sum > /dev/null
            ;;
    esac

    sleep 2
done

rm -f /tmp/evil_$$_* 2>/dev/null || true
echo "[ANOMALY] Done"
