import threading
import time
from collections import defaultdict
from src.collector.base import BaseCollector, register_collector

EVENT_TYPE_SYSCALL = 0

NET_SYSCALLS = {42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
                49: "bind", 50: "listen"}

SUMMARY_INTERVAL = 5.0


@register_collector
class NetworkCollector(BaseCollector):
    name = "network"

    def __init__(self):
        self._counts: dict[str, int] = defaultdict(int)
        self._total = 0
        self._lock = threading.Lock()
        self._running = False
        self._last_summary = time.monotonic()
        self._summary_timer: threading.Thread | None = None

    def start(self):
        self._running = True
        self._last_summary = time.monotonic()
        self._summary_timer = threading.Thread(target=self._summary_loop, daemon=True)
        self._summary_timer.start()

    def stop(self):
        self._running = False

    def _summary_loop(self):
        while self._running:
            now = time.monotonic()
            if now - self._last_summary >= SUMMARY_INTERVAL:
                self._print_summary()
                self._last_summary = now
            time.sleep(0.5)
        self._print_summary()

    def _print_summary(self):
        with self._lock:
            if self._total == 0:
                return
            parts = [f"[NET-STAT] total_net_events={self._total}"]
            for name in sorted(self._counts):
                parts.append(f"{name}={self._counts[name]}")
            print(" ".join(parts), flush=True)

    def feed(self, event: dict):
        ev_type = event.get("_raw_type")
        if ev_type != EVENT_TYPE_SYSCALL:
            return
        sid = event["syscall_id"]
        if sid not in NET_SYSCALLS:
            return

        name = NET_SYSCALLS[sid]
        with self._lock:
            self._counts[name] += 1
            self._total += 1

        print(
            f"[NET] pid={event['pid']} "
            f"comm={event['comm']} "
            f"{name} "
            f"cgroup={event['cgroup_id']} "
            f"ret={event['ret']}",
            flush=True,
        )
