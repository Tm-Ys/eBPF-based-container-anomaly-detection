import time
from pathlib import Path
from src.collector.base import BaseCollector, register_collector

CGROUP_BASE = Path("/sys/fs/cgroup")


def _read_cgroup_cpu(cg_path: Path) -> dict:
    usage = {}
    try:
        usage_usec = int((cg_path / "cpu.stat").read_text().splitlines()[0].split()[1])
        usage["cpu_usage_usec"] = usage_usec
    except (FileNotFoundError, IndexError, ValueError):
        pass
    try:
        nr_periods = 0
        nr_throttled = 0
        for line in (cg_path / "cpu.stat").read_text().splitlines():
            if line.startswith("nr_periods "):
                nr_periods = int(line.split()[1])
            elif line.startswith("nr_throttled "):
                nr_throttled = int(line.split()[1])
        usage["nr_periods"] = nr_periods
        usage["nr_throttled"] = nr_throttled
    except (FileNotFoundError, IndexError, ValueError):
        pass
    return usage


def _read_cgroup_memory(cg_path: Path) -> dict:
    mem = {}
    try:
        current = int((cg_path / "memory.current").read_text())
        mem["memory_current_bytes"] = current
    except (FileNotFoundError, ValueError):
        pass
    try:
        swap = int((cg_path / "memory.swap.current").read_text())
        mem["memory_swap_bytes"] = swap
    except (FileNotFoundError, ValueError):
        pass
    try:
        for line in (cg_path / "memory.stat").read_text().splitlines():
            if line.startswith("anon "):
                mem["memory_anon_bytes"] = int(line.split()[1])
                break
    except (FileNotFoundError, IndexError, ValueError):
        pass
    return mem


def _find_container_cgroups() -> list[tuple[str, Path]]:
    containers = []
    for child in CGROUP_BASE.iterdir():
        name = child.name
        if name.startswith("system.") or name.startswith("."):
            continue
        if (child / "cpu.stat").exists() and (child / "memory.current").exists():
            containers.append((name, child))
    return containers


@register_collector
class ResourceCollector(BaseCollector):
    name = "resource"

    def __init__(self, interval: float = 2.0):
        self._interval = interval
        self._running = False

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def events(self):
        while self._running:
            containers = _find_container_cgroups()
            for cg_name, cg_path in containers:
                cpu = _read_cgroup_cpu(cg_path)
                mem = _read_cgroup_memory(cg_path)
                if not cpu and not mem:
                    continue
                yield {
                    "timestamp_ns": time.time_ns(),
                    "cgroup": cg_name,
                    "cpu": cpu,
                    "memory": mem,
                }
            time.sleep(self._interval)
