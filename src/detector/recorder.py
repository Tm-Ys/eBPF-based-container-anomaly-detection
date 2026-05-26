import csv
import threading
import time
from datetime import datetime
from pathlib import Path

from src.collector.base import BaseCollector, register_collector

WINDOW_SEC = 1.0
WINDOW_NS = int(WINDOW_SEC * 1_000_000_000)

EVENT_TYPE_SYSCALL = 0
EVENT_TYPE_PROCESS = 1

SYSCALL_CATEGORIES = {
    "file_read": {0, 17, 19},
    "file_write": {1, 18, 20},
    "file_open": {2, 257, 258},
    "file_close": {3},
    "file_meta": {4, 5, 6, 8},
    "file_sync": {74, 75},
    "mem_mmap": {9, 10, 11, 12, 25},
    "net_sock": {41, 49, 50, 54, 55},
    "net_io": {42, 43, 44, 45, 46, 47, 48},
    "proc_create": {56, 57, 58, 59},
    "proc_exit_wait": {60, 61},
    "proc_signal": {62, 200, 234},
    "ipc": {22, 293, 193, 198, 199, 194, 195, 196, 197},
    "futex": {202},
    "clock": {35, 96, 201, 228},
    "poll_epoll": {7, 23, 24},
}

CATEGORY_NAMES = sorted(SYSCALL_CATEGORIES.keys()) + ["other"]

EVENT_CSV_COLUMNS = [
    "ts_ns", "ts_iso", "cgroup_id", "type",
    "total_events",
] + [f"cat_{n}" for n in CATEGORY_NAMES] + [
    "proc_exec", "proc_fork", "proc_exit",
]

RAW_EVENT_COLUMNS = [
    "ts_ns", "pid", "cgroup_id", "syscall_id", "ret", "raw_type", "comm",
]

RESOURCE_CSV_COLUMNS = [
    "timestamp_ns", "timestamp_iso", "cgroup_name",
    "cpu_usage_usec", "nr_periods", "nr_throttled",
    "memory_current_bytes", "memory_swap_bytes", "memory_anon_bytes",
]

CGROUP_BASE = Path("/sys/fs/cgroup")


def _categorize_syscall(sid: int) -> str:
    for name, ids in SYSCALL_CATEGORIES.items():
        if sid in ids:
            return name
    return "other"


def _read_cgroup_cpu(cg_path: Path) -> dict:
    usage = {}
    try:
        for line in (cg_path / "cpu.stat").read_text().splitlines():
            if line.startswith("usage_usec "):
                usage["cpu_usage_usec"] = int(line.split()[1])
            elif line.startswith("nr_periods "):
                usage["nr_periods"] = int(line.split()[1])
            elif line.startswith("nr_throttled "):
                usage["nr_throttled"] = int(line.split()[1])
    except (FileNotFoundError, ValueError):
        pass
    return usage


def _read_cgroup_memory(cg_path: Path) -> dict:
    mem = {}
    try:
        mem["memory_current_bytes"] = int((cg_path / "memory.current").read_text())
    except (FileNotFoundError, ValueError):
        pass
    try:
        mem["memory_swap_bytes"] = int((cg_path / "memory.swap.current").read_text())
    except (FileNotFoundError, ValueError):
        pass
    try:
        for line in (cg_path / "memory.stat").read_text().splitlines():
            if line.startswith("anon "):
                mem["memory_anon_bytes"] = int(line.split()[1])
                break
    except (FileNotFoundError, ValueError):
        pass
    return mem


def _find_container_cgroups() -> list[tuple[str, Path]]:
    containers = []
    for child in CGROUP_BASE.iterdir():
        name = child.name
        if name.startswith("."):
            continue
        if (child / "cpu.stat").exists() and (child / "memory.current").exists():
            containers.append((name, child))
    for scope in (CGROUP_BASE / "system.slice").glob("docker-*.scope"):
        if (scope / "cpu.stat").exists() and (scope / "memory.current").exists():
            containers.append((scope.name, scope))
    return containers


@register_collector
class DataRecorder(BaseCollector):
    name = "recorder"

    def __init__(self, output_dir: str = "data"):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._raw_csv = self._output_dir / f"raw_{ts}.csv"
        self._win_csv = self._output_dir / f"windows_{ts}.csv"
        self._resource_csv = self._output_dir / f"resources_{ts}.csv"

        self._raw_fh = open(self._raw_csv, "w", newline="")
        self._raw_writer = csv.DictWriter(self._raw_fh, fieldnames=RAW_EVENT_COLUMNS)
        self._raw_writer.writeheader()

        self._win_fh = open(self._win_csv, "w", newline="")
        self._win_writer = csv.DictWriter(self._win_fh, fieldnames=EVENT_CSV_COLUMNS)
        self._win_writer.writeheader()

        self._resource_fh = open(self._resource_csv, "w", newline="")
        self._resource_writer = csv.DictWriter(self._resource_fh, fieldnames=RESOURCE_CSV_COLUMNS)
        self._resource_writer.writeheader()

        self._lock = threading.Lock()
        self._running = False
        self._windows: dict[int, dict] = {}
        self._window_ids: dict[int, int] = {}

        self._res_thread: threading.Thread | None = None

    def start(self):
        self._running = True
        self._res_thread = threading.Thread(target=self._resource_loop, daemon=True)
        self._res_thread.start()

    def stop(self):
        self._running = False
        self._flush_all()
        self._raw_fh.close()
        self._win_fh.close()
        self._resource_fh.close()

    def _resource_loop(self):
        while self._running:
            containers = _find_container_cgroups()
            now_ns = time.time_ns()
            for cg_name, cg_path in containers:
                cpu = _read_cgroup_cpu(cg_path)
                mem = _read_cgroup_memory(cg_path)
                if not cpu and not mem:
                    continue
                row = {
                    "timestamp_ns": now_ns,
                    "timestamp_iso": datetime.fromtimestamp(
                        now_ns / 1_000_000_000
                    ).isoformat(),
                    "cgroup_name": cg_name,
                }
                row.update(cpu)
                row.update(mem)
                with self._lock:
                    self._resource_writer.writerow(row)
                    self._resource_fh.flush()
            time.sleep(2.0)

    @staticmethod
    def _init_window(win_id: int, cg: int):
        row = {
            "ts_ns": win_id * WINDOW_NS,
            "ts_iso": datetime.fromtimestamp(win_id).isoformat(),
            "cgroup_id": cg,
            "type": 0,
            "total_events": 0,
            "proc_exec": 0,
            "proc_fork": 0,
            "proc_exit": 0,
        }
        for cat in CATEGORY_NAMES:
            row[f"cat_{cat}"] = 0
        return row

    def _flush_all(self):
        for w in self._windows.values():
            self._win_writer.writerow(w)
        self._windows.clear()
        self._window_ids.clear()
        self._win_fh.flush()

    def feed(self, event: dict):
        ts = event["timestamp_ns"]
        cg = event.get("cgroup_id", 0)
        ev_type = event.get("_raw_type", EVENT_TYPE_SYSCALL)
        win_id = ts // WINDOW_NS

        raw_row = {
            "ts_ns": ts,
            "pid": event.get("pid", 0),
            "cgroup_id": cg,
            "syscall_id": event.get("syscall_id", -1),
            "ret": event.get("ret", 0),
            "raw_type": ev_type,
            "comm": event.get("comm", ""),
        }

        with self._lock:
            self._raw_writer.writerow(raw_row)

            prev_win_id = self._window_ids.get(cg)
            if prev_win_id is not None and prev_win_id != win_id:
                prev = self._windows.pop(cg)
                self._win_writer.writerow(prev)
                self._win_fh.flush()

            if cg not in self._windows:
                self._windows[cg] = self._init_window(win_id, cg)
                self._window_ids[cg] = win_id

            w = self._windows[cg]
            w["total_events"] += 1

            if ev_type == EVENT_TYPE_SYSCALL:
                sid = event.get("syscall_id", -1)
                cat = _categorize_syscall(sid)
                w[f"cat_{cat}"] += 1
            elif ev_type == EVENT_TYPE_PROCESS:
                subtype = event.get("syscall_id", -1)
                if subtype == 0:
                    w["proc_exec"] += 1
                elif subtype == 1:
                    w["proc_fork"] += 1
                elif subtype == 2:
                    w["proc_exit"] += 1
