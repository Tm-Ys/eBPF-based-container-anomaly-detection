import struct
import subprocess
import sys
from pathlib import Path

from src.collector.base import BaseCollector

EVENT_FORMAT = struct.Struct("Q 2I 2i 16s")
BASE_DIR = Path(__file__).resolve().parent.parent.parent


class SyscallCollector(BaseCollector):
    name = "syscall"

    def __init__(self):
        self._proc: subprocess.Popen | None = None

    def start(self):
        loader_path = BASE_DIR / "build" / "loader"
        if not loader_path.exists():
            raise FileNotFoundError(
                f"Loader not found at {loader_path}. Run 'make' first."
            )

        self._proc = subprocess.Popen(
            [str(loader_path)],
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
        )

    def stop(self):
        if self._proc:
            self._proc.terminate()
            self._proc.wait()
            self._proc = None

    def events(self):
        if not self._proc or not self._proc.stdout:
            return

        while True:
            data = self._proc.stdout.read(EVENT_FORMAT.size)
            if not data:
                break

            ts, pid, cgroup_id, syscall_id, ret_s32, comm = EVENT_FORMAT.unpack(data)
            yield {
                "timestamp_ns": ts,
                "pid": pid,
                "cgroup_id": cgroup_id,
                "syscall_id": syscall_id,
                "ret": ret_s32,
                "comm": comm.rstrip(b"\x00").decode("utf-8", errors="replace"),
                "type": "EXIT" if ret_s32 != 0 else "ENTER",
            }
