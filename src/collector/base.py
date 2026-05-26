import json
import os
import socket
import struct
from abc import ABC, abstractmethod

UNIX_SOCKET_PATH = "/tmp/ebpf_events.sock"
EVENT_FORMAT = struct.Struct("Q 2I 2i B 16s")  # 41 bytes


_registry: dict[str, type["BaseCollector"]] = {}


def register_collector(cls: type["BaseCollector"]) -> type["BaseCollector"]:
    _registry[cls.name] = cls
    return cls


def list_collectors() -> dict[str, type["BaseCollector"]]:
    return dict(_registry)


def get_collector(name: str) -> type["BaseCollector"] | None:
    return _registry.get(name)


class BaseCollector(ABC):
    name: str = "base"

    @abstractmethod
    def start(self):
        ...

    @abstractmethod
    def stop(self):
        ...

    def feed(self, event: dict):
        pass


def discover_collectors():
    import src.collector.syscall_collector  # noqa: F401
    import src.collector.process_collector  # noqa: F401
    import src.collector.network_collector  # noqa: F401
    import src.collector.resource_collector  # noqa: F401
    import src.detector.recorder  # noqa: F401


# ---- Unix socket client ----

def _unpack_event(raw: bytes) -> dict:
    ts, pid, cgroup_id, syscall_id, ret_s32, ev_type, comm = \
        EVENT_FORMAT.unpack(raw)
    comm_str = comm.rstrip(b"\x00").decode("utf-8", errors="replace")
    return {
        "timestamp_ns": ts,
        "pid": pid,
        "cgroup_id": cgroup_id,
        "syscall_id": syscall_id,
        "ret": ret_s32,
        "comm": comm_str,
        "_raw_type": ev_type,
        "_type": ev_type,
    }


def unix_socket_events(sock_path: str = UNIX_SOCKET_PATH):
    """Connect to the Unix socket server and yield parsed event dicts."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    try:
        while True:
            raw = sock.recv(EVENT_FORMAT.size, socket.MSG_WAITALL)
            if not raw:
                break
            if len(raw) < EVENT_FORMAT.size:
                break
            yield _unpack_event(raw)
    finally:
        sock.close()


class UnixSocketCollector(BaseCollector):
    """Base class for collectors that receive events via Unix socket.

    Subclasses must define `name` and `handle_event(event: dict)`.
    Run as: python3 -c 'from path.to.MyCollector import MyCollector; MyCollector.run()'
    """

    def __init__(self):
        self._running = False

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def handle_event(self, event: dict):
        raise NotImplementedError

    def feed(self, event: dict):
        self.handle_event(event)

    def run(self, sock_path: str = UNIX_SOCKET_PATH):
        discover_collectors()
        self.start()
        print(json.dumps({"collector": self.name, "status": "started", "socket": sock_path}))
        try:
            for event in unix_socket_events(sock_path):
                if not self._running:
                    break
                self.handle_event(event)
        except (ConnectionRefusedError, FileNotFoundError) as e:
            print(json.dumps({"collector": self.name, "error": str(e)}), file=__import__("sys").stderr)
        finally:
            self.stop()
