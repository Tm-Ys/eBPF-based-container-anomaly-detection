import os
import re
import socket
import sys
import struct
import threading
import time

from src.collector.base import discover_collectors, list_collectors
from src.collector.syscall_collector import SyscallCollector, EVENT_FORMAT

UNIX_SOCKET_PATH = "/tmp/ebpf_events.sock"

EVENT_TYPE_SYSCALL = 0
EVENT_TYPE_PROCESS = 1


def _build_syscall_table():
    table = {}
    paths = [
        "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
        "/usr/include/asm/unistd_64.h",
        "/usr/include/linux/syscall.h",
    ]
    for path in paths:
        try:
            with open(path) as f:
                for line in f:
                    m = re.match(r"#define\s+__NR_(\w+)\s+(\d+)", line)
                    if m:
                        table[int(m.group(2))] = m.group(1)
        except FileNotFoundError:
            continue
    return table


SYSCALL_NAMES = _build_syscall_table()


def syscall_name(nr: int) -> str:
    return SYSCALL_NAMES.get(nr, f"sys_{nr}")


def _format_syscall_event(ev: dict) -> str:
    return (
        f"[{ev['type']}] pid={ev['pid']} "
        f"comm={ev['comm']} "
        f"syscall={syscall_name(ev['syscall_id'])} "
        f"cgroup={ev['cgroup_id']} "
        f"ret={ev['ret']}"
    )


def main():
    discover_collectors()

    loader_args = []
    enabled = ["syscall", "process", "network", "resource", "recorder"]
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--rate", "--pid") and i + 1 < len(sys.argv):
            loader_args.extend([arg, sys.argv[i + 1]])
            i += 2
        elif arg in ["syscall", "process", "network", "resource", "recorder"]:
            enabled = [arg]
            i += 1
        else:
            i += 1

    collectors = {}
    for name in enabled:
        cls = list_collectors().get(name)
        if cls:
            collectors[name] = cls()

    syscall_col = collectors.get("syscall")
    if syscall_col:
        syscall_col._loader_args = loader_args

    # ---- Unix socket server ----
    sock_path = UNIX_SOCKET_PATH
    clients: list[socket.socket] = []
    clients_lock = threading.Lock()

    try:
        try:
            os.unlink(sock_path)
        except FileNotFoundError:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(sock_path)
        sock.listen(5)
        sock.settimeout(1.0)

        def accept_loop():
            while True:
                try:
                    conn, _ = sock.accept()
                    with clients_lock:
                        clients.append(conn)
                except socket.timeout:
                    continue
                except OSError:
                    break

        t_accept = threading.Thread(target=accept_loop, daemon=True)
        t_accept.start()
    except OSError as e:
        print(f"Warning: Unix socket {sock_path}: {e}", file=sys.stderr)
        sock = None

    def broadcast(raw: bytes):
        if not clients:
            return
        dead: list[socket.socket] = []
        with clients_lock:
            for c in clients:
                try:
                    c.sendall(raw)
                except OSError:
                    dead.append(c)
            for c in dead:
                clients.remove(c)

    try:
        for name in enabled:
            c = collectors.get(name)
            if c:
                c.start()

        if syscall_col:
            raw_stream = syscall_col._proc.stdout
        else:
            raw_stream = None

        print(f"Collectors: {', '.join(enabled)}", file=sys.stderr)

        if "resource" in collectors:
            def resource_loop():
                rc = collectors["resource"]
                rc.start()
                for ev in rc.events():
                    cpu = ev.get("cpu", {})
                    mem = ev.get("memory", {})
                    cpu_str = f"cpu={cpu.get('cpu_usage_usec', '?')}us"
                    mem_str = f"mem={mem.get('memory_current_bytes', '?')}B"
                    print(f"[RESOURCE] cgroup={ev['cgroup']} {cpu_str} {mem_str}", flush=True)

            t = threading.Thread(target=resource_loop, daemon=True)
            t.start()

        if raw_stream:
            while True:
                data = raw_stream.read(EVENT_FORMAT.size)
                if not data:
                    break

                broadcast(data)

                ts, pid, cgroup_id, syscall_id, ret_s32, ev_type, comm = \
                    EVENT_FORMAT.unpack(data)
                comm_str = comm.rstrip(b"\x00").decode("utf-8", errors="replace")

                base = {
                    "timestamp_ns": ts,
                    "pid": pid,
                    "cgroup_id": cgroup_id,
                    "syscall_id": syscall_id,
                    "ret": ret_s32,
                    "comm": comm_str,
                    "_raw_type": ev_type,
                }

                if ev_type == EVENT_TYPE_SYSCALL:
                    base["type"] = "EXIT" if ret_s32 != 0 else "ENTER"
                    print(_format_syscall_event(base), flush=True)

                for name in enabled:
                    c = collectors.get(name)
                    if c and c is not syscall_col:
                        c.feed(base)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutting down...", file=sys.stderr)
    finally:
        for name in enabled:
            c = collectors.get(name)
            if c:
                c.stop()
        if syscall_col:
            syscall_col.stop()
        with clients_lock:
            for c in clients:
                try:
                    c.close()
                except OSError:
                    pass
            clients.clear()
        if sock:
            sock.close()
        try:
            os.unlink(sock_path)
        except (FileNotFoundError, OSError):
            pass
        time.sleep(0.6)


if __name__ == "__main__":
    main()
