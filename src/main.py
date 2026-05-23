import sys

from src.collector.syscall_collector import SyscallCollector

SYSCALL_NAMES = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
    9: "mmap", 10: "mprotect", 11: "munmap",
    12: "brk", 14: "rt_sigprocmask",
    39: "getpid", 56: "clone", 57: "fork", 59: "execve",
    62: "kill", 63: "uname", 78: "getdents",
    101: "ptrace", 102: "getuid", 110: "getppid",
    137: "statfs", 138: "fstatfs",
    257: "openat", 262: "newfstatat",
    290: "process_vm_readv", 291: "process_vm_writev",
    318: "getrandom",
    332: "statx",
    42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
    49: "bind", 50: "listen",
    165: "mount", 166: "umount2",
}


def syscall_name(nr: int) -> str:
    return SYSCALL_NAMES.get(nr, f"sys_{nr}")


def main():
    collector = SyscallCollector()

    try:
        collector.start()
        print("Listening for syscall events...", file=sys.stderr)

        for event in collector.events():
            name = syscall_name(event["syscall_id"])
            print(
                f"[SYSCALL] pid={event['pid']} "
                f"comm={event['comm']} "
                f"syscall={name} "
                f"cgroup={event['cgroup_id']}"
            )

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutting down...", file=sys.stderr)
    finally:
        collector.stop()


if __name__ == "__main__":
    main()
