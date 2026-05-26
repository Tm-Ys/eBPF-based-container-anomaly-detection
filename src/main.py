import re
import sys

from src.collector.syscall_collector import SyscallCollector


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


def main():
    collector = SyscallCollector()

    try:
        collector.start()
        print("Listening for syscall events...", file=sys.stderr)

        for event in collector.events():
            name = syscall_name(event["syscall_id"])
            print(
                f"[{event['type']}] pid={event['pid']} "
                f"comm={event['comm']} "
                f"syscall={name} "
                f"cgroup={event['cgroup_id']} "
                f"ret={event['ret']}"
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
