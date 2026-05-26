from src.collector.base import BaseCollector, register_collector

EVENT_TYPE_PROCESS = 1

PROCESS_EVENT_NAMES = {0: "exec", 1: "fork", 2: "exit"}

PROCESS_EVENT_INTERESTING = {0, 1, 2}


def process_event_name(subtype: int) -> str:
    return PROCESS_EVENT_NAMES.get(subtype, f"proc_{subtype}")


@register_collector
class ProcessCollector(BaseCollector):
    name = "process"

    def start(self):
        pass

    def stop(self):
        pass

    def feed(self, event: dict):
        ev_type = event.get("_raw_type")
        if ev_type != EVENT_TYPE_PROCESS:
            return
        subtype = event["syscall_id"]
        if subtype not in PROCESS_EVENT_INTERESTING:
            return

        name = process_event_name(subtype)
        extra = ""
        if subtype == 1 and event["ret"]:
            extra = f" child_pid={event['ret']}"

        print(
            f"[PROCESS] pid={event['pid']} "
            f"comm={event['comm']} "
            f"event={name} "
            f"cgroup={event['cgroup_id']}"
            f"{extra}",
            flush=True,
        )
