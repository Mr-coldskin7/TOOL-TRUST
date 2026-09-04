"""Event annotation: add behavior class (and path/mode for writes, ip/port for nets).

Consumed by bench (synthetic corpus) — real tool events
"""
from attest import rules


def drop_launch_execve(events: list[dict]) -> list[dict]:
    """Drop the tool's own launch execve (first event); keep child execves."""
    if events and events[0]["syscall"] in ("execve", "execveat"):
        return events[1:]
    return events


def annotate(events: list[dict]) -> None:
    """Annotate events with class (plus path/mode for writes, ip/port for nets).

    In-place. Then run fd routing to correct socket writes to 'network'.
    """
    for e in events:
        e["class"] = rules.classify(e["syscall"], e["args"])
        if e["class"] == "file-write":
            e["path"], e["mode"] = rules.write_attrs(e["syscall"], e["args"])
        if e["class"] == "network":
            e["ip"], e["port"] = rules.net_attrs(e["args"])
    rules.route_fds(events)