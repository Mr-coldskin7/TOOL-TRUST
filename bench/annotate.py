"""Event annotation: add behavior class (and path/mode for writes, ip/port for nets).

STATUS: strace-era classification layer. NOT used by any production path.
  - live enforcement gets violations from srt --debug denial events
    (attest/live.py violation_events) — no syscall parsing at runtime;
  - permission discovery is denial-based (attest/scan.py), not classify-based.
Only caller: bench/run_bench.py (synthetic corpus).

Why it stays: the corpus feeds it hand-written events, so it is graded against
ground truth that no instrument produced. An instrument cannot grade itself —
if bench input ever comes from srt's own observation, srt's blind spots become
the benchmark's blind spots. Deleting this module means losing the system's
only ruler independent of the sandbox.
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