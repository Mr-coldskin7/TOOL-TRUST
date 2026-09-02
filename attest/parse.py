"""strace text → structured events.

Deterministic regex parsing; does not depend on strace JSON output versions.
Each event: {pid, syscall, args, ret}. Failed calls (negative return) are kept —
a blocked attempt (rejected connect, failed open) is evidence too.
"""
import re

# Typical line: `12345 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3`
# Failed call:  `12345 openat(...) = -1 ENOENT (No such file or directory)`
# Negative returns must be captured — unsuccessful out-of-scope attempts are evidence.
_EVENT_RE = re.compile(
    r"^\s*(?P<pid>\d+)\s+"
    r"(?P<syscall>[A-Za-z0-9_]+)\((?P<args>.*)\)"
    r"\s*=\s*(?P<ret>-?[?0-9]+(?:,\s*[0-9]+)*)"
)


def parse_strace(text: str) -> list[dict]:
    """Parse strace output into a list of event dicts (unknown lines skipped).

    Args:
      text: str: 

    Returns:

    """
    events = []
    for line in text.splitlines():
        m = _EVENT_RE.match(line)
        if not m:
            continue
        events.append(
            {
                "pid": int(m.group("pid")),
                "syscall": m.group("syscall"),
                "args": m.group("args"),
                "ret": m.group("ret"),
            }
        )
    return events