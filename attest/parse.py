"""strace 文本 → 结构化事件。确定性正则解析，不赌 strace JSON 版本。"""
import re

# 典型 strace 行：`12345 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3`
_EVENT_RE = re.compile(
    r"^\s*(?P<pid>\d+)\s+"
    r"(?P<syscall>[A-Za-z0-9_]+)\((?P<args>.*)\)"
    r"\s*=\s*(?P<ret>[?0-9]+(?:,\s*[0-9]+)*)"
)


def parse_strace(text: str) -> list[dict]:
    """strace 输出 → 事件列表。未知格式行跳过（strace 跨版本差异）。"""
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
