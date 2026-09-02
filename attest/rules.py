"""syscall → behavior class mapping. Hand-written, deterministic, auditable (not LLM).

Terminology: a "class" is the abstract behavior bucket a syscall maps to
(e.g. file-write, network, exec). The event pipeline uses these classes for
claims reconciliation. Severity drives report display.
"""
import re

# Severity per class (used in reports).
SEVERITY = {
    "file-write": "high",
    "network": "high",
    "exec": "high",
    "perms": "high",
    "process": "medium",
    "fork": "low",
    "file-read": "low",
    "stdout": "low",
    "stderr": "low",
    "exit": "low",
    "memory": "low",
    "sync": "low",
    "fd": "low",
    "other": "medium",
}

_WRITE_SYSCALLS = {
    "write", "writev", "pwrite", "pwritev", "sendfile",
    "pwrite64", "sendfile64",  # 64-bit variants (amd64 glibc noise)
}
_READ_SYSCALLS = {
    "read", "readv", "pread", "preadv",
    "pread64",  # amd64 runtime noise: glibc calls pread64 instead of pread
    "getdents", "getdents64",
    "stat", "fstat", "lstat", "faccessat", "access", "newfstatat",
}
_OPEN_SYSCALLS = {"open", "openat", "openat2", "creat"}
_NETWORK_SYSCALLS = {
    "connect", "sendto", "sendmsg", "bind", "socket",
    "accept", "accept4", "recvfrom", "recvmsg", "recv",
    "send", "sendmmsg", "recvmmsg",
}
_EXEC_SYSCALLS = {"execve", "execveat"}
# Dangerous process ops (kill/debug/inject). Child creation (fork/clone) is "fork".
_PROCESS_SYSCALLS = {"kill", "ptrace", "tgkill"}
# Child processes: required by shell pipelines/scripts; benign (traced via -f).
_FORK_SYSCALLS = {"clone", "clone3", "fork", "vfork"}
_PERMS_SYSCALLS = {"chmod", "fchmod", "chown", "fchown", "mount", "symlink", "mknod"}
_FS_WRITE_SYSCALLS = {
    "mkdir", "mkdirat", "unlink", "unlinkat", "rename", "renameat", "renameat2",
    "truncate", "ftruncate",
}
# Runtime noise (dynamic linking / heap / thread sync) — classified, not "other".
_MEMORY_SYSCALLS = {
    "mmap", "munmap", "mprotect", "brk", "mremap", "madvise", "msync", "membarrier",
}
_SYNC_SYSCALLS = {
    "futex", "rseq", "set_robust_list", "set_tid_address", "prlimit64",
    "getrandom", "getpid", "gettid", "clock_gettime", "clock_getres",
    "nanosleep", "sched_yield", "arch_prctl", "sched_getaffinity", "getcpu",
    "getppid", "rt_sigreturn", "wait4", "waitid",
    # signal handling + identity/system info (python3 runtime, security noise)
    "rt_sigaction", "rt_sigprocmask", "sigaction", "sigprocmask",
    "getuid", "geteuid", "getgid", "getegid", "uname",
}
# File-system metadata probes (read-like, not writes).
_FS_INSPECT = {"getcwd", "readlinkat", "readlink"}
_FD_SYSCALLS = {
    "close", "dup", "dup2", "dup3", "fcntl", "ioctl",
    "poll", "ppoll", "select", "pselect6", "epoll_create1", "epoll_ctl", "epoll_wait",
    "eventfd2", "pipe", "pipe2", "socketpair", "setsockopt", "getsockopt", "shutdown",
    "lseek", "lseek64", "getsockname", "getpeername", "fadvise64", "fadvise64_64",
}

_FD_RE = re.compile(r"^\s*(\d+)")
_PATH_RE = re.compile(r'"([^"]*)"')
# Network target: strace connect shows {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}
_SIN_PORT_RE = re.compile(r"sin_port=htons\((\d+)\)")
_SIN_ADDR_RE = re.compile(r'inet_addr\("([^"]+)"\)')
# These syscalls' first arg is NOT a path (write content may contain quoted strings).
_NO_PATH_SYSCALLS = {"write", "writev", "pwrite", "pwritev", "sendfile", "sendfile64"}

# fd routing: syscalls returning an fd / consuming an fd as first arg.
_FD_RETURN = {"socket", "socketpair", "open", "openat", "openat2", "creat"}
_FD_DUP = {"dup", "dup2", "dup3"}
_FD_OPS = {
    "write", "writev", "pwrite", "pwritev", "sendfile",
    "read", "readv", "pread", "preadv",
    "recv", "recvfrom", "recvmsg", "recvmmsg",
    "send", "sendto", "sendmsg", "sendmmsg",
}


def _first_fd(args: str) -> int | None:
    """Return the leading fd number in args, or None."""
    m = _FD_RE.match(args or "")
    return int(m.group(1)) if m else None


def _ret_fd(ret: str) -> int | None:
    """Return the returned fd on success; None for '?'/negative/unknown."""
    if not ret:
        return None
    r = ret.split()[0]
    if r == "?" or r.startswith("-") or not r.isdigit():
        return None
    return int(r)


# Declared modes and the actual intents each covers (create is strictest).
MODE_ALLOWS = {
    "create": {"create"},
    "append": {"create", "append"},
    "overwrite": {"create", "append", "overwrite"},
}


def write_attrs(syscall: str, args: str) -> tuple[str | None, str | None]:
    """Extract (target path, intent mode) from a write-class syscall.

    Mode is judged from strace text flags only (no language-specific flags):
    O_TRUNC → overwrite, O_APPEND → append, else → create.
    """
    if syscall in _NO_PATH_SYSCALLS:
        return None, None
    m = _PATH_RE.search(args)
    if m is None:
        return None, None
    path = m.group(1)
    if "O_TRUNC" in args:
        return path, "overwrite"
    if "O_APPEND" in args:
        return path, "append"
    return path, "create"


def classify(syscall: str, args: str) -> str:
    """Classify a single syscall call into a behavior class.

    Includes fd dispatch: write(1) is stdout, write(2) is stderr,
    everything else handled by the write/read sets below.
    """
    if syscall in {"exit", "exit_group"}:
        return "exit"
    if syscall in _WRITE_SYSCALLS:
        m = _FD_RE.match(args)
        if m:
            fd = int(m.group(1))
            if fd == 1:
                return "stdout"
            if fd == 2:
                return "stderr"
        return "file-write"
    if syscall in _READ_SYSCALLS:
        return "file-read"
    if syscall in _FS_INSPECT:
        return "file-read"
    if syscall in _OPEN_SYSCALLS:
        return "file-write" if _open_flags_write(args) else "file-read"
    if syscall in _NETWORK_SYSCALLS:
        return "network"
    if syscall in _EXEC_SYSCALLS:
        return "exec"
    if syscall in _PROCESS_SYSCALLS:
        return "process"
    if syscall in _FORK_SYSCALLS:
        return "fork"
    if syscall in _PERMS_SYSCALLS:
        return "perms"
    if syscall in _FS_WRITE_SYSCALLS:
        return "file-write"
    if syscall in _MEMORY_SYSCALLS:
        return "memory"
    if syscall in _SYNC_SYSCALLS:
        return "sync"
    if syscall in _FD_SYSCALLS:
        return "fd"
    return "other"


def net_attrs(args: str) -> tuple[str | None, int | None]:
    """Extract (target IP, port) from network syscall args; None if unparseable."""
    m = _SIN_ADDR_RE.search(args or "")
    ip = m.group(1) if m else None
    mp = _SIN_PORT_RE.search(args or "")
    port = int(mp.group(1)) if mp else None
    return ip, port


def route_fds(events: list[dict]) -> None:
    """Resolve fd→kind (stateful) and re-classify fd operations.

    Fixes a real finding: SSL writes to a socket fd (write(3,...), fd neither 1
    nor 2) were misread as file-write. After tracking: socket()=3 → 3:net,
    open()=4 → 4:file, dup/close maintained. Then write/read(3)→network,
    write/read(4)→file. One table per pid (-f); fork inheritance skipped (edge).
    """
    tables: dict[int, dict[int, str]] = {}
    for e in events:
        # fd 1/2 are the process's std streams; dup'ing them keeps stdout/stderr.
        ctx = tables.setdefault(e["pid"], {1: "stdout", 2: "stderr"})
        sc, args, ret = e["syscall"], e.get("args") or "", e.get("ret")
        fd = _ret_fd(ret)
        if sc in _FD_RETURN and fd is not None:
            ctx[fd] = "net" if sc in ("socket", "socketpair") else "file"
        elif sc in _FD_DUP:
            m = re.match(r"^\s*(\d+),\s*(\d+)", args)
            if m:
                src, dst = int(m.group(1)), int(m.group(2))
                ctx[dst] = ctx.get(src, "unknown")
        elif sc == "close":
            f = _first_fd(args)
            if f is not None:
                ctx.pop(f, None)

        if sc in _FD_OPS and e["class"] in ("file-write", "file-read", "network"):
            f = _first_fd(args)
            if f is not None:
                k = ctx.get(f, "unknown")
                if k == "net":
                    e["class"] = "network"
                elif k == "file":
                    e["class"] = "file-write" if sc in {"write", "writev", "pwrite", "pwritev", "sendfile"} else "file-read"
                elif k in ("stdout", "stderr"):
                    e["class"] = k  # write(3) after dup2(1,3) is still stdout


def _open_flags_write(args: str) -> bool:
    """True when open args request write access."""
    return "O_WRONLY" in args or "O_RDWR" in args or "O_CREAT" in args or "O_TRUNC" in args