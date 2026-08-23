"""syscall → class 归类规则。手写、确定性、可审计。非 LLM。"""
import re

# class 严重度（report 用）
SEVERITY = {
    "file-write": "high",
    "network": "high",
    "exec": "high",
    "perms": "high",
    "process": "medium",
    "file-read": "low",
    "stdout": "low",
    "stderr": "low",
    "exit": "low",
    "memory": "low",
    "sync": "low",
    "fd": "low",
    "other": "medium",
}

_WRITE_SYSCALLS = {"write", "writev", "pwrite", "pwritev", "sendfile"}
_READ_SYSCALLS = {
    "read",
    "readv",
    "pread",
    "preadv",
    "getdents",
    "getdents64",
    "stat",
    "fstat",
    "lstat",
    "faccessat",
    "access",
    "newfstatat",
}
_OPEN_SYSCALLS = {"open", "openat", "openat2", "creat"}
_NETWORK_SYSCALLS = {
    "connect",
    "sendto",
    "sendmsg",
    "bind",
    "socket",
    "accept",
    "accept4",
    "recvfrom",
    "recvmsg",
    "recv",
    "send",
    "sendmmsg",
    "recvmmsg",
}
_EXEC_SYSCALLS = {"execve", "execveat"}
_PROCESS_SYSCALLS = {"kill", "ptrace", "clone", "clone3", "fork", "vfork", "tgkill"}
_PERMS_SYSCALLS = {"chmod", "fchmod", "chown", "fchown", "mount", "symlink", "mknod"}
_FS_WRITE_SYSCALLS = {
    "mkdir",
    "mkdirat",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "truncate",
    "ftruncate",
}
# 运行时噪音（动态链接/堆管理/线程同步）——分到明确 class，不落 other
_MEMORY_SYSCALLS = {"mmap", "munmap", "mprotect", "brk", "mremap", "madvise", "msync", "membarrier"}
_SYNC_SYSCALLS = {
    "futex",
    "rseq",
    "set_robust_list",
    "set_tid_address",
    "prlimit64",
    "getrandom",
    "getpid",
    "gettid",
    "clock_gettime",
    "clock_getres",
    "nanosleep",
    "sched_yield",
    "arch_prctl",
    "sched_getaffinity",
    "getcpu",
    "getppid",
}
_FD_SYSCALLS = {
    "close",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
    "ioctl",
    "poll",
    "ppoll",
    "select",
    "pselect6",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "eventfd2",
    "pipe",
    "pipe2",
    "socketpair",
    "setsockopt",
    "getsockopt",
    "shutdown",
    "lseek",
    "lseek64",
}

_FD_RE = re.compile(r"^\s*(\d+)")
_PATH_RE = re.compile(r'"([^"]*)"')
# 这些 syscall 的参数第一个不是路径（write(fd,..) 的内容里可能含引号字符串）
_NO_PATH_SYSCALLS = {"write", "writev", "pwrite", "pwritev", "sendfile", "sendfile64"}

# 声明模式可接受的意图模式（create 最受限，overwrite 全接受）
MODE_ALLOWS = {
    "create": {"create"},
    "append": {"create", "append"},
    "overwrite": {"create", "append", "overwrite"},
}


def write_attrs(syscall: str, args: str) -> tuple[str | None, str | None]:
    """从写类 syscall 提取（目标路径, 意图模式）。带路径的 open 才可判定。

    模式判定（不开语言旗标，只看 strace 文本里的 flag）：
      O_TRUNC  → overwrite（清空重建）
      O_APPEND → append（追加尾部）
      其他     → create（新建）
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
    """单个 syscall 调用 → class。含 fd 判断（write(1) 是 stdout 不是 file-write）。"""
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
    if syscall in _OPEN_SYSCALLS:
        return "file-write" if _open_flags_write(args) else "file-read"
    if syscall in _NETWORK_SYSCALLS:
        return "network"
    if syscall in _EXEC_SYSCALLS:
        return "exec"
    if syscall in _PROCESS_SYSCALLS:
        return "process"
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


def _open_flags_write(args: str) -> bool:
    return "O_WRONLY" in args or "O_RDWR" in args or "O_CREAT" in args or "O_TRUNC" in args
