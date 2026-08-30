from attest.rules import classify, route_fds, write_attrs


def test_write_fd_is_stdout_not_file_write():
    assert classify("write", '1, "hi\\n", 3') == "stdout"


def test_write_fd2_is_stderr():
    assert classify("write", '2, "err\\n", 4') == "stderr"


def test_write_non_stdio_is_file_write():
    assert classify("write", '3, "data", 1') == "file-write"


def test_open_readonly_is_file_read():
    assert classify("openat", 'AT_FDCWD, "/f", O_RDONLY|O_CLOEXEC') == "file-read"


def test_open_write_is_file_write():
    assert classify("openat", 'AT_FDCWD, "/f", O_WRONLY|O_CREAT') == "file-write"


def test_network():
    assert classify("connect", "3, {sa_family=AF_INET, sin_port=htons(443)}") == "network"


def test_exec_and_exit():
    assert classify("execve", '"./tool", ["tool"], 0x0') == "exec"
    assert classify("exit_group", "0") == "exit"


def test_fs_write_ops():
    assert classify("unlink", '"/tmp/x"') == "file-write"
    assert classify("mkdir", '"/tmp/d", 0755') == "file-write"


def test_perms_and_unknown():
    assert classify("chmod", '"/tmp/x", 0777') == "perms"
    assert classify("totally_unknown_syscall", "x") == "other"


def test_fork_split_from_process():
    # 创建子进程(clone/fork)是良性 fork 类；杀/调试仍是危险 process
    assert classify("clone", "CLONE_CHILD_CLEARTID") == "fork"
    assert classify("fork", "") == "fork"
    assert classify("kill", "1, SIGTERM") == "process"
    assert classify("ptrace", "PTRACE_TRACEME") == "process"


def test_other_noise_fixed():
    assert classify("rt_sigreturn", "") == "sync"
    assert classify("wait4", "-1, 0x0, 0, NULL") == "sync"
    assert classify("fadvise64", "3, 0, 0, POSIX_FADV_WILLNEED") == "fd"


def test_runtime_noise_classes():
    assert classify("mmap", "NULL, 8192, PROT_READ|PROT_WRITE") == "memory"
    assert classify("futex", "0x1234, FUTEX_WAIT") == "sync"
    assert classify("close", "3") == "fd"
    assert classify("socketpair", "AF_UNIX, SOCK_STREAM") == "fd"


def test_write_attrs_openat_trunc_is_overwrite():
    p, m = write_attrs("openat", 'AT_FDCWD, "/src/data.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666')
    assert p == "/src/data.txt"
    assert m == "overwrite"


def test_write_attrs_open_append():
    p, m = write_attrs("open", '"/tmp/log", O_WRONLY|O_APPEND')
    assert p == "/tmp/log"
    assert m == "append"


def test_write_attrs_open_create():
    p, m = write_attrs("openat", 'AT_FDCWD, "/tmp/new", O_WRONLY|O_CREAT, 0644')
    assert p == "/tmp/new"
    assert m == "create"


def test_write_attrs_write_has_no_path():
    # write(fd, "content") 内容里的引号不是路径，必须跳过
    p, m = write_attrs("write", '3, "data.txt", 9')
    assert p is None
    assert m is None


def test_write_attrs_rdonly_open_is_create_but_ok():
    # O_RDONLY 打开不该被当写意图，但 write_attrs 只在 open 带写时由调用方使用
    p, m = write_attrs("openat", 'AT_FDCWD, "/tmp/x", O_RDONLY')
    assert p == "/tmp/x"
    assert m == "create"


# ---- fd 路由：socket fd 的 write/read 归正为 network ----

def _re(pid, sc, args, ret):
    return {"pid": pid, "syscall": sc, "args": args, "ret": ret, "class": classify(sc, args)}


def test_socket_write_is_network_not_file_write():
    events = [
        _re(1, "socket", "AF_INET, SOCK_STREAM", "3"),
        _re(1, "connect", "3, {sa_family=AF_INET, sin_port=htons(443)}", "0"),
        _re(1, "write", '3, "\\x16\\x03\\x01...", 517', "517"),
        _re(1, "read", '3, "\\x16\\x03\\x01...", 832', "42"),
    ]
    route_fds(events)
    assert events[0]["class"] == "network"
    assert events[2]["class"] == "network"  # SSL 写 socket 不再当 file-write
    assert events[3]["class"] == "network"


def test_file_write_stays_file_write():
    events = [
        _re(1, "openat", 'AT_FDCWD, "/tmp/x", O_WRONLY|O_CREAT, 0644', "4"),
        _re(1, "write", '4, "data", 4', "4"),
    ]
    route_fds(events)
    assert events[1]["class"] == "file-write"


def test_dup_copies_fd_kind():
    events = [
        _re(1, "socket", "AF_INET, SOCK_STREAM", "3"),
        _re(1, "dup", "3, 5", "5"),
        _re(1, "write", '5, "x", 1', "1"),
    ]
    route_fds(events)
    assert events[1]["class"] == "fd"
    assert events[2]["class"] == "network"


def test_close_removes_fd_kind():
    events = [
        _re(1, "socket", "AF_INET, SOCK_STREAM", "3"),
        _re(1, "close", "3", "0"),
        _re(1, "write", '3, "x", 1', "1"),
    ]
    route_fds(events)
    # close 后 fd 类型未知 → 保持 classify 的保守默认(file-write)
    assert events[2]["class"] == "file-write"
