from attest.parse import parse_strace


def test_parses_valid_lines():
    text = """\
    1 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
    1 write(1, "hi\\n", 3) = 3
    1 exit_group(0) = ?
    """
    events = parse_strace(text)
    assert len(events) == 3
    assert events[0]["pid"] == 1
    assert events[0]["syscall"] == "openat"
    assert "O_RDONLY" in events[0]["args"]
    assert events[1]["syscall"] == "write"
    assert events[1]["args"].startswith("1")
    assert events[2]["syscall"] == "exit_group"
    assert events[2]["ret"] == "?"


def test_skips_unknown_lines():
    text = """\
    1 execve("./tool", ["tool"], 0x...) = 0
    could not attach: ptrace
    ===== this is not strace =====
    2 exit_group(0) = 0
    """
    events = parse_strace(text)
    assert len(events) == 2
    assert events[0]["syscall"] == "execve"
    assert events[1]["pid"] == 2


def test_parses_error_return_values():
    """失败的 syscall 带负数返回值（-1 ENOENT），不能被丢弃——
    未遂的越界操作（connect 被拒、写文件失败）同样是要证据的。"""
    text = """\
    1 openat(AT_FDCWD, "/nope.txt", O_WRONLY|O_CREAT, 0666) = -1 ENOENT (No such file or directory)
    1 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 ECONNREFUSED (Connection refused)
    1 write(1, "hi\\n", 3) = 3
    """
    events = parse_strace(text)
    assert len(events) == 3
    assert events[0]["syscall"] == "openat"
    assert events[0]["ret"] == "-1"
    assert "O_WRONLY" in events[0]["args"]
    assert events[1]["syscall"] == "connect"
    assert events[1]["ret"] == "-1"
    # 成功调用不受影响
    assert events[2]["ret"] == "3"
