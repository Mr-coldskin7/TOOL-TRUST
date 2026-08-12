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
