from attest.rules import classify, write_attrs


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
