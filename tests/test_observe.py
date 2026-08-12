from observe import _drop_launch_execve


def ev(syscall):
    return {"syscall": syscall, "pid": 9, "args": "", "ret": "0"}


def test_drops_initial_execve():
    events = [ev("execve"), ev("write"), ev("exit_group")]
    assert [e["syscall"] for e in _drop_launch_execve(events)] == ["write", "exit_group"]


def test_keeps_child_execve():
    events = [ev("execve"), ev("execve"), ev("exit_group")]
    assert [e["syscall"] for e in _drop_launch_execve(events)] == ["execve", "exit_group"]


def test_noop_when_first_not_execve():
    events = [ev("write"), ev("exit_group")]
    assert len(_drop_launch_execve(events)) == 2
