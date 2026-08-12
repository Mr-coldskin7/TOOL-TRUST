from attest.reconcile import reconcile

CLAIMS = {
    "allow": ["file-read", "stdout", "stderr", "exit"],
    "deny": ["network", "file-write", "exec"],
}


def ev(class_, syscall="x", args=""):
    return {"class": class_, "syscall": syscall, "args": args}


def test_all_claimed_classes_pass():
    events = [ev("stdout", "write"), ev("file-read", "openat"), ev("exit", "exit_group")]
    assert reconcile(events, CLAIMS) == []


def test_denied_class_is_violation():
    events = [ev("network", "connect", "3, 10.0.0.1:443")]
    violations = reconcile(events, CLAIMS)
    assert len(violations) == 1
    v = violations[0]
    assert v["class"] == "network"
    assert v["reason"] == "denied"
    assert v["syscalls"] == ["connect"]
    assert "443" in v["evidence"]


def test_unclaimed_class_default_reject():
    events = [ev("perms", "chmod")]
    violations = reconcile(events, CLAIMS)
    assert len(violations) == 1
    assert violations[0]["reason"] == "not-claimed"


def test_empty_events_no_violations():
    assert reconcile([], CLAIMS) == []
