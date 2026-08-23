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


# ---- 三级对账：file-write 的 paths 白名单 + mode 覆盖 ----

WRITE_CLAIM = [
    {"class": "file-write", "mode": "create", "paths": ["/tmp/"]}
]


def test_fw_in_scope_create_passes():
    ev = {"class": "file-write", "syscall": "openat", "path": "/tmp/x", "mode": "create"}
    assert reconcile([ev], {"allow": WRITE_CLAIM, "deny": []}) == []


def test_fw_out_of_scope_is_violation():
    ev = {"class": "file-write", "syscall": "openat", "path": "/src/data.txt", "mode": "overwrite"}
    v = reconcile([ev], {"allow": WRITE_CLAIM, "deny": []})
    assert len(v) == 1
    assert v[0]["reason"] == "out-of-scope"
    assert "data.txt" in v[0]["detail"]


def test_fw_mode_exceeded_is_violation():
    # 声明 create，却 O_TRUNC（overwrite 意图）→ mode-exceeded
    ev = {"class": "file-write", "syscall": "openat", "path": "/tmp/x", "mode": "overwrite"}
    v = reconcile([ev], {"allow": WRITE_CLAIM, "deny": []})
    assert len(v) == 1
    assert v[0]["reason"] == "mode-exceeded"


def test_fw_append_exceeds_create():
    ev = {"class": "file-write", "syscall": "openat", "path": "/tmp/x", "mode": "append"}
    v = reconcile([ev], {"allow": WRITE_CLAIM, "deny": []})
    assert len(v) == 1
    assert v[0]["reason"] == "mode-exceeded"


def test_fw_overwrite_decl_covers_append_and_create():
    decl = [{"class": "file-write", "mode": "overwrite", "paths": ["/tmp/"]}]
    for m in ("create", "append", "overwrite"):
        ev = {"class": "file-write", "syscall": "openat", "path": "/tmp/x", "mode": m}
        assert reconcile([ev], {"allow": decl, "deny": []}) == []


def test_fw_pathless_event_skipped():
    # write(fd) 无路径，无法单独判定 → 放行（由同件事的 openat 判定）
    ev = {"class": "file-write", "syscall": "write", "path": None, "mode": None}
    assert reconcile([ev], {"allow": WRITE_CLAIM, "deny": []}) == []


def test_fw_without_claim_is_not_claimed():
    ev = {"class": "file-write", "syscall": "openat", "path": "/tmp/x", "mode": "create"}
    v = reconcile([ev], {"allow": ["stdout"], "deny": []})
    assert len(v) == 1
    assert v[0]["reason"] == "not-claimed"


def test_filename_prefix_not_confused_with_dir():
    # 声明 /tmp/ 前缀，但路径 /etc/tmpx 不应命中白名单（目录边界）
    decl = [{"class": "file-write", "mode": "create", "paths": ["/tmp/"]}]
    ev = {"class": "file-write", "syscall": "openat", "path": "/etc/tmpx", "mode": "create"}
    v = reconcile([ev], {"allow": decl, "deny": []})
    assert len(v) == 1
    assert v[0]["reason"] == "out-of-scope"
