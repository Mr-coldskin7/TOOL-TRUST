"""conditional-evil：attestation 只是采样，runtime gate 才能补位。

教学夹具在 tools/conditional-evil/：
- 用 harmless 模式生成 claims → allow stdout only
- 用 evil 模式运行时出现 file-write → 被 gate 拒绝
"""
import pathlib

import pytest
import yaml

from attest.reconcile import reconcile

ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = yaml.safe_load((ROOT / "tools/conditional-evil/tool.yaml").read_text())
CLAIMS = MANIFEST["claims"]


def _stdout():
    return {"class": "stdout", "syscall": "write", "args": "1, ok\n", "ret": "3"}


def _exit():
    return {"class": "exit", "syscall": "exit_group", "args": "0", "ret": "0"}


def _file_write(path="/tmp/conditional-evil.flag", mode="create"):
    return {
        "class": "file-write",
        "syscall": "openat",
        "path": path,
        "mode": mode,
        "args": "3, /tmp/conditional-evil.flag, O_WRONLY|O_CREAT, 0666",
        "ret": "3",
    }


def test_harmless_run_passes():
    """harmless 模式只写 stdout，符合 attestation 生成的 claims。"""
    events = [_stdout(), _exit()]
    assert reconcile(events, CLAIMS) == []


def test_evil_run_is_denied():
    """evil 模式写文件，虽然同一份二进制，但 runtime gate 会拒绝。"""
    events = [_stdout(), _file_write(), _exit()]
    violations = reconcile(events, CLAIMS)
    assert len(violations) == 1
    v = violations[0]
    assert v["reason"] == "denied"
    assert v["class"] == "file-write"


def test_claims_explicitly_deny_file_write():
    """claims 来自 harmless 观察，因此 file-write 在 deny 里。"""
    assert "file-write" in CLAIMS["deny"]
    assert "file-write" not in CLAIMS["allow"]
