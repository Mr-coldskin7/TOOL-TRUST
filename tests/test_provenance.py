"""provenance 回归测试：身份校验三闸 + 不影响无身份证工具。

场景（全部构造目录+文件，不碰 Docker/真实工具）:
  - 稳定哈希:同目录两次一致;无关文件(报告/声明/产物)不参与
  - tampered:源码被改 → gate deny(tampered)
  - stale:有身份证但缓存报告无快照 → deny(stale),重新 --save-report 后 allow
  - stale-version:报告快照版本 ≠ 声明版本 → deny(stale-version)
  - 无 provenance:旧工具不受影响(allow 或按原逻辑)
"""
import json
import pathlib

import pytest

from attest import provenance
from attest.gate import decide

MANIFEST_BASE = {
    "name": "prov-demo",
    "description": "provenance test",
    "build": "true",
    "command": "sh run.sh",
}


@pytest.fixture
def tool_dir(tmp_path):
    (tmp_path / "run.sh").write_text("#!/bin/sh\necho hello\n")
    return tmp_path


def _manifest(version="1.0", with_hash=True, **kw):
    m = {**MANIFEST_BASE, "provenance": {"source": "demo", "version": version}}
    if with_hash:
        m["provenance"]["hash"] = provenance.compute_tool_hash(
            pathlib.Path(__file__).parent.parent / "tools"
        ) if kw.pop("use_real_dir", False) else "PENDING"
    m.update(kw)
    return m


def _write_report(tool_dir, *, version="1.0", with_prov=True):
    r = {"tool": "prov-demo", "verdict": "pass", "claims": {}, "observed": {},
         "violations": []}
    if with_prov:
        r["provenance"] = {"version": version, "hash": "any", "at": "t"}
    (tool_dir / "report.json").write_text(json.dumps(r))


def test_hash_is_stable_and_directory_scoped(tmp_path):
    (tmp_path / "a.py").write_text("x\n")
    h1 = provenance.compute_tool_hash(tmp_path)
    h2 = provenance.compute_tool_hash(tmp_path)
    (tmp_path / "a.py").write_text("x\n")  # 同内容
    assert provenance.compute_tool_hash(tmp_path) == h1 == h2


def test_hash_excludes_declaration_and_artifacts(tmp_path):
    (tmp_path / "run.sh").write_text("echo hi\n")
    base = provenance.compute_tool_hash(tmp_path)
    # tool.yaml/report.json/测试产物不改变哈希
    (tmp_path / "tool.yaml").write_text("name: x\n")
    (tmp_path / "report.json").write_text("{}")
    (tmp_path / "test").write_bytes(b"\x7fELF")
    assert provenance.compute_tool_hash(tmp_path) == base


def test_hash_changes_when_source_changes(tool_dir):
    h1 = provenance.compute_tool_hash(tool_dir)
    (tool_dir / "run.sh").write_text("#!/bin/sh\necho pwned\n")
    assert provenance.compute_tool_hash(tool_dir) != h1


def test_tampered_source_is_denied(tool_dir):
    _write_report(tool_dir, version="1.0")  # 报告与版本匹配,让闸 3 走到 hash 检查
    m = _manifest(version="1.0", with_hash=False)
    m["provenance"]["hash"] = "0" * 64  # 声明的身份证哈希与真实源码不符
    d = decide(m, tool_dir)
    assert d["decision"] == "deny" and d["reason"] == "tampered"


def test_stale_without_snapshot_is_denied(tool_dir):
    _write_report(tool_dir, with_prov=False)  # 旧报告:无 provenance 快照
    m = _manifest(with_hash=False)
    d = decide(m, tool_dir)
    assert d["decision"] == "deny" and d["reason"] == "stale"


def test_version_bump_invalidates(tool_dir):
    _write_report(tool_dir, version="1.0")
    m = _manifest(version="1.1", with_hash=False)  # 升级,但报告还是 1.0
    d = decide(m, tool_dir)
    assert d["decision"] == "deny" and d["reason"] == "stale-version"


def test_matching_provenance_allows(tool_dir):
    _write_report(tool_dir, version="1.0")
    m = _manifest(version="1.0", with_hash=False)
    d = decide(m, tool_dir)
    assert d["decision"] == "allow"


def test_no_provenance_unchanged(tool_dir):
    """无身份证的存量工具:不因闸 3 改变行为(无 report 也 allow)。"""
    m = {**MANIFEST_BASE}
    assert decide(m, tool_dir)["decision"] == "allow"


def test_snapshot_records_declared_values():
    m = {"provenance": {"source": "s", "version": "2.0", "hash": "abc"}}
    snap = provenance.snapshot(m)
    assert snap["source"] == "s" and snap["version"] == "2.0" and snap["hash"] == "abc"
    assert "at" in snap
    assert provenance.snapshot({}) is None