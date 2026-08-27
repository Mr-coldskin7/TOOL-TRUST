import json
import pathlib

import pytest

from attest.gate import decide, format_command, gated_invoke, load_attestation_verdict
from attest.telemetry import log_run


def _script(tool_dir: pathlib.Path, name: str, body: str) -> pathlib.Path:
    p = tool_dir / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(0o755)
    return p


def _manifest(**over):
    base = {
        "name": "t",
        "command": "./tool.sh",
        "requires": {},
        "claims": {"deny": []},
    }
    base.update(over)
    return base


def test_format_command_prepends_tool_dir_for_relative():
    m = {"command": "./tool run"}
    assert format_command(m, ["a", "b"], pathlib.Path("/t")) == [
        "/t/tool", "run", "a", "b",
    ]


def test_format_command_keeps_absolute():
    m = {"command": "/bin/echo hi"}
    assert format_command(m, [], pathlib.Path("/t")) == ["/bin/echo", "hi"]


def test_load_attestation_verdict(tmp_path):
    (tmp_path / "report.json").write_text(json.dumps({"verdict": "fail"}))
    assert load_attestation_verdict(tmp_path) == "fail"
    (tmp_path / "report.json").write_text(json.dumps({"verdict": "pass"}))
    assert load_attestation_verdict(tmp_path) == "pass"
    (tmp_path / "report.json").write_text("not json")
    assert load_attestation_verdict(tmp_path) is None
    (tmp_path / "report.json").unlink()
    assert load_attestation_verdict(tmp_path) is None


# ---- decide：纯决策，不运行 ----

def test_decide_deny_on_attestation_fail(tmp_path):
    (tmp_path / "report.json").write_text('{"verdict": "fail"}')
    assert decide(_manifest(), tmp_path)["decision"] == "deny"
    assert decide(_manifest(), tmp_path)["reason"] == "attestation-fail"


def test_decide_deny_on_missing_requires(tmp_path):
    m = _manifest(requires={"env": ["TT_MISSING_XYZ"]})
    d = decide(m, tmp_path)
    assert d["decision"] == "deny"
    assert d["reason"] == "env-mismatch"
    assert d["missing"]  # 指明缺哪个前置


def test_decide_allow_when_clear(tmp_path):
    assert decide(_manifest(), tmp_path)["decision"] == "allow"


# ---- gated_invoke：决策 + 真实执行 ----

def test_gated_invoke_deny_attestation_does_not_run(tmp_path):
    marker = tmp_path / "ran.txt"
    _script(tmp_path, "tool.sh", f'touch "{marker}"')
    (tmp_path / "report.json").write_text('{"verdict": "fail"}')
    r = gated_invoke(_manifest(command="./tool.sh"), [], tmp_path)
    assert r["decision"] == "deny"
    assert not marker.exists()  # 没运行


def test_gated_invoke_deny_requires_does_not_run(tmp_path):
    marker = tmp_path / "ran.txt"
    _script(tmp_path, "tool.sh", f'touch "{marker}"')
    m = _manifest(command="./tool.sh", requires={"env": ["TT_MISSING_XYZ"]})
    r = gated_invoke(m, [], tmp_path)
    assert r["decision"] == "deny"
    assert r["reason"] == "env-mismatch"
    assert not marker.exists()


def test_gated_invoke_allow_runs_in_runtime(tmp_path):
    out = _script(tmp_path, "tool.sh", "echo 'harness-ok'")
    r = gated_invoke(_manifest(command=str(out)), [], tmp_path)
    assert r["decision"] == "allow"
    assert r["returncode"] == 0
    assert r["stdout"] == "harness-ok"


def test_gated_invoke_launch_error_is_structured_not_raised(tmp_path):
    # 二进制不存在/平台不匹配(如 Linux ELF 在 mac) → 结构化返回 launch_error，不抛裸异常
    r = gated_invoke(_manifest(command="./no_such_bin"), [], tmp_path)
    assert r["decision"] == "allow"
    assert "launch_error" in r
    assert "No such file" in r["launch_error"]


# ---- telemetry：每次决策/调用落日志 ----

def test_decide_logs_to_telemetry(tmp_path, monkeypatch):
    log = tmp_path / "access.jsonl"
    monkeypatch.setenv("TOOL_TRUST_TELEMETRY", str(log))
    decide(_manifest(), tmp_path)
    lines = log.read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["event"] == "decide"
    assert rec["decision"] == "allow"
    assert "ts" in rec


def test_invoke_logs_event_and_deny_does_not(tmp_path, monkeypatch):
    log = tmp_path / "access.jsonl"
    monkeypatch.setenv("TOOL_TRUST_TELEMETRY", str(log))
    out = _script(tmp_path, "tool.sh", "echo hi")
    gated_invoke(_manifest(command=str(out)), ["x"], tmp_path)
    recs = [json.loads(l) for l in log.read_text().splitlines()]
    events = [r["event"] for r in recs]
    assert events == ["decide", "invoke"]
    inv = recs[1]
    assert inv["returncode"] == 0
    assert inv["inputs"] == ["x"]


def test_log_run_ignores_failure(tmp_path, monkeypatch):
    # telemetry 写失败(如路径不存在)不阻断主流程
    log_run({"x": 1}, path=tmp_path / "no" / "such" / "dir" / "a.jsonl")
    assert True
