import json
import pathlib

from attest.gate import decide, format_command, gated_invoke, load_attestation_verdict


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
