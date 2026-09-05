"""Authorization layer tests: state machine, approve_core, revoke (no srt needed)."""
import json
import pathlib

import yaml

from attest import authorize


def _mini(tool_dir: pathlib.Path, *, with_claims=True) -> dict:
    claims = {"origin": "author-built", "allow": ["stdout", "exit", "network"], "deny": []}
    m = {"name": "mini-x", "claims": claims, "command": "sh run.sh",
         "sandbox": {"srt_settings": "srt-settings.json"}}
    (tool_dir / "run.sh").write_text("#!/bin/sh\necho hi\n")
    (tool_dir / "tool.yaml").write_text(yaml.safe_dump(m))
    (tool_dir / "srt-settings.json").write_text(json.dumps({
        "network": {"allowedDomains": ["a.example.com"], "deniedDomains": []},
        "filesystem": {"allowWrite": ["/tmp"], "denyWrite": [".env"], "denyRead": ["~/.ssh"]}}))
    return m


def test_status_unmanaged_then_approved(tmp_path):
    d = tmp_path / "mini-x"
    d.mkdir()
    m = _mini(d)
    st = authorize.tool_state(m, d)
    assert st["state"] == "unmanaged"
    authorize.approve_core(m, d)
    st2 = authorize.tool_state(m, d)
    assert st2["state"] == "approved"
    assert "a.example.com" in st2["network"]
    assert "/tmp" in st2["writes"]


def test_approve_locks_settings_content(tmp_path):
    d = tmp_path / "mini-x"
    d.mkdir()
    m = _mini(d)
    r = authorize.approve_core(m, d)
    assert r["decision"] == "approved"
    snap = json.loads((d / "contract.json").read_text())
    assert snap["schema"] == 2
    assert "srt_settings_sha256" in snap["sandbox"]
    assert r["settings_sha256"] == snap["sandbox"]["srt_settings_sha256"][:12]
    # edit settings → hash no longer matches
    sett = json.loads((d / "srt-settings.json").read_text())
    sett["network"]["allowedDomains"].append("evil.io")
    (d / "srt-settings.json").write_text(json.dumps(sett))
    from attest import gate
    man2 = yaml.safe_load((d / "tool.yaml").read_text())
    res = gate.decide(man2, d)
    assert res["decision"] == "deny"
    assert res["reason"] == "contract-mismatch"


def test_revoke_returns_to_unmanaged(tmp_path):
    d = tmp_path / "mini-x"
    d.mkdir()
    m = _mini(d)
    authorize.approve_core(m, d)
    out = authorize.revoke(m, d)
    assert out["decision"] == "revoked"
    assert not (d / "contract.json").exists()
    # settings kept for re-review
    assert (d / "srt-settings.json").exists()
    man = yaml.safe_load((d / "tool.yaml").read_text())
    assert man["claims"]["origin"] == "author-built"
    assert authorize.tool_state(man, d)["state"] == "unmanaged"


def test_permission_rows_shape():
    m = {"claims": {"allow": ["stdout"], "deny": ["exec"]}}
    s = {"network": {"allowedDomains": ["x.com"]},
         "filesystem": {"allowWrite": ["/tmp"], "denyWrite": [".env"], "denyRead": ["~/.ssh"]}}
    rows = authorize.permission_rows(m, s)
    tags = [r[0] for r in rows]
    assert tags == ["NET", "WRITE", "NO-WRITE", "NO-READ", "CLAIMS-ALLOW", "CLAIMS-DENY"]
    assert any("x.com" in r[1] for r in rows if r[0] == "NET")