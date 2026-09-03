"""srt live backend: unit (parsing, any platform) + integration (srt present).

Unit tests run anywhere. Integration tests need srt installed
(npm install -g @anthropic-ai/sandbox-runtime) — skipped otherwise.
"""
import pathlib
import shutil
import sys

import pytest

from attest import live

NEED_SRT = pytest.mark.skipif(
    shutil.which("srt") is None, reason="srt (sandbox-runtime) not installed"
)

DEBUG_SAMPLE = """\
[SandboxDebug] {"allowedHosts":["anthropic.com"]}
[SandboxDebug] [Sandbox macOS] Applied restrictions - network: true
[SandboxDebug] No matching config rule, denying: google.com:443
[SandboxDebug] Connection blocked to google.com:443
"""


def test_parse_blocked_and_denying():
    evs = live.violation_events(DEBUG_SAMPLE)
    assert {"kind": "net-block", "target": "google.com", "port": 443} in evs
    assert any(e["kind"] == "net-deny" for e in evs)


def test_parse_no_violation():
    assert live.violation_events("clean output\n") == []


def test_ensure_srt_missing_gives_hint(monkeypatch):
    monkeypatch.setattr(live.shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError) as e:
        live.ensure_srt()
    assert "npm install -g @anthropic-ai/sandbox-runtime" in str(e.value)


@NEED_SRT
def test_run_sandboxed_allows_and_blocks(tmp_path):
    sett = tmp_path / "s.json"
    sett.write_text(
        '{"network":{"allowedDomains":[],"deniedDomains":["*"]},'
        '"filesystem":{"denyRead":[],"denyWrite":[".env"],"allowWrite":["/tmp","/private/tmp"]}}'
    )
    # allowed: write to /tmp (no violations)
    ok = live.run_sandboxed(
        ["python3", "-c", "open('/private/tmp/srt-live-ok','w').close()"],
        sett, cwd=str(tmp_path))
    assert ok["violations"] == []
    # blocked: network denied → violation recorded
    blk = live.run_sandboxed(
        ["python3", "-c", "import urllib.request; urllib.request.urlopen('https://google.com', timeout=5)"],
        sett, cwd=str(tmp_path), timeout=60)
    assert any(v["kind"].startswith("net-") for v in blk["violations"]), blk


@NEED_SRT
def test_gated_invoke_enforced_demo(tmp_path):
    """End-to-end: operator-approved claims + sandbox.srt_settings → srt-enforced."""
    from attest.gate import gated_invoke
    import yaml

    tool_dir = tmp_path
    (tool_dir / "demo.py").write_text("print('enforced hello')\n")
    (tool_dir / "srt-settings.json").write_text(
        '{"network":{"allowedDomains":[],"deniedDomains":["*"]},'
        '"filesystem":{"denyRead":["~/.ssh"],"denyWrite":[".env"],'
        '"allowWrite":["/tmp","/private/tmp"]}}')
    man = {
        "name": "demo", "command": "python3 demo.py", "build": "true",
        "claims": {
            "origin": "operator-approved",
            "allow": ["stdout", "exit", "fd", "memory", "sync", "file-read"],
            "deny": ["network", "exec", "file-write", "perms", "process", "fork", "other"],
        },
        "sandbox": {"srt_settings": "srt-settings.json"},
    }
    r = gated_invoke(man, [], tool_dir)
    assert r["decision"] == "allow", r
    assert r["violations"] == [], r
    assert "enforced hello" in r["stdout"], r


@NEED_SRT
def test_violations_flip_to_deny(tmp_path):
    """Runtime breach of contract → srt blocks → gate flips to deny (violation-deny)."""
    from attest.gate import gated_invoke

    tool_dir = tmp_path
    (tool_dir / "evil.py").write_text(
        "import urllib.request\n"
        "urllib.request.urlopen('https://google.com', timeout=5)\n")
    (tool_dir / "srt-settings.json").write_text(
        '{"network":{"allowedDomains":[],"deniedDomains":["*"]},'
        '"filesystem":{"denyRead":[],"denyWrite":[],"allowWrite":["/tmp","/private/tmp"]}}')
    man = {
        "name": "evil", "command": "python3 evil.py", "build": "true",
        "claims": {
            "origin": "operator-approved",
            "allow": ["stdout", "exit", "fd", "memory", "sync", "file-read"],
            "deny": ["network", "exec", "file-write", "perms", "process", "fork", "other"],
        },
        "sandbox": {"srt_settings": "srt-settings.json"},
    }
    r = gated_invoke(man, [], tool_dir)
    assert r["decision"] == "deny", r
    assert r["reason"] == "violation-deny", r
    assert r["violations"], r