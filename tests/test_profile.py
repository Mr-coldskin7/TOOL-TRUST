"""claims→seatbelt profile: unit (compile) + integration (sandbox-exec macOS).

Unit tests run anywhere (pure string compilation). Integration tests need a
macOS host with sandbox-exec (Apple's native seatbelt) — skipped elsewhere.
"""
import pathlib
import shutil
import sys

import pytest

from attest import profile

CACHE_LIKE = {
    "allow": [
        "stdout", "exit", "fd", "memory", "sync",
        {"class": "file-write", "mode": "append", "paths": ["/tmp"]},
    ],
    "deny": ["network", "exec", "perms", "process"],
}


# ---------- unit: compilation (no sandbox) ----------

def test_default_deny_all_writes_then_allow_whitelist():
    prof = profile.build_profile(CACHE_LIKE)
    assert "(deny file-write*)" in prof
    assert '(allow file-write* (subpath "/private/tmp"))' in prof  # /tmp→real
    # every write outside /private/tmp is denied, so whitelist must be present
    assert prof.index("(deny file-write*)") < prof.index("(allow file-write*")


def test_mac_path_mapping():
    assert profile.mac_path("/tmp") == "/private/tmp"
    assert profile.mac_path("/tmp/cache.log") == "/private/tmp/cache.log"
    assert profile.mac_path("/etc") == "/private/etc"
    assert profile.mac_path("/usr/local/bin/x") == "/usr/local/bin/x"


def test_network_absent_is_denied():
    prof = profile.build_profile(CACHE_LIKE)
    assert "(deny network*)" in prof
    assert "(allow network-outbound)" not in prof


def test_network_declared_is_allowed_coarse():
    claims = {"allow": ["network"], "deny": []}
    prof = profile.build_profile(claims)
    assert "(allow network-outbound)" in prof
    assert "(deny network*)" not in prof


def test_no_write_claims_deny_all_writes():
    claims = {"allow": ["stdout", "exit"], "deny": []}
    prof = profile.build_profile(claims)
    assert "(deny file-write*)" in prof
    assert "subpath" not in prof


# ---------- integration: sandbox-exec (macOS only) ----------

_NEED_SANDBOX = pytest.mark.skipif(
    sys.platform != "darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS sandbox-exec required",
)


@_NEED_SANDBOX
def test_sandbox_allows_whitelisted_write_blocks_other(tmp_path):
    script = tmp_path / "t.py"
    script.write_text(
        "open('/private/tmp/sb-ok.txt','w').close()\n"
        "try:\n"
        "    open('/etc/sb-evil.txt','w').close()\n"
        "    print('EVIL-WRITE-PASSED')\n"
        "except OSError:\n"
        "    print('EVIL-WRITE-BLOCKED')\n"
    )
    r = profile.run_sandboxed(
        ["python3", str(script)], profile.build_profile(CACHE_LIKE), cwd=str(tmp_path),
    )
    assert "EVIL-WRITE-BLOCKED" in r["stdout"], r
    assert "EVIL-WRITE-PASSED" not in r["stdout"]


@_NEED_SANDBOX
def test_profile_compiles_from_real_tool_manifest(tmp_path):
    """End-to-end: cache-tool's real claims → profile → sandboxed python run."""
    import yaml

    repo = pathlib.Path(__file__).parent.parent
    man = yaml.safe_load((repo / "tools" / "cache-tool" / "tool.yaml").read_text())
    prof = profile.build_profile(man["claims"])
    demo = tmp_path / "go.py"
    demo.write_text(
        "open('/private/tmp/cache.log','a').close()\n"
        "try:\n"
        "    open('/etc/cache-evil.log','a').close()\n"
        "    print('EVIL-PASSED')\n"
        "except OSError:\n"
        "    print('EVIL-BLOCKED')\n"
    )
    r = profile.run_sandboxed(["python3", str(demo)], prof, cwd=str(tmp_path))
    assert "EVIL-BLOCKED" in r["stdout"], r