#!/usr/bin/env python3
"""CI 可用性冒烟：验证「软件真的能用」——不是只有测试绿。

四件事,对应四层可用性:
  1. server 拉起:toolhub 能启动并加载全部公共工具(loaded N tool(s))
  2. gate 决策:sha-tool 被放行(allow)+ env-gate 被 requires 硬拒(env-mismatch)
     —— 证明「真能用」与「真会拒」两条路径都活着
  3. enforce 验证(srt 可用时):cache-tool 经 srt 放行且零违例
     —— 观察+契约+srt 强制的三角闭环在 CI 真跑

用法:
  scripts/ci_smoke.py
"""
import argparse
import os
import pathlib
import re
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
os.chdir(REPO)
sys.path.insert(0, str(REPO))  # 允许 `uv run python scripts/ci_smoke.py` 直跑


def public_tool_count() -> int:
    out = subprocess.run(["git", "ls-files", "tools/*/tool.py"],
                         capture_output=True, text=True).stdout.split()
    return len(out)


def check_server() -> None:
    p = subprocess.Popen(["./toolhub"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(4)
    if p.poll() is None:
        p.kill()
    err = p.stderr.read().decode()
    m = re.search(r"loaded (\d+) tool\(s\)", err)
    assert m, f"server 未输出 loaded N tool(s): {err[:300]}"
    n = int(m.group(1))
    exp = public_tool_count()
    assert n >= exp, f"loaded {n} 缺公共工具 (需要 ≥ {exp})"
    print(f"[server] ✓ loaded {n} tool(s) >= public tools {exp}")


def _sandbox_env_broken(r: dict) -> bool:
    """True when the sandbox itself cannot run in this environment (not the
    tool's fault): bwrap/seccomp/user-ns restrictions on some runners."""
    err = (r.get("stderr") or "")
    markers = ("Failed RTM_NEWADDR", "No permissions to create new namespace",
               "apply-seccomp", "Sandbox dependencies not available",
               "nested userns is capability-restricted")
    return any(m in err for m in markers)


def check_gate() -> None:
    import yaml
    from attest.gate import gated_invoke

    # allow 冒烟用 sha-tool:受 srt 强制。运行器若无法跑 bwrap/seccomp,
    # srt 自身不会成功 —— 那属于环境受限,skip 而不是红。
    allow_tool, deny_tool = "sha-tool", "env-gate"
    aman = yaml.safe_load((REPO / "tools" / "sha-tool" / "tool.yaml").read_text())
    adir = REPO / "tools" / "sha-tool"
    r = gated_invoke(aman, ["ci-smoke"], adir)
    if r["decision"] == "allow" and r.get("returncode") == 0:
        print(f"[gate] ✓ sha-tool allow, rc=0 (输出 {r.get('stdout','')[:20]!r})")
    elif r["decision"] == "allow" and not r.get("violations") and _sandbox_env_broken(r):
        print("[gate] ⏭ sha-tool sandboxed allow 无法在本机跑(user-ns 受限);跳过实证")
    else:
        assert False, f"sha-tool 冒烟失败: {r}"

    dman = yaml.safe_load((REPO / "tools" / "env-gate" / "tool.yaml").read_text())
    ddir = REPO / "tools" / "env-gate"
    r2 = gated_invoke(dman, [], ddir)
    assert r2["decision"] == "deny" and r2.get("reason") == "env-mismatch", \
        f"{deny_tool} 应被 requires 硬拒: {r2}"
    print(f"[gate] ✓ {deny_tool} 被 requires 硬拒 (env-mismatch) — 拒绝路径活着")


def check_enforced() -> None:
    """srt 可用时,验证 enforced 工具真的在沙箱里跑(否则 skip 不红)。"""
    import shutil
    import tempfile
    import yaml
    from attest import live
    from attest.gate import gated_invoke

    if shutil.which("srt") is None:
        print("[enforced] ⏭ srt 未安装,跳过(cache-tool enforce 验证)")
        return
    try:
        with tempfile.TemporaryDirectory() as d:
            probe = pathlib.Path(d) / "probe.json"
            probe.write_text(
                '{"network":{"allowedDomains":[],"deniedDomains":["*"]},'
                '"filesystem":{"denyRead":[],"denyWrite":[],'
                '"allowWrite":["/tmp","/private/tmp"]}}')
            t = live.run_sandboxed([sys.executable, "-c", "pass"],
                                   probe, cwd=d, timeout=60)
            if t["returncode"] != 0:
                raise RuntimeError(f"srt 不可用: rc={t['returncode']}")
    except Exception as exc:
        print(f"[enforced] ⏭ srt 无法沙箱({exc});跳过 enforce 验证")
        return

    aman = yaml.safe_load((REPO / "tools" / "cache-tool" / "tool.yaml").read_text())
    adir = REPO / "tools" / "cache-tool"
    r = gated_invoke(aman, ["ci-smoke-enforced"], adir)
    assert r["decision"] == "allow" and r.get("returncode") == 0, \
        f"cache-tool enforce 失败: {r}"
    assert r.get("violations") == [], f"cache-tool 出现违例: {r.get('violations')}"
    print(f"[enforced] ✓ cache-tool 经 srt 放行,violations=[] (输出 {r.get('stdout','')[:20]!r})")


def main() -> None:
    check_server()
    check_gate()
    check_enforced()
    print("CI SMOKE PASSED")


if __name__ == "__main__":
    main()