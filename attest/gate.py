"""消费决策闸 gate：agent 在 bash runtime 里调用工具前的把关（决策时，非 per-call 沙箱）。

tool-trust 的产品是 attestation report（体检证书），不是"每次调用都加锁/隔离"。
真实运行属于工具所在的 runtime agent（bash）本身，这里只做**决策时**把关：

  闸 1　attestation 校验　：缓存报告 verdict=fail → 直接拒绝，不让它被使用/运行
  闸 2　requires 硬拒　　　：缺任一前置 → 拒绝(env-mismatch)，不运行，省 token/算力
  都过 → 放行，交给调用方在 runtime 里正常执行（不做 kernel 隔离）。

这是 #1 优先级(attestation report → MCP 消费)的落地：
  agent 只看到/只调用通过闸门的工具；违规或前置缺失的工具在调用时被硬拒，
  且不会白白浪费算力去跑一个跑不动的工具。
"""
import json
import pathlib
import subprocess

from attest import prereq, telemetry


def load_attestation_verdict(tool_dir: pathlib.Path) -> str | None:
    """读工具目录下缓存的 attestation report 的 verdict；无/坏返回 None(不拦截)。"""
    p = tool_dir / "report.json"
    if not p.exists():
        return None
    try:
        report = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    v = report.get("verdict")
    return v if v in ("pass", "fail") else None


def decide(manifest: dict, tool_dir: pathlib.Path) -> dict:
    """决策闸：给"这个工具现在能不能被使用"下结论。纯逻辑，不运行工具。"""
    # 闸 1：attestation 判 fail → 拒绝
    verdict = load_attestation_verdict(tool_dir)
    if verdict == "fail":
        d = {"decision": "deny", "reason": "attestation-fail", "tool": manifest["name"]}
        telemetry.log_run({"event": "decide", **d})
        return d

    # 闸 2：requires 硬拒 —— 缺任一前置 → 拒绝，省 token/算力
    check = prereq.hard_check(manifest.get("requires"), cwd=str(tool_dir))
    if check["verdict"] != "pass":
        d = {
            "decision": "deny",
            "reason": "env-mismatch",
            "tool": manifest["name"],
            **check,
        }
        telemetry.log_run({"event": "decide", **d})
        return d

    d = {"decision": "allow", "reason": "ok", "tool": manifest["name"]}
    telemetry.log_run({"event": "decide", **d})
    return d


def format_command(manifest: dict, inputs: list[str], tool_dir: pathlib.Path) -> list[str]:
    """命令 + 输入 → argv。相对命令基于工具目录解析（工具以此目录为 cwd 运行）。"""
    cmd = manifest["command"].split()
    if cmd and not pathlib.Path(cmd[0]).is_absolute():
        cmd[0] = str(tool_dir / cmd[0])
    return cmd + inputs


def gated_invoke(
    manifest: dict,
    inputs: list[str],
    tool_dir: pathlib.Path,
) -> dict:
    """带决策闸地调用工具。deny → 直接返回拒绝(不运行)；allow → 在 runtime 里正常执行。

    真实运行就是普通 subprocess（agent 的 bash runtime 上下文），不再套内核沙箱——
    改造成本远大于收益，工具本就活在它所在 runtime 的约束里。
    """
    d = decide(manifest, tool_dir)
    if d["decision"] != "allow":
        return {"tool": manifest["name"], **d, "output": ""}

    argv = format_command(manifest, inputs, tool_dir)
    try:
        result = subprocess.run(argv, capture_output=True, text=True, cwd=str(tool_dir))
    except OSError as exc:
        # 启动失败（二进制不存在/平台不匹配等）：结构化返回 + 记日志，不抛裸异常
        out = {
            "tool": manifest["name"],
            "decision": "allow",
            "launch_error": f"{type(exc).__name__}: {exc}",
            "returncode": None,
            "stdout": "",
            "stderr": "",
        }
        telemetry.log_run(
            {"event": "invoke", "tool": out["tool"], "launch_error": out["launch_error"]}
        )
        return out
    out = {
        "tool": manifest["name"],
        "decision": "allow",
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }
    telemetry.log_run(
        {
            "event": "invoke",
            "tool": out["tool"],
            "decision": out["decision"],
            "returncode": out["returncode"],
            "stdout_len": len(out["stdout"]),
            "stderr_len": len(out["stderr"]),
            "inputs": inputs,
        }
    )
    return out
