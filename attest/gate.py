"""消费决策闸 gate：agent 在 bash runtime 里调用工具前的把关（决策时，非 per-call 沙箱）。

tool-trust 的产出是 attestation report（体检证书），不是"每次调用都加锁/隔离"。
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
import shutil
import subprocess

from attest import prereq, provenance, telemetry


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


def load_report(tool_dir: pathlib.Path) -> dict | None:
    """读整份缓存报告（无/坏返回 None）。闸 3 provenance 用读快照。"""
    p = tool_dir / "report.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _deny(manifest: dict, reason: str, extra: dict | None = None) -> dict:
    d = {"decision": "deny", "reason": reason, "tool": manifest["name"]}
    if extra:
        d.update(extra)
    telemetry.log_run({"event": "decide", **d})
    return d


def decide(manifest: dict, tool_dir: pathlib.Path) -> dict:
    """决策闸：给"这个工具现在能不能被使用"下结论。纯逻辑，不运行工具。

    闸 1  attestation：缓存报告 verdict=fail → 拒绝
    闸 2  requires   ：缺任一前置 → 拒绝(env-mismatch)，不运行省 token/算力
    闸 3  provenance ：有身份证的工具必须证明「还是原来那个」——
          源码哈希被改(tampered)/缓存报告无快照(stale)/版本漂移(stale-version) → 拒绝
    """
    # 闸 1：attestation 判 fail → 拒绝
    verdict = load_attestation_verdict(tool_dir)
    if verdict == "fail":
        return _deny(manifest, "attestation-fail")

    # 闸 2：requires 硬拒 —— 缺任一前置 → 拒绝，省 token/算力
    check = prereq.hard_check(manifest.get("requires"), cwd=str(tool_dir))
    if check["verdict"] != "pass":
        return _deny(manifest, "env-mismatch", {**check})

    # 闸 3：provenance —— 有身份证的工具必须证明「还是原来那个」
    prov = manifest.get("provenance")
    if prov:
        declared = prov.get("hash") or ""
        cur = provenance.compute_tool_hash(tool_dir) if declared else None
        rp = (load_report(tool_dir) or {}).get("provenance")
        if not rp:
            return _deny(manifest, "stale", {
                "detail": "cached attestation has no provenance snapshot; re-observe (--save-report)"})
        declared_v, observed_v = prov.get("version"), rp.get("version")
        hash_changed = bool(declared) and cur != declared
        version_changed = bool(declared_v) and observed_v != declared_v
        if hash_changed and not version_changed:
            # 源码变了但版本没变 → 疑似被换内容,且没声称升级 → 篡改
            return _deny(manifest, "tampered", {
                "detail": f"source hash {cur[:12]} != declared {declared[:12]}, version unchanged"})
        if version_changed:
            # 版本变了(源码动没动都算)→ 可能是正常升级,旧证明作废 → 重检
            return _deny(manifest, "stale-version", {
                "detail": f"observed {observed_v!r} -> declared {declared_v!r}; re-observe (--save-report)"})

    d = {"decision": "allow", "reason": "ok", "tool": manifest["name"]}
    telemetry.log_run({"event": "decide", **d})
    return d


def format_command(manifest: dict, inputs: list[str], tool_dir: pathlib.Path) -> list[str]:
    """命令 + 输入 → argv。相对命令基于工具目录解析（工具以此目录为 cwd 运行）。"""
    cmd = manifest["command"].split()
    if cmd:
        first = cmd[0]
        if not pathlib.Path(first).is_absolute() and shutil.which(first) is None:
            # 相对工具目录的命令(如 ./test) → 拼完整路径；PATH 可执行(python3)不动
            cmd[0] = str(tool_dir / first)
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
