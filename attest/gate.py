"""Decision gate: what the agent consults before invoking a tool.

tool-trust produces attestation reports (health certificates); it does NOT
sandbox every call. The tool runs inside the runtime (agent's bash) — the gate
only makes decisions, without running the tool:

  Gate 1  attestation: cached report verdict=fail → deny
  Gate 2  requires   : any prerequisite missing → deny (env-mismatch), no run
  Gate 3  provenance : a tool with an ID must prove it is still the same tool —
                       tampered source / stale report / stale version → deny

Note: claims (what it does) are checked at attest time by reconcile; provenance
checks "still the same verified artifact".
"""
import json
import pathlib
import shutil
import subprocess

from attest import contract, live, prereq, provenance, telemetry


def load_attestation_verdict(tool_dir: pathlib.Path) -> str | None:
    """Read cached report verdict; None if missing/corrupt (no interception)."""
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
    """Read full cached report (None if missing/corrupt). Used by gate 3."""
    p = tool_dir / "report.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _deny(manifest: dict, reason: str, extra: dict | None = None) -> dict:
    """Build a deny result and log it to telemetry."""
    d = {"decision": "deny", "reason": reason, "tool": manifest["name"]}
    if extra:
        d.update(extra)
    telemetry.log_run({"event": "decide", **d})
    return d


def decide(manifest: dict, tool_dir: pathlib.Path) -> dict:
    """Decide whether the tool may be used right now. Pure logic, no execution.

    Args:
      manifest: tool.yaml contents.
      tool_dir: tool directory (holds report.json, source files).

    Returns:
      {"decision": "allow"|"deny", "reason": ..., "tool": ...}
    """
    # Gate 1: failed attestation → deny
    verdict = load_attestation_verdict(tool_dir)
    if verdict == "fail":
        return _deny(manifest, "attestation-fail")

    # Gate 2: missing prerequisites → deny (saves tokens/compute)
    check = prereq.hard_check(manifest.get("requires"), cwd=str(tool_dir))
    if check["verdict"] != "pass":
        return _deny(manifest, "env-mismatch", {**check})

    # Gate 3: provenance — a tool with an ID must prove it is unchanged
    prov = manifest.get("provenance")
    if prov:
        declared = prov.get("hash") or ""
        cur = provenance.compute_tool_hash(tool_dir) if declared else None
        rp = (load_report(tool_dir) or {}).get("provenance")
        if not rp:
            return _deny(manifest, "stale", {
                "detail": "no provenance snapshot in cached attestation; re-observe (--save-report)"})
        declared_v, observed_v = prov.get("version"), rp.get("version")
        hash_changed = bool(declared) and cur != declared
        version_changed = bool(declared_v) and observed_v != declared_v
        if hash_changed and not version_changed:
            # source changed without a version bump → likely tampering
            return _deny(manifest, "tampered", {
                "detail": f"source hash {cur[:12]} != declared {declared[:12]}, version unchanged"})
        if version_changed:
            # version changed (code or not) → normal upgrade, old proof expired
            return _deny(manifest, "stale-version", {
                "detail": f"observed {observed_v!r} -> declared {declared_v!r}; re-observe (--save-report)"})

    d = {"decision": "allow", "reason": "ok", "tool": manifest["name"]}
    telemetry.log_run({"event": "decide", **d})
    return d


def format_command(manifest: dict, inputs: list[str], tool_dir: pathlib.Path) -> list[str]:
    """Build argv: command + inputs. Relative commands resolve against tool_dir."""
    cmd = manifest["command"].split()
    if cmd:
        first = cmd[0]
        if not pathlib.Path(first).is_absolute() and shutil.which(first) is None:
            # ./test → <tool_dir>/test ; PATH executables (python3) stay as-is
            cmd[0] = str(tool_dir / first)
    return cmd + inputs


def gated_invoke(manifest: dict, inputs: list[str], tool_dir: pathlib.Path) -> dict:
    """Invoke a tool through the decision gate (deny → no run, allow → execute).

    Execution path depends on contract enforcement status:
      - claims operator-approved AND manifest declares a non-null enforcement
        backend config (e.g. `sandbox:
        {srt_settings: "srt-settings.json"}`) → run inside srt; violations are
        collected and surfaced (Step 3: live reconciliation)
      - otherwise → plain subprocess (legacy path; candidates not enforced)

    Args:
      manifest: tool.yaml contents.
      inputs:   extra argv entries.
      tool_dir: cwd for the process.

    Returns:
      Result dict with decision/returncode/stdout/stderr (+violations when enforced).
    """
    d = decide(manifest, tool_dir)
    if d["decision"] != "allow":
        return {"tool": manifest["name"], **d, "output": ""}

    # Enforcement path: operator-approved contract → run inside srt
    sb = manifest.get("sandbox") or {}
    enforced = contract.can_enforce(manifest.get("claims")) and bool(sb.get("srt_settings"))
    if enforced:
        settings = tool_dir / sb["srt_settings"]
        if not settings.exists():
            return {"tool": manifest["name"], "decision": "deny",
                    "reason": "srt-settings-missing",
                    "detail": f"{settings} missing; operator should review & approve contract",
                    "output": ""}
        argv = format_command(manifest, inputs, tool_dir)
        try:
            r = live.run_sandboxed(argv, settings, cwd=str(tool_dir))
        except RuntimeError as exc:  # srt not installed
            return {"tool": manifest["name"], "decision": "deny",
                    "reason": "srt-not-installed", "detail": str(exc), "output": ""}
        out = {
            "tool": manifest["name"],
            "decision": "allow",
            "returncode": r["returncode"],
            "stdout": r["stdout"].strip(),
            "stderr": r["stderr"].strip(),
            "violations": r["violations"],
        }
        telemetry.log_run({"event": "invoke", "tool": out["tool"],
                           "decision": out["decision"], "returncode": out["returncode"],
                           "violations": out["violations"], "inputs": inputs})
        return out

    argv = format_command(manifest, inputs, tool_dir)
    try:
        result = subprocess.run(argv, capture_output=True, text=True, cwd=str(tool_dir))
    except OSError as exc:
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