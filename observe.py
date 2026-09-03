"""attest observation pipeline CLI.

Usage:
  python observe.py <tool> <input...>                    # one input → one report
  python observe.py <tool> --generate-claims <input...>  # build claims baseline
  python observe.py <tool> --save-report <input...>      # persist report.json (gate cache)
  python observe.py <tool> --scan <input...>             # srt permission discovery
"""
import argparse
import json
import pathlib

import yaml

from attest import build, contract, parse, prereq, provenance, reconcile, report, rules, run, scan as scan_mod

TOOLS_DIR = pathlib.Path("tools")


def load_manifest(tool: str) -> dict:
    """Load tools/<tool>/tool.yaml as dict."""
    p = TOOLS_DIR / tool / "tool.yaml"
    with open(p) as f:
        return yaml.safe_load(f)


def _drop_launch_execve(events: list[dict]) -> list[dict]:
    """Drop the tool's own launch execve (first event); keep child execves."""
    if events and events[0]["syscall"] in ("execve", "execveat"):
        return events[1:]
    return events


def annotate(events: list[dict]) -> None:
    """Annotate events with class (plus path/mode for writes, ip/port for nets).

    In-place. Then run fd routing to correct socket writes to 'network'.
    """
    for e in events:
        e["class"] = rules.classify(e["syscall"], e["args"])
        if e["class"] == "file-write":
            e["path"], e["mode"] = rules.write_attrs(e["syscall"], e["args"])
        if e["class"] == "network":
            e["ip"], e["port"] = rules.net_attrs(e["args"])
    rules.route_fds(events)


def observe(tool: str, inputs: list[str]) -> dict:
    """Full pipeline for one tool+input: build → trace → classify → reconcile.

    Args:
      tool: tool name under tools/.
      inputs: argv entries to run during observation.

    Returns:
      Attestation report dict (verdict 'pass'/'fail', violations, provenance).
    """
    manifest = load_manifest(tool)
    tool_dir = TOOLS_DIR / tool
    build.build_tool(manifest, tool_dir)
    text = run.run_tool(manifest, tool_dir, inputs)
    events = _drop_launch_execve(parse.parse_strace(text))
    annotate(events)
    violations = reconcile.reconcile(events, manifest["claims"])
    return report.build_report(
        manifest["name"], inputs, manifest["claims"], events, violations,
        provenance=provenance.snapshot(manifest),
    )


def save_report(tool: str, r: dict) -> pathlib.Path:
    """Persist report to tools/<tool>/report.json (the gate's decision cache)."""
    p = TOOLS_DIR / tool / "report.json"
    p.write_text(json.dumps(r, ensure_ascii=False, indent=2))
    print(f"report written to {p}")
    return p


def generate_claims(tool: str, inputs: list[str]) -> None:
    """Build claims from one run as CANDIDATES (observed-suggested), not law.

    Tagged as candidates per the contract flow; refuses to overwrite an
    operator-approved manifest (no auto-expansion invariant). Use
    --approve to enact them.

    Args:
      tool: tool name.
      inputs: observation argv.
    """
    manifest = load_manifest(tool)
    if contract.origin_of(manifest.get("claims")) == "operator-approved":
        print(f"[contract] {tool} claims are operator-approved — refusing to overwrite "
              f"with observed candidates (no auto-expansion)")
        raise SystemExit(2)
    tool_dir = TOOLS_DIR / tool
    build.build_tool(manifest, tool_dir)
    text = run.run_tool(manifest, tool_dir, inputs)
    events = _drop_launch_execve(parse.parse_strace(text))
    annotate(events)

    observed = sorted({e["class"] for e in events})
    known = set(rules.SEVERITY)
    allow = [c for c in observed if c != "other"]  # other never allowed (default deny)

    # structured file-write: aggregate paths + strictest mode
    fw = [e for e in events if e["class"] == "file-write" and e.get("path")]
    if fw:
        import posixpath

        paths = sorted({posixpath.dirname(e["path"]) or "/" for e in fw})
        modes = {e.get("mode") for e in fw}
        if "overwrite" in modes:
            mode = "overwrite"
        elif "append" in modes:
            mode = "append"
        else:
            mode = "create"
        allow = [c for c in allow if c != "file-write"]
        allow.append({"class": "file-write", "mode": mode, "paths": paths})

    deny = sorted((known - set(observed)) | {"other"})
    claims = contract.mark_generated({"allow": allow, "deny": deny})

    manifest["claims"] = claims
    p = TOOLS_DIR / tool / "tool.yaml"
    with open(p, "w") as f:
        f.write("# claims are observed-suggested CANDIDATES — run observe.py --approve %s to enact\n" % tool)
        yaml.safe_dump(manifest, f, allow_unicode=True, sort_keys=False)
    print(json.dumps(claims, ensure_ascii=False, indent=2))
    print(f"written to {p} (origin=observed-suggested — NOT enforced until approved)")


def generate_requires(tool: str, inputs: list[str]) -> None:
    """Infer requires from one observed run and write it back to tool.yaml.

    Args:
      tool: tool name.
      inputs: observation argv.
    """
    manifest = load_manifest(tool)
    tool_dir = TOOLS_DIR / tool
    build.build_tool(manifest, tool_dir)
    text = run.run_tool(manifest, tool_dir, inputs)
    events = _drop_launch_execve(parse.parse_strace(text))
    annotate(events)

    # file-write whitelist paths → writable dirs the tool needs on the host
    writable = []
    for a in manifest.get("claims", {}).get("allow", []):
        if isinstance(a, dict) and a.get("class") == "file-write":
            writable += a.get("paths") or []
    inferred = prereq.infer_requires_full(events, writable)

    # merge, don't overwrite: env/cwd unobservable; exec keeps manual entry
    old = manifest.get("requires") or {}
    requires = {
        "env": old.get("env") or [],
        "files": inferred.get("files") or [],
        "exec": inferred.get("exec") or old.get("exec") or [],
        "writable": inferred.get("writable") or [],
    }
    if old.get("cwd"):
        requires["cwd"] = old["cwd"]

    manifest["requires"] = requires
    p = TOOLS_DIR / tool / "tool.yaml"
    with open(p, "w") as f:
        f.write("# requires auto-generated by observe.py --generate-requires\n")
        yaml.safe_dump(manifest, f, allow_unicode=True, sort_keys=False)
    print(json.dumps(requires, ensure_ascii=False, indent=2))
    print(f"written to {p}")


def check_requires(tool: str, inputs: list[str]) -> dict:
    """Pre-flight hard check of the tool's requires; missing any → fail.

    Args:
      tool: tool name.
      inputs: unused (kept for CLI symmetry).
    """
    manifest = load_manifest(tool)
    check = prereq.hard_check(manifest.get("requires"), cwd=str(TOOLS_DIR / tool))
    print(json.dumps(check, ensure_ascii=False, indent=2))
    return check


def scan_tool(tool: str, inputs: list[str]) -> None:
    """srt permission discovery: run the tool in a minimal sandbox, report needs.

    Output is a SUGGESTION (evidence from a sandboxed smoke run). The operator
    reviews it and writes the final srt-settings.json — enforcing is legislative.
    """
    from attest.gate import format_command

    manifest = load_manifest(tool)
    tool_dir = TOOLS_DIR / tool
    argv = format_command(manifest, inputs, tool_dir)
    r = scan_mod.scan(argv, cwd=str(tool_dir))
    print(json.dumps({"tool": tool, **r}, ensure_ascii=False, indent=2))
    if r["denials"]:
        print(
            f"\n>>> {tool} needs {len(r['denials'])} permission(s). Review the suggested"
            f" settings; write them to {tool_dir / 'srt-settings.json'} to enforce.")
    else:
        print(f"\n>>> {tool} needed nothing beyond defaults. ({r['note']})")


def approve_tool(tool: str, yes: bool = False) -> None:
    """Operator confirmation: observed-suggested claims → operator-approved.

    This is the legislative step — only the operator (or an agent acting for
    them) may call it. Once approved, --generate-claims refuses to overwrite
    (no auto-expansion invariant).

    Args:
      tool: tool name.
      yes: skip interactive confirmation (scripting/demos).
    """
    manifest = load_manifest(tool)
    claims = manifest.get("claims")
    if not claims or contract.origin_of(claims) == "operator-approved":
        print(f"[contract] {tool}: nothing to approve (already operator-approved)")
        return None
    print(f"[contract] reviewing {tool} claims (origin={contract.origin_of(claims)}):")
    print(json.dumps(claims, ensure_ascii=False, indent=2))
    if not yes:
        if input("Approve as enforceable contract? [y/N] ").strip().lower() not in ("y", "yes"):
            print("[contract] not approved; claims stay candidates")
            return None
    manifest["claims"] = contract.approve(claims)
    p = TOOLS_DIR / tool / "tool.yaml"
    with open(p, "w") as f:
        yaml.safe_dump(manifest, f, allow_unicode=True, sort_keys=False)
    print(f"[contract] {tool} claims now operator-approved (written to {p})")
    return manifest


def main() -> None:
    """CLI entry: dispatch on subcommand flags."""
    ap = argparse.ArgumentParser(prog="observe")
    ap.add_argument("tool", help="tool name under tools/")
    ap.add_argument("inputs", nargs="*", default=[])
    ap.add_argument("--generate-claims", action="store_true")
    ap.add_argument("--generate-requires", action="store_true")
    ap.add_argument("--check-requires", action="store_true")
    ap.add_argument("--save-report", action="store_true",
                    help="write report.json (gate decision cache)")
    ap.add_argument("--approve", action="store_true",
                    help="operator-confirm claims: candidate → enforceable contract")
    ap.add_argument("--scan", action="store_true",
                    help="srt permission discovery: run in minimal sandbox, "
                         "report what the tool needs (domains/paths)")
    ap.add_argument("--yes", action="store_true",
                    help="skip interactive confirm (with --approve)")
    args = ap.parse_args()

    if args.scan:
        scan_tool(args.tool, args.inputs)
        return
    if args.generate_claims:
        generate_claims(args.tool, args.inputs)
        return
    if args.generate_requires:
        generate_requires(args.tool, args.inputs)
        return
    if args.approve:
        approve_tool(args.tool, yes=args.yes)
        return
    if args.check_requires:
        check_requires(args.tool, args.inputs)
        return
    r = observe(args.tool, args.inputs)
    print(json.dumps(r, ensure_ascii=False, indent=2))
    if args.save_report:
        save_report(args.tool, r)


if __name__ == "__main__":
    main()