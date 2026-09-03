"""attest observation CLI — srt-native (no Docker, no strace).

Everything happens inside sandbox-runtime:
  1. `--scan <tool> [inputs...]`  — run the tool in a MINIMAL srt sandbox,
     read what it needed (blocked hosts / EPERM paths) → suggested settings.
  2. `--approve`                 — operator legislates: claims origin →
     operator-approved; writes a committed contract.json (gate snapshot).
  3. `--check-requires`          — pre-flight prerequisites hard check.

Usage:
  python observe.py <tool> --scan [input...]        # srt permission discovery
  python observe.py <tool> --approve [--yes]        # legislate + contract snapshot
  python observe.py <tool> --check-requires         # requires pre-flight
"""
import argparse
import json
import pathlib

import yaml

from attest import contract, prereq, scan as scan_mod

TOOLS_DIR = pathlib.Path("tools")


def load_manifest(tool: str) -> dict:
    """Load tools/<tool>/tool.yaml as dict."""
    p = TOOLS_DIR / tool / "tool.yaml"
    with open(p) as f:
        return yaml.safe_load(f)


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
    """srt permission discovery: run the tool inside the minimal sandbox.

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
    them) may call it. Also writes contract.json (committed): the gate snapshot
    with claims, sandbox settings reference, provenance (hash/version) and
    approval metadata. Gate 1 (verdict) + Gate 3 (provenance) read this file.
    """
    from attest.gate import format_command  # noqa: F401  (unused here)
    from attest.provenance import compute_tool_hash

    tool_dir = TOOLS_DIR / tool
    manifest = load_manifest(tool)
    claims = manifest.get("claims")
    if not claims:
        raise SystemExit(
            f"no claims to approve; run `observe.py {tool} --scan` first "
            "(scan evidence ⇒ monkey/clear claims, then approve)")
    print(f"[contract] reviewing {tool} claims (origin={claims.get('origin') or 'author-built'}):")
    print(json.dumps(claims, ensure_ascii=False, indent=2))
    if not yes:
        if input("Approve as enforceable contract? [y/N] ").strip().lower() not in ("y", "yes"):
            print("aborted — nothing written")
            return
    contract.approve(claims)
    claims["approved_by"] = "operator"
    # persist manifest changes (origin/approved_*)
    (tool_dir / "tool.yaml").write_text(yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False))
    # committed gate snapshot
    prov = manifest.get("provenance")
    snapshot = {
        "schema": 1,
        "tool": tool,
        "verdict": "pass",
        "claims": claims,
        "sandbox": manifest.get("sandbox") or {},
        "provenance": {
            "version": prov.get("version") if prov else None,
            "hash": compute_tool_hash(tool_dir),
        },
        "approved_by": claims.get("approved_by"),
        "approved_at": claims.get("approved_at"),
    }
    (tool_dir / "contract.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2))
    print(f"[contract] {tool} claims now operator-approved "
          f"(written to {tool_dir / 'tool.yaml'} + contract.json)")


def main() -> None:
    """CLI entry: dispatch on subcommand flags."""
    ap = argparse.ArgumentParser(prog="observe")
    ap.add_argument("tool", help="tool name under tools/")
    ap.add_argument("inputs", nargs="*", default=[])
    ap.add_argument("--scan", action="store_true",
                    help="srt permission discovery: run in minimal sandbox, "
                         "report what the tool needs (domains/paths)")
    ap.add_argument("--approve", action="store_true",
                    help="operator-confirm claims: candidate → enforceable contract")
    ap.add_argument("--check-requires", action="store_true",
                    help="pre-flight requires hard check")
    ap.add_argument("--yes", action="store_true",
                    help="skip interactive confirm (with --approve)")
    args = ap.parse_args()

    if args.scan:
        scan_tool(args.tool, args.inputs)
        return
    if args.check_requires:
        check_requires(args.tool, args.inputs)
        return
    if args.approve:
        approve_tool(args.tool, yes=args.yes)
        return
    ap.print_help()


if __name__ == "__main__":
    main()