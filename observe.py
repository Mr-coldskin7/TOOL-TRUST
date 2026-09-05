"""attest observation CLI — srt-native (no Docker, no strace).

Everything happens inside sandbox-runtime:

  1. `--scan <tool> [input...]`  — run the tool in a MINIMAL srt sandbox, read
     what it needed (blocked hosts / EPERM paths) → srt-settings.json.proposed.
  2. `--onboard <tool> [input...]` — guided wizard: scan → permission table →
     trim anything you don't want → approve & LOCK in one flow.
  3. `--approve`                 — legislate (shows EXACT permission summary,
     then commits contract.json with the settings content hashed in).
  4. `--revoke`                  — remove authorization (back to unmanaged).
  5. `--status`                  — every tool × authorization state.

Usage:
  python observe.py <tool> --scan [input...]       # propose permissions
  python observe.py <tool> --onboard [input...]    # wizard → approve → lock
  python observe.py <tool> --approve [--yes]       # legislate + lock
  python observe.py <tool> --revoke                # unmanage
  python observe.py --status                       # overview
"""
import argparse
import json
import pathlib
import shutil

import yaml

from attest import authorize, contract, prereq, scan as scan_mod

TOOLS_DIR = pathlib.Path("tools")
PROPOSED_SUFFIX = ".proposed"


def load_manifest(tool: str) -> dict:
    """Load tools/<tool>/tool.yaml as dict."""
    p = TOOLS_DIR / tool / "tool.yaml"
    with open(p) as f:
        return yaml.safe_load(f)


def _fmt(items) -> str:
    """Join claim/settings items, tolerating structured (dict) entries."""
    parts = [it if isinstance(it, str) else json.dumps(it, ensure_ascii=False)
             for it in (items or [])]
    return ", ".join(parts) if parts else "(none)"


def permission_summary(manifest: dict, settings: dict) -> str:
    """Human-readable summary of exactly what the tool is allowed to do."""
    lines: list[str] = []
    net = settings.get("network", {})
    doms = net.get("allowedDomains") or []
    lines.append(f"  network domains : {', '.join(doms) if doms else '(none)'}")
    fs = settings.get("filesystem", {})
    lines.append("  allowWrite      : " + _fmt(fs.get("allowWrite") or []))
    lines.append("  denyWrite       : " + _fmt(fs.get("denyWrite") or []))
    lines.append("  denyRead        : " + _fmt(fs.get("denyRead") or []))
    c = manifest.get("claims") or {}
    lines.append(f"  claims allow    : {_fmt(c.get('allow'))}")
    lines.append(f"  claims deny     : {_fmt(c.get('deny'))}")
    return "\n".join(lines)


def check_requires(tool: str, inputs: list[str]) -> dict:
    """Pre-flight hard check of the tool's requires; missing any → fail."""
    manifest = load_manifest(tool)
    check = prereq.hard_check(manifest.get("requires"), cwd=str(TOOLS_DIR / tool))
    print(json.dumps(check, ensure_ascii=False, indent=2))
    return check


def _scan_and_propose(tool: str, inputs: list[str]) -> tuple[dict, pathlib.Path]:
    """Run --scan, persist srt-settings.json.proposed, declare the sandbox ref.

    No permission is enabled here — approval is the legislative step.
    """
    from attest.gate import format_command

    manifest = load_manifest(tool)
    tool_dir = TOOLS_DIR / tool
    argv = format_command(manifest, inputs, tool_dir)
    r = scan_mod.scan(argv, cwd=str(tool_dir))
    proposed = tool_dir / f"srt-settings.json{PROPOSED_SUFFIX}"
    proposed.write_text(json.dumps(r["suggested"], indent=2, ensure_ascii=False))
    sb = manifest.get("sandbox") or {}
    if not sb.get("srt_settings"):
        manifest["sandbox"] = {"srt_settings": "srt-settings.json"}
        (tool_dir / "tool.yaml").write_text(
            yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False))
        print("  [scan] tool.yaml 已声明 sandbox.srt_settings: srt-settings.json")
    print(json.dumps({"tool": tool, "suggested": r["suggested"],
                      "denials": r["denials"], "rc": r["rc"]},
                     ensure_ascii=False, indent=2))
    return r["suggested"], proposed


def scan_tool(tool: str, inputs: list[str]) -> None:
    """srt permission discovery: propose what the tool needs."""
    manifest = load_manifest(tool)
    suggested, proposed = _scan_and_propose(tool, inputs)
    print(f"\n>>> suggested permissions written to {proposed}:\n"
          + permission_summary(manifest, suggested))
    print(f"\n    review it — then run:  observe.py {tool} --approve   "
          "(y/N confirms and LOCKS these permissions)")


def approve_tool(tool: str, yes: bool = False) -> None:
    """Operator confirmation: scan evidence → enforceable, LOCKED contract."""
    tool_dir = TOOLS_DIR / tool
    manifest = load_manifest(tool)
    if not manifest.get("claims"):
        raise SystemExit(f"no claims to approve; run `observe.py {tool} --scan` first")
    sb = manifest.get("sandbox") or {}
    sb_name = sb.get("srt_settings")
    if not sb_name:
        raise SystemExit(
            f"no sandbox.srt_settings in {tool}/tool.yaml; run --scan first")
    target = tool_dir / sb_name
    pp = tool_dir / f"{sb_name}{PROPOSED_SUFFIX}"
    if not target.exists():
        if not pp.exists():
            raise SystemExit(f"nothing to accept: {target} missing and no {pp.name}")
        shutil.copyfile(pp, target)
        print(f"[contract] promoting {pp.name} → {target.name}")
    settings = json.loads(target.read_text())
    print(f"[contract] reviewing {tool} — EXACT permissions to be locked in:\n"
          + permission_summary(manifest, settings))
    if not yes:
        if input("Approve and LOCK these permissions? [y/N] ").strip().lower() not in ("y", "yes"):
            print("aborted — nothing written")
            return
    r = authorize.approve_core(manifest, tool_dir)
    print(f"[contract] {tool} APPROVED + LOCKED (settings sha256 {r['settings_sha256']}…)\n"
          f"          {tool_dir / 'contract.json'} written — edit srt-settings.json "
          "now ⇒ contract-mismatch on next call")


def _remove_lines(settings: dict, rows: list[list[str]], idxs: set[int]) -> None:
    """Remove selected permission-table rows from the suggested settings."""
    fs = settings.setdefault("filesystem", {})
    for idx in sorted(idxs, reverse=True):
        if idx >= len(rows):
            continue
        tag = rows[idx][0]
        if tag == "NET":
            settings["network"]["allowedDomains"] = []
        elif tag == "WRITE":
            fs["allowWrite"] = [p for p in (fs.get("allowWrite") or [])
                                if not isinstance(p, str) or p not in rows[idx][1].split(", ")]
        elif tag == "NO-WRITE":
            fs["denyWrite"] = [p for p in (fs.get("denyWrite") or [])
                               if not isinstance(p, str) or p not in rows[idx][1].split(", ")]
        elif tag == "NO-READ":
            fs["denyRead"] = [p for p in (fs.get("denyRead") or [])
                              if not isinstance(p, str) or p not in rows[idx][1].split(", ")]
        # CLAIMS-* rows live in tool.yaml — not editable from the settings table


def onboard(tool: str, inputs: list[str], yes: bool = False) -> None:
    """Guided wizard: scan → numbered permission table → trim → approve & LOCK."""
    tool_dir = TOOLS_DIR / tool
    manifest = load_manifest(tool)
    if not manifest.get("claims"):
        raise SystemExit(f"no claims; register the tool first (see register-tool)")
    suggested, proposed = _scan_and_propose(tool, inputs)

    while True:
        rows = authorize.permission_rows(manifest, suggested)
        print("\n── permissions to be locked in ──────────────")
        for i, (tag, val) in enumerate(rows):
            print(f"  {i:>3}  {tag:<9} {val}")
        print("  CLAIMS-* rows are set in tool.yaml (not editable here)")
        if yes:
            break
        ans = input("  enter=accept all · n,n=remove those lines · q=cancel: ").strip()
        if not ans:
            break
        if ans.lower() == "q":
            print("aborted — nothing written")
            return
        try:
            idxs = {int(i.strip()) for i in ans.split(",") if i.strip()}
            if any(i >= len(rows) for i in idxs):
                print("  ✗ 行号越界 — 列出的是上面的编号"); continue
        except ValueError:
            print("  ✗ 无法解析 — 例:2,4 或直接回车"); continue
        _remove_lines(suggested, rows, idxs)
        proposed.write_text(json.dumps(suggested, indent=2, ensure_ascii=False))
        print(f"  ✓ 已移除 {len(idxs)} 行,继续审阅")

    r = authorize.approve_core(manifest, tool_dir)
    print(f"\n[contract] {tool} APPROVED + LOCKED (settings sha256 {r['settings_sha256']}…)\n"
          f"          boundary: {r['boundary']}")


def revoke_tool(tool: str) -> None:
    """Remove authorization (contract.json gone → unmanaged)."""
    manifest = load_manifest(tool)
    r = authorize.revoke(manifest, TOOLS_DIR / tool)
    print(f"[contract] {r['tool']}: {r['decision']} — {r.get('detail', '')}")


def status_all() -> None:
    """Human-readable overview: every tool × its authorization state."""
    rows = authorize.status_all(TOOLS_DIR)
    if not rows:
        print("no tools under " + str(TOOLS_DIR))
        return
    width = max(len(r["tool"]) for r in rows) + 2
    for r in rows:
        print(f"  {r['tool']:<{width}} {r['state']:<10} "
              f"net=[{r['network']}] writes=[{r['writes']}] "
              f"approved {r['approved_at']}")


def main() -> None:
    """CLI entry: dispatch on subcommand flags."""
    ap = argparse.ArgumentParser(prog="observe")
    ap.add_argument("tool", nargs="?", default=None, help="tool name under tools/")
    ap.add_argument("inputs", nargs="*", default=[])
    ap.add_argument("--scan", action="store_true",
                    help="srt permission discovery → srt-settings.json.proposed")
    ap.add_argument("--onboard", action="store_true",
                    help="wizard: scan → permission table → trim → approve & lock")
    ap.add_argument("--approve", action="store_true",
                    help="legislate: accept settings + lock contract")
    ap.add_argument("--revoke", action="store_true",
                    help="remove authorization (back to unmanaged)")
    ap.add_argument("--check-requires", action="store_true",
                    help="pre-flight requires hard check")
    ap.add_argument("--status", action="store_true",
                    help="overview: every tool × authorization state")
    ap.add_argument("--yes", action="store_true",
                    help="skip interactive confirm")
    args = ap.parse_args()

    if args.status:
        status_all()
        return
    if not args.tool:
        ap.print_help()
        return
    if args.onboard:
        onboard(args.tool, args.inputs, yes=args.yes)
        return
    if args.scan:
        scan_tool(args.tool, args.inputs)
        return
    if args.approve:
        approve_tool(args.tool, yes=args.yes)
        return
    if args.revoke:
        revoke_tool(args.tool)
        return
    if args.check_requires:
        check_requires(args.tool, args.inputs)
        return
    ap.print_help()


if __name__ == "__main__":
    main()