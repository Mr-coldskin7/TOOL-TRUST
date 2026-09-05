"""attest observation CLI — srt-native (no Docker, no strace).

Everything happens inside sandbox-runtime:

  1. `--scan <tool> [input...]`  — run the tool in a MINIMAL srt sandbox, read
     what it needed (blocked hosts / EPERM paths) → suggested srt-settings
     written to `srt-settings.json.proposed` (reviewable, diff-able).
  2. `--approve`                 — operator legislates: prints a human-readable
     permission summary of exactly what will be allowed, then accepts the
     proposed settings (or the existing srt-settings.json), commits
     contract.json with the SETTINGS CONTENT HASHED IN — an approved tool's
     permissions are locked; any later change flips the gate to
     contract-mismatch.
  3. `--check-requires`          — pre-flight prerequisites hard check.

Usage:
  python observe.py <tool> --scan [input...]        # propose permissions
  python observe.py <tool> --approve [--yes]        # legislate + lock
  python observe.py <tool> --check-requires         # requires pre-flight
"""
import argparse
import hashlib
import json
import pathlib
import shutil

import yaml

from attest import contract, prereq, scan as scan_mod

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


def scan_tool(tool: str, inputs: list[str]) -> None:
    """srt permission discovery: propose what the tool needs.

    Evidence (suggested settings) lands at <tool>/srt-settings.json.proposed.
    Nothing is enabled yet — approval is the legislative step.
    """
    from attest.gate import format_command

    manifest = load_manifest(tool)
    tool_dir = TOOLS_DIR / tool
    argv = format_command(manifest, inputs, tool_dir)
    r = scan_mod.scan(argv, cwd=str(tool_dir))
    print(json.dumps({"tool": tool, **r}, ensure_ascii=False, indent=2))

    proposed = tool_dir / f"srt-settings.json{PROPOSED_SUFFIX}"
    proposed.write_text(json.dumps(r["suggested"], indent=2, ensure_ascii=False))
    print(f"\n>>> suggested permissions written to {proposed}:\n"
          + permission_summary(manifest, r["suggested"]))
    print(f"\n    review it — then run:  observe.py {tool} --approve   "
          "(y/N confirms and LOCKS these permissions)")


def _load_settings(tool_dir: pathlib.Path, name: str) -> dict:
    """Loads the settings file (existing or proposed), promoting proposed on approve."""
    target = tool_dir / name
    if target.exists():
        return json.loads(target.read_text())
    raise SystemExit(f"{target} missing; run `observe.py --scan` first to propose one")


def approve_tool(tool: str, yes: bool = False) -> None:
    """Operator confirmation: scan evidence → enforceable, LOCKED contract.

    Approving accepts the settings (promotes srt-settings.json.proposed if the
    formal file is absent), shows a human-readable permission summary, and
    writes contract.json with the settings content hashed in — so any later
    edit of srt-settings.json flips the gate to contract-mismatch.
    """
    from attest.provenance import compute_tool_hash

    tool_dir = TOOLS_DIR / tool
    manifest = load_manifest(tool)
    claims = manifest.get("claims")
    if not claims:
        raise SystemExit(
            f"no claims to approve; run `observe.py {tool} --scan` first")

    sb = manifest.get("sandbox") or {}
    sb_name = sb.get("srt_settings")
    if not sb_name:
        raise SystemExit(
            f"no sandbox.srt_settings in {tool}/tool.yaml; run `observe.py {tool} --scan` first")
    target = tool_dir / sb_name
    if not target.exists():
        pp = tool_dir / f"srt-settings.json{PROPOSED_SUFFIX}"
        if not pp.exists():
            raise SystemExit(f"nothing to accept: {target} missing and no "
                             f"srt-settings.json{PROPOSED_SUFFIX} from --scan")
        shutil.copyfile(pp, target)
        print(f"[contract] promoting {pp.name} → {target.name}")

    settings = _load_settings(tool_dir, sb_name)
    print(f"[contract] reviewing {tool} — EXACT permissions to be locked in:\n"
          + permission_summary(manifest, settings))
    if not yes:
        if input("Approve and LOCK these permissions? [y/N] ").strip().lower() not in ("y", "yes"):
            print("aborted — nothing written")
            return

    contract.approve(claims)
    claims["approved_by"] = "operator"
    (tool_dir / "tool.yaml").write_text(
        yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False))

    settings_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    prov = manifest.get("provenance")
    snapshot = {
        "schema": 2,
        "tool": tool,
        "verdict": "pass",
        "claims": claims,
        "sandbox": {
            "srt_settings": sb_name,
            "srt_settings_sha256": settings_hash,
        },
        "provenance": {
            "version": prov.get("version") if prov else None,
            "hash": compute_tool_hash(tool_dir),
        },
        "approved_by": claims.get("approved_by"),
        "approved_at": claims.get("approved_at"),
    }
    (tool_dir / "contract.json").write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2))
    (tool_dir / f"srt-settings.json{PROPOSED_SUFFIX}").unlink(missing_ok=True)
    print(f"[contract] {tool} APPROVED + LOCKED (settings sha256 {settings_hash[:12]}…)\n"
          f"          {tool_dir / 'contract.json'} written — edit srt-settings.json "
          "now ⇒ contract-mismatch on next call")


def status_all() -> None:
    """Human-readable overview: every tool × its authorization state."""
    from attest.contract import contract_boundary

    rows: list[tuple[str, str]] = []
    for d in sorted(TOOLS_DIR.iterdir()):
        ym = d / "tool.yaml"
        if not ym.is_file():
            continue
        try:
            m = yaml.safe_load(ym.read_text())
        except OSError:
            continue
        name = m.get("name", d.name)
        rows.append((name, contract_boundary(m, d)))
    if not rows:
        print("no tools under " + str(TOOLS_DIR))
        return
    width = max(len(n) for n, _ in rows) + 2
    print("\n".join(f"{n:<{width}}{b}" for n, b in rows))


def main() -> None:
    """CLI entry: dispatch on subcommand flags."""
    ap = argparse.ArgumentParser(prog="observe")
    ap.add_argument("tool", nargs="?", default=None, help="tool name under tools/")
    ap.add_argument("inputs", nargs="*", default=[])
    ap.add_argument("--scan", action="store_true",
                    help="srt permission discovery → srt-settings.json.proposed")
    ap.add_argument("--approve", action="store_true",
                    help="legislate: accept settings + lock contract (contract.json)")
    ap.add_argument("--check-requires", action="store_true",
                    help="pre-flight requires hard check")
    ap.add_argument("--status", action="store_true",
                    help="overview: every tool × authorization state")
    ap.add_argument("--yes", action="store_true",
                    help="skip interactive confirm (with --approve)")
    args = ap.parse_args()

    if args.status:
        status_all()
        return
    if not args.tool:
        ap.print_help()
        return
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