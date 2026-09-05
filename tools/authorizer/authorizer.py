"""Authorization management backend for the authorizer MCP tool.

Actions mirror the CLI: status / onboard (scan evidence, no approval) /
approve (legislation — requires human confirmation via the MCP permission
system) / revoke.
"""

import json
import pathlib
import sys

import yaml

from attest import authorize, scan as scan_mod
from attest.gate import format_command

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "tools"


def _load(tool: str) -> tuple[dict, pathlib.Path]:
    d = TOOLS_DIR / tool
    if not (d / "tool.yaml").exists():
        raise SystemExit(f"no such tool: {tool}")
    m = yaml.safe_load((d / "tool.yaml").read_text())
    return m, d


def _onboard(tool: str, inputs: list[str]) -> None:
    """Scan inside the minimal sandbox → propose settings; NO approval here."""
    m, d = _load(tool)
    argv = format_command(m, inputs, d)
    r = scan_mod.scan(argv, cwd=str(d))
    proposed = d / "srt-settings.json.proposed"
    proposed.write_text(json.dumps(r["suggested"], indent=2, ensure_ascii=False))
    if not (m.get("sandbox") or {}).get("srt_settings"):
        m["sandbox"] = {"srt_settings": "srt-settings.json"}
        (d / "tool.yaml").write_text(yaml.safe_dump(m, allow_unicode=True, sort_keys=False))
    out = {
        "tool": tool,
        "action": "onboard-scan-done",
        "denials": r["denials"],
        "permissions": authorize.permission_rows(m, r["suggested"]),
        "proposed_file": str(proposed),
        "next": "authorizer.approve(%s) after human review" % tool,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: authorizer.py <status|onboard|approve|revoke> [tool] [input...]")
        sys.exit(1)
    action, *rest = sys.argv[1:]

    if action == "status":
        rows = authorize.status_all(TOOLS_DIR)
        print(f"{'tool':<16} {'state':<10} {'net':<36} {'writes':<28} approved")
        for r in rows:
            print(f"{r['tool']:<16} {r['state']:<10} {r['network']:<36} "
                  f"{r['writes']:<28} {r['approved_at']}")
        return

    if not rest:
        print(f"authorizer.{action} needs a tool name")
        sys.exit(1)
    tool, *inputs = rest
    m, d = _load(tool)

    if action == "onboard":
        _onboard(tool, inputs)
    elif action == "approve":
        out = authorize.approve_core(m, d)
        print(f"{out['decision']} {out['tool']} sha256={out['settings_sha256']} "
              f"promoted={out['promoted']}")
        print(out["boundary"])
    elif action == "revoke":
        out = authorize.revoke(m, d)
        print(f"{out['decision']} {out['tool']} — {out.get('detail', '')}")
    else:
        print(f"unknown authorizer action: {action}")
        sys.exit(1)


if __name__ == "__main__":
    main()