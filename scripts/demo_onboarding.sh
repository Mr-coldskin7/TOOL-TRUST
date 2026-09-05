#!/usr/bin/env bash
# Onboarding demo: shows the scan → approve → lock → tamper flow on a sample tool.
#   uv run python scripts/demo_onboarding.py
set -euo pipefail
cd "$(dirname "$0")/.."

T=demo-fetch
DIR="tools/$T"
SETTINGS="$DIR/srt-settings.json"
PROPOSED="$SETTINGS.proposed"

echo "═════════ ① 初始状态(未授权) ═════════"
rm -f "$SETTINGS" "$PROPOSED" "$DIR/contract.json" /tmp/demo-fetch.log
uv run python observe.py --status | grep "$T" || true
echo
echo "  —— agent 视角(MCP 工具描述) ——"
uv run python - <<'PY'
import asyncio, server
from fastmcp import FastMCP
async def main():
    mcp = FastMCP("toolhub"); server.load_tools(mcp)
    for t in await mcp.list_tools():
        if t.name == "demo_fetch":
            print("   " + t.description.replace("\n", " "))
asyncio.run(main())
PY

echo
echo "═════════ ② 观察(--scan):把工具放进最小沙箱,看它需要什么 ═════════"
uv run python observe.py "$T" --scan
echo
echo "  —— 落盘的授权建议 --"
echo "  proposed settings → $PROPOSED"
sed 's/^/    /' "$PROPOSED"

echo
echo "═════════ ③ 授权(--approve):权限摘要 + y/N 锁定 ═════════"
uv run python observe.py "$T" --approve --yes

echo
echo "═════════ ④ 授权后状态 ═════════"
echo "  observe.py --status:"
uv run python observe.py --status | grep "$T"
echo
echo "  agent 视角(MCP 工具描述):"
uv run python - <<'PY'
import asyncio, server
from fastmcp import FastMCP
async def main():
    mcp = FastMCP("toolhub"); server.load_tools(mcp)
    for t in await mcp.list_tools():
        if t.name == "demo_fetch":
            print("   " + t.description.replace("\n", " "))
asyncio.run(main())
PY
echo
echo "  实际执行(经 srt 强制):"
uv run python - <<'PY'
import pathlib, yaml
from attest.gate import gated_invoke
p = pathlib.Path("tools/demo-fetch")
m = yaml.safe_load((p / "tool.yaml").read_text())
r = gated_invoke(m, [], p)
print("   decision=%s reason=%s rc=%s violations=%s" % (r.get("decision"), r.get("reason"), r.get("returncode"), r.get("violations")))
print("   out:", str(r.get("stdout"))[:80])
PY

echo
echo "═════════ ⑤ 破坏演示:事后多放行一个域名 → gate 拒绝 ═════════"
cp "$SETTINGS" /tmp/demo-settings.bak
uv run python - <<'PY'
import json
p = "tools/demo-fetch/srt-settings.json"
d = json.load(open(p))
d["network"]["allowedDomains"].append("evil.cz")
json.dump(d, open(p, "w"))
print("   篡改:allowedDomains 加了 evil.cz")
PY
uv run python - <<'PY'
import pathlib, yaml
from attest.gate import gated_invoke
p = pathlib.Path("tools/demo-fetch")
m = yaml.safe_load((p / "tool.yaml").read_text())
r = gated_invoke(m, [], p)
print("   decision=%s reason=%s" % (r.get("decision"), r.get("reason")))
print("   detail:", r.get("detail", "")[:80])
PY
mv /tmp/demo-settings.bak "$SETTINGS"
echo "  (settings 已复原)"

echo
echo "═════════ 完 ═════════"
echo "  这个工具现在是已授权的 sample:observe.py --status 里 demo-fetch 为 operator-approved。"