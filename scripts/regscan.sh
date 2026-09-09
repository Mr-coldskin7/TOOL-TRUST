#!/usr/bin/env bash
# regscan.sh — scheduled registry health review, driven by the pi CLI agent.
#
# What it does:
#   1. ONE pi agent call (non-interactive, read-only tool profile) that runs
#      `observe.py --find-dups` + `observe.py --status` and summarizes:
#        - near-duplicate candidate pairs (with reasons)
#        - authorization anomalies (unmanaged / drifted / unreadable)
#   2. Writes a markdown report to runtime/regscan-<ts>.md
#   3. Posts a macOS notification with the summary count
#
# It NEVER modifies tools/ — the agent is allowed only read + bash(reading),
# and the script itself only writes under runtime/.
#
# Schedule it (choose one; edit the PWD):
#   cron:  30 8 * * 1 cd /Users/lishanyi/Documents/projects/tool-trust && bash scripts/regscan.sh >> runtime/regscan.log 2>&1
#   launchd: copy scripts/com.tooltrust.regscan.plist into ~/Library/LaunchAgents
#
# Manual run: bash scripts/regscan.sh [--report-dir <dir>]
set -euo pipefail
cd "$(dirname "$0")/.."

REPORT_DIR="runtime"
if [[ "${1:-}" == "--report-dir" ]]; then REPORT_DIR="${2:-runtime}"; fi
mkdir -p "$REPORT_DIR"
TS=$(date +%Y%m%d-%H%M%S)
OUT="$REPORT_DIR/regscan-$TS.md"

PROMPT='你是 TOOL-TRUST 仓库的只读例行审查员。在 /Users/lishanyi/Documents/projects/tool-trust 下:
1) 运行: uv run python observe.py --find-dups
2) 运行: uv run python observe.py --status
然后输出一份 markdown 审查报告,包含:
## 重复候选   —— 每组:两个工具名、相似理由(同端点/同自定义写路径)、目录、你的合并/删除建议(仅建议)
## 授权异常   —— 列出 unmanaged / drifted / unreadable 的工具与原因
## 总体结论   —— 一段话。
硬性约束:只读巡检;绝不允许修改、创建、删除仓库内任何文件(包括 tools/ 与 runtime/ 以外的写入);不要输出多余寒暄。'

# run the agent read-only
pi -p --exclude-tools "edit,write" \
  --append-system-prompt "Read-only review session. Do not modify any repository files." \
  "$PROMPT" > "$OUT" 2> "$REPORT_DIR/regscan-$TS.err" || {
  echo "pi agent failed — see $REPORT_DIR/regscan-$TS.err"
  exit 1
}

# macOS banner: line count of candidates
N=$(grep -c "dirs:" "$OUT" || true)
osascript -e "display notification \"注册表审查完成: $N 组重复候选 → $OUT\" with title \"tool-trust regscan\"" >/dev/null 2>&1 || true
echo "regscan done → $OUT"