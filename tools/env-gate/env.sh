#!/bin/sh
# 依赖环境变量 TOOL_TRUST_DEMO_KEY；缺失时 gate 应硬拒(不运行，省 token)
[ -n "$TOOL_TRUST_DEMO_KEY" ] || { echo "missing TOOL_TRUST_DEMO_KEY" >&2; exit 1; }
echo "env ok: ${TOOL_TRUST_DEMO_KEY}"
