# server.py
import importlib
import pathlib
from fastmcp import FastMCP

from attest import gate


def load_tools(mcp: FastMCP, tools_dir: pathlib.Path = pathlib.Path("tools")) -> int:
    """扫描 tools/*/tool.py，import 并调用其 register(mcp)。返回加载数。

    消费闸门一：注册前拒绝不合规工具 —— 带缓存 attestation report 且 verdict=fail
    的工具目录直接跳过(不 import、不注册)，agent 根本看不到它。
    """
    count = 0
    for p in sorted(tools_dir.glob("*/tool.py")):
        if gate.load_attestation_verdict(p.parent) == "fail":
            continue  # attestation fail → 拒绝注册
        module_path = f"{tools_dir.name}.{p.parent.name}.tool"
        mod = importlib.import_module(module_path)
        mod.register(mcp)
        count += 1
    return count


if __name__ == "__main__":
    import sys

    mcp = FastMCP("toolhub")
    n = load_tools(mcp)
    print(f"loaded {n} tool(s)", file=sys.stderr)  # stdio 时 stdout 只走 MCP 协议

    if "--stdio" in sys.argv:
        mcp.run(transport="stdio")
    else:
        print(f"toolhub HTTP on http://localhost:8000/mcp")
        mcp.run(transport="http", port=8000)
