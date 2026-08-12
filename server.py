# server.py
import importlib
import pathlib
from fastmcp import FastMCP


def load_tools(mcp: FastMCP, tools_dir: pathlib.Path = pathlib.Path("tools")) -> int:
    """扫描 tools/*/tool.py，import 并调用其 register(mcp)。返回加载数。"""
    count = 0
    for p in sorted(tools_dir.glob("*/tool.py")):
        module_path = f"{tools_dir.name}.{p.parent.name}.tool"
        mod = importlib.import_module(module_path)
        mod.register(mcp)
        count += 1
    return count


if __name__ == "__main__":
    mcp = FastMCP("toolhub")
    n = load_tools(mcp)
    print(f"loaded {n} tool(s)")
    mcp.run(transport="http", port=8000)
