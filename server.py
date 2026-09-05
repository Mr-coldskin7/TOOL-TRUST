"""MCP server: auto-load tools from tools/*/tool.py, filtering failed attestation.

Consumption gate: a tool directory with a cached report verdict=fail is skipped
at registration — the agent never even sees it.
"""
import importlib
import pathlib

from fastmcp import FastMCP

from attest import gate


def load_tools(mcp: FastMCP, tools_dir: pathlib.Path = pathlib.Path("tools")) -> int:
    """Scan tools/*/tool.py, import each, call register(mcp). Returns count loaded.

    Args:
      mcp:       FastMCP instance to register tools on.
      tools_dir: tool root directory.

    Returns:
      Number of successfully loaded tools.
    """
    count = 0
    for p in sorted(tools_dir.glob("*/tool.py")):
        if gate.load_attestation_verdict(p.parent) == "fail":
            continue  # failed attestation → refuse registration
        module_path = f"{tools_dir.name}.{p.parent.name}.tool"
        mod = importlib.import_module(module_path)
        mod.register(mcp)
        count += 1
    return count


if __name__ == "__main__":
    import sys

    mcp = FastMCP("toolhub")
    n = load_tools(mcp)
    print(f"loaded {n} tool(s)", file=sys.stderr)  # stdio: stdout stays MCP protocol

    if "--stdio" in sys.argv:
        mcp.run(transport="stdio")
    else:
        print(f"toolhub HTTP on http://localhost:8000/mcp")
        import pathlib as _pl
        import yaml as _yaml
        from attest.contract import contract_boundary
        print("── tool authorization overview ────────────")
        for p in sorted(_pl.Path("tools").glob("*/tool.yaml")):
            try:
                m = _yaml.safe_load(p.read_text())
                print(" ", contract_boundary(m, p.parent))
            except Exception:
                continue
        mcp.run(transport="http", port=8000)