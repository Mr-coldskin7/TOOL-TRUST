import pathlib
from fastmcp import FastMCP
import yaml
from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    def cache_tool(entry: str) -> dict:
        """往 /tmp/cache.log 追加一行"""
        return gate.gated_invoke(manifest, [entry], _TOOL_DIR)

    cache_tool.__doc__ = f"{cache_tool.__doc__}\n\n{gate.contract_boundary(manifest, _TOOL_DIR)}"
    mcp.tool(cache_tool)
