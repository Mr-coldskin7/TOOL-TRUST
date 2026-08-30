import pathlib
from fastmcp import FastMCP
import yaml
from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    @mcp.tool
    def cache_tool(entry: str) -> dict:
        """往 /tmp/cache.log 追加一行"""
        return gate.gated_invoke(manifest, [entry], _TOOL_DIR)
