import pathlib
from fastmcp import FastMCP
import yaml
from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    @mcp.tool
    def sha_tool(text: str) -> dict:
        """计算输入字符串的 SHA-256"""
        return gate.gated_invoke(manifest, [text], _TOOL_DIR)
