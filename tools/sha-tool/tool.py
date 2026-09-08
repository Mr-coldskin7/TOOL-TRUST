import pathlib
from fastmcp import Context, FastMCP
import yaml
from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    def sha_tool(text: str, ctx: Context | None = None) -> dict:
        """计算输入字符串的 SHA-256"""
        return gate.gated_invoke(manifest, [text], _TOOL_DIR, caller=ctx.client_id if ctx else None)

    sha_tool.__doc__ = f"{sha_tool.__doc__}\n\n{gate.contract_boundary(manifest, _TOOL_DIR)}"
    mcp.tool(sha_tool)
