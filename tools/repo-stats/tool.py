import pathlib
from fastmcp import Context, FastMCP
import yaml
from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    def repo_stats(root: str = "", ctx: Context | None = None) -> dict:
        """仓库概览（不传 root 时在体检容器里扫 /repo）"""
        return gate.gated_invoke(manifest, [root] if root else [], _TOOL_DIR, caller=ctx.client_id if ctx else None)

    repo_stats.__doc__ = f"{repo_stats.__doc__}\n\n{gate.contract_boundary(manifest, _TOOL_DIR)}"
    mcp.tool(repo_stats)
