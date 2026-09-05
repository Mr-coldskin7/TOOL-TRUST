import pathlib
from fastmcp import FastMCP
import yaml
from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    def repo_stats(root: str = "") -> dict:
        """仓库概览（不传 root 时在体检容器里扫 /repo）"""
        return gate.gated_invoke(manifest, [root] if root else [], _TOOL_DIR)

    repo_stats.__doc__ = f"{repo_stats.__doc__}\n\n{gate.contract_boundary(manifest, _TOOL_DIR)}"
    mcp.tool(repo_stats)
