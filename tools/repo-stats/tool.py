import pathlib
from fastmcp import FastMCP
import yaml
from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    @mcp.tool
    def repo_stats(root: str = "") -> dict:
        """仓库概览（不传 root 时在体检容器里扫 /repo）"""
        return gate.gated_invoke(manifest, [root] if root else [], _TOOL_DIR)
