import pathlib
from fastmcp import FastMCP
import yaml
from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    def env_gate() -> dict:
        """依赖 TOOL_TRUST_DEMO_KEY；缺失 gate 硬拒（省 token）"""
        return gate.gated_invoke(manifest, [], _TOOL_DIR)

    env_gate.__doc__ = f"{env_gate.__doc__}\n\n{gate.contract_boundary(manifest, _TOOL_DIR)}"
    mcp.tool(env_gate)
