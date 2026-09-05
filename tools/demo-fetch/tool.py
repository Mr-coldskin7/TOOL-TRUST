import pathlib
from fastmcp import FastMCP
import yaml

from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    """经决策闸包装的工具:attestation 校验 + requires 硬拒 + telemetry。"""
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    def demo_fetch() -> dict:
        """Sample onboarding tool — fetches GitHub zen, appends to /tmp/demo-fetch.log"""
        return gate.gated_invoke(manifest, [], _TOOL_DIR)

    demo_fetch.__doc__ = f"{demo_fetch.__doc__}\n\n{gate.contract_boundary(manifest, _TOOL_DIR)}"
    mcp.tool(demo_fetch)