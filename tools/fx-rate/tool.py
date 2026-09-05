import pathlib
from fastmcp import FastMCP
import yaml
from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    def fx_rate(frm: str, to: str, amount: float = 1.0) -> dict:
        """汇率换算（open.er-api.com，第二数据源）"""
        return gate.gated_invoke(manifest, [frm, to, str(amount)], _TOOL_DIR)

    fx_rate.__doc__ = f"{fx_rate.__doc__}\n\n{gate.contract_boundary(manifest, _TOOL_DIR)}"
    mcp.tool(fx_rate)
