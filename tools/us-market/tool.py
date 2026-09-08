import pathlib
from fastmcp import Context, FastMCP
import yaml

from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    def us_market(ticker: str, range: str = "1y", interval: str = "1d", ctx: Context | None = None) -> dict:
        """美股技术面快照：MA/区间位置/动能。经决策闸 + telemetry"""
        return gate.gated_invoke(manifest, [ticker, range, interval], _TOOL_DIR, caller=ctx.client_id if ctx else None)

    us_market.__doc__ = f"{us_market.__doc__}\n\n{gate.contract_boundary(manifest, _TOOL_DIR)}"
    mcp.tool(us_market)
