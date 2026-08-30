import pathlib
from fastmcp import FastMCP
import yaml

from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    @mcp.tool
    def us_market(ticker: str, range: str = "1y", interval: str = "1d") -> dict:
        """美股技术面快照：MA/区间位置/动能。经决策闸 + telemetry"""
        return gate.gated_invoke(manifest, [ticker, range, interval], _TOOL_DIR)