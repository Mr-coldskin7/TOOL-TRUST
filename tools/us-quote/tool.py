import pathlib
from fastmcp import FastMCP
import yaml

from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    @mcp.tool
    def us_quote(ticker: str) -> dict:
        """查询美股实时行情（Yahoo Finance，无 key）。经决策闸 + telemetry"""
        return gate.gated_invoke(manifest, [ticker], _TOOL_DIR)