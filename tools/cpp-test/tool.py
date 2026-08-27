import pathlib
from fastmcp import FastMCP
import yaml

from attest import gate

_TOOL_DIR = pathlib.Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    manifest = yaml.safe_load((_TOOL_DIR / "tool.yaml").read_text())

    @mcp.tool
    def cpp_test(message: str) -> dict:
        """把输入消息转大写输出（C++ 二进制）。经决策闸：attestation 校验 + requires 硬拒"""
        return gate.gated_invoke(manifest, [message], _TOOL_DIR)
