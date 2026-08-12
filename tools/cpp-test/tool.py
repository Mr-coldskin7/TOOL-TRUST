import subprocess
from fastmcp import FastMCP


def register(mcp: FastMCP) -> None:
    @mcp.tool
    def cpp_test(message: str) -> str:
        """把输入消息转大写输出（C++ 二进制）"""
        result = subprocess.run(
            ["./tools/cpp-test/test", message],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"exit {result.returncode}")
        return result.stdout.strip()
