# tests/test_server.py
import sys
from fastmcp import FastMCP
import server


def _write_toolpy(tool_dir, name):
    tool_dir.mkdir(parents=True)
    (tool_dir / "tool.py").write_text(
        "from fastmcp import FastMCP\n"
        "def register(mcp: FastMCP) -> None:\n"
        "    @mcp.tool\n"
        f"    def {name}() -> str:\n"
        f"        '''{name}'''\n"
        "        return 'ok'\n"
    )


def test_load_tools_registers_each_tool(tmp_path):
    _write_toolpy(tmp_path / "tools" / "demo", "demo")
    sys.path.insert(0, str(tmp_path))
    try:
        mcp = FastMCP("test")
        count = server.load_tools(mcp, tmp_path / "tools")
        assert count == 1
    finally:
        sys.path.remove(str(tmp_path))


def test_load_tools_skips_fail_attestation(tmp_path):
    _write_toolpy(tmp_path / "tools" / "good", "good_tool")
    _write_toolpy(tmp_path / "tools" / "bad", "bad_tool")
    (tmp_path / "tools" / "bad" / "contract.json").write_text('{"verdict": "fail"}')
    sys.path.insert(0, str(tmp_path))
    try:
        mcp = FastMCP("test")
        count = server.load_tools(mcp, tmp_path / "tools")
        assert count == 1  # bad 因 attestation fail 被拒绝注册,只剩 good
    finally:
        sys.path.remove(str(tmp_path))


def test_load_tools_registers_pass_attestation(tmp_path):
    _write_toolpy(tmp_path / "tools" / "t", "t")
    (tmp_path / "tools" / "t" / "contract.json").write_text('{"verdict": "pass"}')
    sys.path.insert(0, str(tmp_path))
    try:
        mcp = FastMCP("test")
        assert server.load_tools(mcp, tmp_path / "tools") == 1
    finally:
        sys.path.remove(str(tmp_path))
