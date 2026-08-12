# tests/test_server.py
import sys
from fastmcp import FastMCP
import server


def test_load_tools_registers_each_tool(tmp_path):
    tool_dir = tmp_path / "tools" / "demo"
    tool_dir.mkdir(parents=True)
    (tool_dir / "tool.py").write_text(
        "from fastmcp import FastMCP\n"
        "def register(mcp: FastMCP) -> None:\n"
        "    @mcp.tool\n"
        "    def demo() -> str:\n"
        "        '''demo tool'''\n"
        "        return 'ok'\n"
    )
    sys.path.insert(0, str(tmp_path))
    try:
        mcp = FastMCP("test")
        count = server.load_tools(mcp, tmp_path / "tools")
        assert count == 1
    finally:
        sys.path.remove(str(tmp_path))
