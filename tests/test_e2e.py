import asyncio
import pathlib
import shutil

import pytest
from fastmcp import FastMCP

import server
from observe import observe

ROOT = pathlib.Path(__file__).parent.parent


@pytest.mark.slow
def test_cpp_tool_registers():
    mcp = FastMCP("test")
    server.load_tools(mcp, ROOT / "tools")
    names = asyncio.run(mcp.list_tools())
    assert "cpp_test" in [t.name for t in names]


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker required")
def test_observe_cpp_test_passes():
    r = observe("cpp-test", ["hello"])
    assert r["verdict"] == "pass"


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("docker") is None, reason="docker required")
def test_observe_evil_write_fails():
    r = observe("evil-write", ["x"])
    assert r["verdict"] == "fail"
    assert any(v["class"] == "file-write" for v in r["violations"])
