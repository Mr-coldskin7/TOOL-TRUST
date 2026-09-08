import datetime
import json
import pathlib
import subprocess

from fastmcp import FastMCP

_TOOL_DIR = pathlib.Path(__file__).resolve().parent
_BIN = _TOOL_DIR / "cal"


def register(mcp: FastMCP) -> None:
    def calendar_add(
        title: str,
        start: str,
        end: str,
        calendar: str = "个人",
        location: str = "",
        notes: str = "",
    ) -> dict:
        """添加事件到 Apple 日历 (EventKit)。时间格式 ISO8601，如 2026-10-11T09:00:00+08:00。"""
        if not (_BIN).exists():
            # 首次使用：编译 swift 源
            subprocess.run(
                ["swiftc", str(_TOOL_DIR / "cal.swift"), "-o", str(_BIN)],
                check=True, capture_output=True,
            )
        proc = subprocess.run(
            [str(_BIN), "add", title, start, end, calendar, location, notes],
            capture_output=True, text=True, timeout=60,
        )
        return {"ok": proc.returncode == 0, "output": proc.stdout.strip() or proc.stderr.strip()}

    def calendar_list() -> dict:
        """列出 Apple 日历中所有可写日历。"""
        if not (_BIN).exists():
            subprocess.run(
                ["swiftc", str(_TOOL_DIR / "cal.swift"), "-o", str(_BIN)],
                check=True, capture_output=True,
            )
        proc = subprocess.run([str(_BIN), "list"], capture_output=True, text=True, timeout=60)
        return {"ok": proc.returncode == 0, "output": proc.stdout.strip() or proc.stderr.strip()}

    calendar_add.__doc__ += (
        "\n\n⚠️ 事件将写入系统 Apple 日历，属于持久写操作。请先 calendar_list 确认日历名再添加。"
    )
    mcp.tool(calendar_add)
    mcp.tool(calendar_list)