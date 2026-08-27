"""pytest 全局配置：所有测试统一把 telemetry 指向临时文件，避免污染 runtime/。"""
import pathlib
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _isolate_telemetry(tmp_path, monkeypatch):
    """每个测试的 telemetry 日志定向到独立临时文件。"""
    log = tmp_path / "telemetry.jsonl"
    monkeypatch.setenv("TOOL_TRUST_TELEMETRY", str(log))
    return log