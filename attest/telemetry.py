"""telemetry：每次 gate 决策/调用落一条 JSONL，让真实使用产生数据。

dogfood 反馈闭环：工具被真实调用后，日志积累会暴露"哪里不够好"——
  - env-mismatch 反复出现 → requires 反推漏了/噪音太大
  - 拒绝的 reason 太含糊       → report/decide 的决策信息不好读
  - 某工具从未被拒             → gate 可能太松，需要收紧

路径默认 <repo>/runtime/access.jsonl（gitignore），可用 env TOOL_TRUST_TELEMETRY 覆盖。
"""
import json
import os
import pathlib
import time

_DEFAULT_PATH = pathlib.Path(__file__).resolve().parent.parent / "runtime" / "access.jsonl"


def telemetry_path() -> pathlib.Path:
    env = os.environ.get("TOOL_TRUST_TELEMETRY")
    return pathlib.Path(env) if env else _DEFAULT_PATH


def log_run(entry: dict, path: pathlib.Path | None = None) -> None:
    """追加一条决策/调用日志。带 ts 前缀，幂等、append-only。"""
    p = path or telemetry_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        record = {"ts": time.time(), **entry}
        with open(p, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass  # telemetry 失败不阻断主流程