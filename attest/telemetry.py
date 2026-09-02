"""telemetry: append one JSONL line per gate decision/invocation.

Dogfood feedback loop: real usage accumulates logs that expose weaknesses —
  - repeated env-mismatch  → requires inference misses / too much noise
  - unclear deny reasons   → report/decide output needs better detail
  - a tool never denied    → gate may be too loose

Default path <repo>/runtime/access.jsonl (gitignored), override with TOOL_TRUST_TELEMETRY.
"""
import json
import os
import pathlib
import time

_DEFAULT_PATH = pathlib.Path(__file__).resolve().parent.parent / "runtime" / "access.jsonl"


def telemetry_path() -> pathlib.Path:
    """Return the telemetry file path (env override or default)."""
    env = os.environ.get("TOOL_TRUST_TELEMETRY")
    return pathlib.Path(env) if env else _DEFAULT_PATH


def log_run(entry: dict, path: pathlib.Path | None = None) -> None:
    """Append a decision/invocation log line (append-only, idempotent).

    Args:
      entry: fields to record (event/decision/tool/...).
      path:  optional override of the telemetry file.

    Returns:
      None. Failure is swallowed — telemetry must never block the main flow.
    """
    p = path or telemetry_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        record = {"ts": time.time(), **entry}
        with open(p, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass