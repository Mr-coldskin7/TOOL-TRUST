"""Live execution backend: run tool calls inside a mature sandbox (srt).

Replaces strace-based observation at RUNTIME (gate). srt (anthropics/
sandbox-runtime) provides the constraints (network domain allowlist,
filesystem denies) and the violation trigger; we are consumers of both —
we do not write policy ourselves.

Requirements:
  - macOS: sandbox-exec (system) + npm i -g @anthropic-ai/sandbox-runtime
  - Linux: bubblewrap (srt's Linux backend)

Violations surface on stderr (srt --debug) as:
  [SandboxDebug] No matching config rule, denying: google.com:443
  [SandboxDebug] Connection blocked to google.com:443
stdout stays the tool's clean output.
"""
import pathlib
import re
import shlex
import shutil
import subprocess

INSTALL_HINT = "npm install -g @anthropic-ai/sandbox-runtime  (and for Linux: brew install bubblewrap / apt install bubblewrap)"

# lines that carry denial context from --debug
_BLOCKED_RE = re.compile(r"\[SandboxDebug\] Connection blocked to ([^:\s]+)(?::(\d+))?")
_DENYING_RE = re.compile(r"\[SandboxDebug\].*denying: ([^:\s]+)(?::(\d+))?")


def ensure_srt() -> str:
    """Return srt binary path; raise RuntimeError with install hint if missing."""
    p = shutil.which("srt")
    if p is None:
        raise RuntimeError(f"srt (sandbox-runtime) is required for enforcement: {INSTALL_HINT}")
    return p


def violation_events(stderr: str) -> list[dict]:
    """Parse srt --debug denial context into violation events.

    Args:
      stderr: captured stderr from an srt run.

    Returns:
      List of {"kind": "net-block", "target": host, "port": int|None}.
    """
    out = []
    seen = set()
    for m in _BLOCKED_RE.finditer(stderr):
        ev = {"kind": "net-block", "target": m.group(1),
              "port": int(m.group(2)) if m.group(2) else None}
        key = (ev["kind"], ev["target"], ev["port"])
        if key not in seen:
            seen.add(key)
            out.append(ev)
    for m in _DENYING_RE.finditer(stderr):
        ev = {"kind": "net-deny", "target": m.group(1),
              "port": int(m.group(2)) if m.group(2) else None}
        key = (ev["kind"], ev["target"], ev["port"])
        if key not in seen:
            seen.add(key)
            out.append(ev)
    return out


def run_sandboxed(
    argv: list[str],
    settings_path: pathlib.Path | str,
    cwd: str | None = None,
    timeout: int = 300,
) -> dict:
    """Run a command via srt with the given settings file.

    Args:
      argv: command + args (e.g. ["python3", "cache.py", "x"]).
      settings_path: SRT settings JSON (the approved contract).
      cwd: working directory.
      timeout: seconds.

    Returns:
      {"returncode", "stdout", "stderr", "violations"}.
    """
    ensure_srt()
    # settings must be absolute: subprocess cwd already points at the tool dir,
    # a relative path would nest and fail to load
    resolved = str(pathlib.Path(settings_path).expanduser().resolve())
    cmd = ["srt", "--debug", "--settings", resolved, "-c", shlex.join(argv)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "timeout",
                "violations": [], "timed_out": True}
    return {
        "returncode": r.returncode,
        "stdout": r.stdout,
        "stderr": r.stderr,
        "violations": violation_events(r.stderr),
        "timed_out": False,
    }