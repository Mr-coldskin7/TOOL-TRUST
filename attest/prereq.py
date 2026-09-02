"""Runtime prerequisites (requires): hard pre-flight check + inference from events.

Division of labor (parallel to claims):
  claims       = side effects the tool "will do"   (checked at attest time)
  requires     = what the tool "needs" to run      (pre-flight, abort if missing)
  consequences = paths the tool touches on the host

Hard check is deterministic: any missing prerequisite → missing list (non-empty
= fail). Default-deny: missing prerequisites mean "cannot guarantee correct run",
so we refuse instead of wasting tokens/compute.
"""
import os
import pathlib
import re
import shutil

# Runtime system noise: excluded from inferred requires (not host dependencies).
NOISE_PREFIXES = (
    "/etc/ld.so", "/etc/localtime", "/etc/machine-id", "/etc/nsswitch.conf",
    "/etc/resolv.conf", "/usr/lib", "/usr/share/zoneinfo", "/usr/lib64", "/lib64",
    "/lib/", "/proc/", "/sys/", "/dev/", "/var/lib/dpkg",
    # observation path inside the container (/src = tool source mount); not a host dep
    "/src",
    # python interpreter internals; not host prerequisites
    "/usr/bin/python3", "/usr/local/bin/python3", "/usr/local/sbin/python3",
    "/usr/sbin/python3", "/usr/local/lib/python3", "/usr/lib/python3",
    "/usr/bin/lib/python3", "/root/.local", "/etc/hosts", "/etc/host.conf",
    "/etc/gai.conf", "/usr/share/locale",
)
# Tool's own toolchain outputs are not host exec deps.
_TOOLCHAIN = ("g++", "gcc", "cc", "ld", "as", "make", "clang", "clang++")

_PATH_RE = re.compile(r'"([^"]*)"')

# Syscalls whose args carry a real path. read/write args are fd + buffer content
# (quoted strings inside) — not paths; excluding them avoids ELF-magic reads.
_PATH_SYSCALLS = {
    "open", "openat", "openat2", "creat",
    "access", "faccessat", "faccessat2",
    "stat", "fstat", "lstat", "newfstatat", "statx",
    "unlink", "unlinkat", "mkdir", "mkdirat", "rmdir",
    "rename", "renameat", "renameat2", "truncate", "ftruncate",
    "chmod", "fchmod", "chown", "fchown", "symlink", "mknod",
}


# ---------- hard check ----------

def _resolve(base: pathlib.Path, p: str) -> pathlib.Path:
    """Resolve a path against base (absolute paths pass through)."""
    return pathlib.Path(p) if os.path.isabs(p) else base / p


def validate_requires(requires: dict | None, cwd: str | None = None) -> list[dict]:
    """Check requires; return missing list (empty = all satisfied).

    Each missing entry has kind + location so the agent can fix the env
    instead of hard-running a tool that cannot work.

    Args:
      requires: manifest requires section.
      cwd:      base dir for relative paths.

    Returns:
      List of {"kind": ..., "name": ..., "detail": ...} for each missing item.
    """
    missing: list[dict] = []
    base = pathlib.Path(cwd) if cwd else pathlib.Path.cwd()
    req = requires or {}

    for var in req.get("env") or []:
        if not os.environ.get(var):
            missing.append(
                {"kind": "env", "name": var, "detail": f"environment variable {var} is not set"}
            )

    for p in req.get("files") or []:
        if not _resolve(base, p).exists():
            missing.append({"kind": "file", "name": p, "detail": f"missing file/dir: {p}"})

    for exe in req.get("exec") or []:
        if shutil.which(exe) is None:
            missing.append(
                {"kind": "exec", "name": exe, "detail": f"executable not on PATH: {exe}"}
            )

    if req.get("cwd"):
        cd = _resolve(base, req["cwd"])
        if not cd.is_dir():
            missing.append(
                {"kind": "cwd", "name": req["cwd"], "detail": f"working dir not found: {req['cwd']}"}
            )

    for w in req.get("writable") or []:
        wp = _resolve(base, w)
        if not wp.exists():
            missing.append({"kind": "writable", "name": w, "detail": f"writable dir missing: {w}"})
        elif not os.access(wp, os.W_OK):
            missing.append(
                {"kind": "writable", "name": w, "detail": f"dir not writable: {w}"}
            )

    return missing


def hard_check(requires: dict | None, cwd: str | None = None) -> dict:
    """Hard-deny wrapper: any missing prerequisite → verdict fail + missing list.

    Args:
      requires: manifest requires section.
      cwd:      base dir for relative paths.

    Returns:
      {"requires": ..., "missing": [...], "verdict": "fail"|"pass", "note": ...}
    """
    missing = validate_requires(requires, cwd)
    return {
        "requires": requires or {},
        "missing": missing,
        "verdict": "fail" if missing else "pass",
        "note": (
            "pre-flight aborted: missing prerequisite(s), refusing to run "
            "(avoid wasting tokens/compute)" if missing else "all prerequisites present"
        ),
    }


# ---------- inference from observed events ----------

def _quoted_path(args: str) -> str | None:
    """Extract the first quoted path from syscall args, or None."""
    m = _PATH_RE.search(args or "")
    return m.group(1) if m else None


def _is_noise(p: str) -> bool:
    """True when a path is runtime/system noise (not a host dependency)."""
    return any(p.startswith(n) for n in NOISE_PREFIXES)


def infer_requires(events: list[dict]) -> dict:
    """Infer requires from observed events (best-effort; system noise filtered).

    - real paths opened by file-read  → files (local input the tool reads)
    - execve binaries                → exec (executables it depends on)
    - toolchain outputs (own build)  → excluded
    - env: unobservable from strace → left empty for the author
    - writable: caller passes file-write whitelist paths, see infer_requires_full()

    Args:
      events: classified events.

    Returns:
      {"env": [], "files": [...], "exec": [...]}.
    """
    files: set[str] = set()
    exes: set[str] = set()

    for e in events:
        c = e.get("class")
        if c == "file-read":
            if e.get("syscall") not in _PATH_SYSCALLS:
                continue  # read/readv args are buffer content, not a path
            p = _quoted_path(e.get("args") or "")
            if p and not _is_noise(p):
                files.add(p)
        elif c == "exec":
            p = _quoted_path(e.get("args") or "")
            if p and not p.endswith(_TOOLCHAIN):
                # interpreters/real subprocess binaries are meaningful deps
                exes.add(p)

    return {"env": [], "files": sorted(files), "exec": sorted(exes)}


def infer_requires_full(events: list[dict], writable_paths: list[str]) -> dict:
    """infer_requires + merge file-write whitelist paths into writable.

    Args:
      events: classified events.
      writable_paths: paths the tool claims to write (host must allow writes).

    Returns:
      requires dict with system noise filtered and writable appended.
    """
    req = infer_requires(events)
    req["writable"] = sorted(set(req.get("writable") or []) | set(writable_paths or []))
    return req