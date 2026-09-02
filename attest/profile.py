"""Compile operator-approved claims into a seatbelt (macOS) profile.

Bridge between the contract (tool.yaml claims) and the mature sandbox:
the sandbox becomes the enforcer; deny = out-of-contract. Only
operator-approved claims should be compiled (see contract.py).

Current scope (minimal prototype):
  - file-write: whitelisted paths → (allow file-write* (subpath ...)),
    everything else denied
  - network:  absent from claims → (deny network*); declared → coarse
    (allow network-outbound) — domain-level allowlists are a later iteration
  - everything else: allow default (file-read/exec/memory/sync noise)

Platform notes:
  - macOS aliases: /tmp -> /private/tmp, /etc -> /private/etc (seatbelt
    matches the real path, not the symlink)
  - rule order is not load-bearing: a specific allow beats the global deny
    (verified empirically: /private/tmp writes pass, /etc writes fail)
"""
import posixpath
import subprocess
import tempfile

# mac absolute-path aliases: seatbelt sees the real path, not the symlink.
_MAC_REAL = {
    "/tmp": "/private/tmp",
    "/etc": "/private/etc",
}


def mac_path(p: str) -> str:
    """Map a user-facing abs path to the real darwin path (no-op elsewhere)."""
    ps = posixpath.normpath(p)
    for alias, real in _MAC_REAL.items():
        if ps == alias or ps.startswith(alias + "/"):
            return real + ps[len(alias):]
    return ps


def _write_paths(claims: dict) -> list[str]:
    """Collect whitelisted write dirs from claims (allow entries)."""
    out = []
    for a in claims.get("allow", []):
        if isinstance(a, dict) and a.get("class") == "file-write":
            out += a.get("paths") or []
    return out


def _network_declared(claims: dict) -> bool:
    """True when claims declare any network capability."""
    allow = claims.get("allow", [])
    return any(
        (a == "network") or (isinstance(a, dict) and a.get("class") == "network")
        for a in allow
    )


def build_profile(claims: dict, platform: str = "darwin") -> str:
    """Compile claims into a seatbelt profile.

    Args:
      claims: tool.yaml claims ({allow, deny}).
      platform: "darwin" for macOS seatbelt paths.

    Returns:
      Seatbelt profile text (run via sandbox-exec -f).
    """
    lines = ["(version 1)", "(allow default)"]

    wpaths = _write_paths(claims)
    lines.append("(deny file-write*)")
    for w in wpaths:
        real = mac_path(w) if platform == "darwin" else w
        lines.append(f'(allow file-write* (subpath "{real}"))')

    if _network_declared(claims):
        lines.append("(allow network-outbound)")
    else:
        lines.append("(deny network*)")

    return "\n".join(lines) + "\n"


def run_sandboxed(argv: list[str], profile: str, cwd: str | None = None) -> dict:
    """Run a command under sandbox-exec with the compiled profile.

    Args:
      argv:    command + args (e.g. ["python3", "cache.py", "x"]).
      profile: seatbelt profile text (build_profile output).
      cwd:     working directory for the process.

    Returns:
      {"returncode", "stdout", "stderr", "timed_out"}.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".sb", delete=False) as f:
        f.write(profile)
        prof_path = f.name
    try:
        r = subprocess.run(
            ["sandbox-exec", "-f", prof_path, *argv],
            capture_output=True, text=True, cwd=cwd, timeout=120,
        )
        return {"returncode": r.returncode, "stdout": r.stdout,
                "stderr": r.stderr, "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "timeout", "timed_out": True}
    finally:
        try:
            import os
            os.unlink(prof_path)
        except OSError:
            pass