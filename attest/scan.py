"""Permission discovery: run a tool inside srt with MINIMAL privileges and
learn what it actually needs.

Rationale (operator-driven, not guess-driven): instead of reading tool.yaml
and declaring permissions from imagination, we put the tool into the sandbox
for a smoke run. Whatever the sandbox blocks is what the tool genuinely tried
to touch — that becomes the *suggestion* for allowedDomains / allowWrite etc.
A human still reviews and approves; the sandbox run merely supplies evidence.

Two denial channels are read:
  - network  → [SandboxDebug] Connection blocked / No matching rule denying
  - files    → srt is silent (EPERM); we parse the child's stderr for
               "Operation not permitted: '<path>'" / "Permission denied" hints
"""
import json
import pathlib
import re

from attest import live

# default minimal settings for a discovery run:
#   - no network
#   - no extra writes beyond the scratch dirs every tool gets
#   - no reads restricted (reads default allowed inside srt)
# NOTE platform difference: glob patterns (**/.git/**, **/.env) are honored on
# macOS seatbelt but IGNORED on Linux (bwrap). If you run on Linux/CI, list the
# concrete deny paths explicitly for the same protection.
MIN_SETTINGS = {
    "network": {"allowedDomains": [], "deniedDomains": ["*"]},
    "filesystem": {
        "denyRead": ["~/.ssh", "~/.aws/credentials"],
        "denyWrite": [".env", "**/.env", "**/.git/**"],
        "allowWrite": ["/tmp", "/private/tmp"],
    },
}

_EPERM_RE = re.compile(
    r"Operation not permitted: ['\"]([^'\"]+)['\"]"
    r"|Permission denied: ['\"]([^'\"]+)['\"]"
    r"|can't open ['\"]?([^'\"]+?)['\"]?: .*[Pp]ermission"
)


def _eperm_paths(stderr: str) -> list[str]:
    """Extract filesystem paths the child could not access (EPERM)."""
    out: list[str] = []
    for m in _EPERM_RE.finditer(stderr):
        for g in m.groups():
            if g and g not in out:
                out.append(g)
    return out


def _build_suggested(denials: list[dict], settings: dict) -> dict:
    """Turn collected denials into a suggested (minimal) settings grant. Pure."""
    suggested = {
        "network": {"allowedDomains": [], "deniedDomains": []},
        "filesystem": {
            "denyRead": list(settings["filesystem"]["denyRead"]),
            "denyWrite": list(settings["filesystem"]["denyWrite"]),
            "allowWrite": list(settings["filesystem"]["allowWrite"]),
        },
    }
    for d in denials:
        if d["kind"].startswith("net-"):
            t = d["target"]
            if t not in suggested["network"]["allowedDomains"]:
                suggested["network"]["allowedDomains"].append(t)
        elif d["kind"] == "fs-deny":
            t = d["target"]
            if t not in suggested["filesystem"]["allowWrite"]:
                # filesystem denials that sat outside our defaults → suggest allowWrite
                suggested["filesystem"]["allowWrite"].append(t)
    return suggested


def scan(argv: list[str], settings: dict | None = None, cwd: str | None = None,
         timeout: int = 120) -> dict:
    """Run a tool under minimal srt settings; return what it needed.

    Args:
      argv:      command to run (tool command + sample inputs).
      settings:  sandbox settings dict for the run (defaults to MIN_SETTINGS).
      cwd:       working directory.

    Returns:
      {"suggested": {...}, "denials": [...], "rc": ..., "note": ...}
    """
    settings = settings or MIN_SETTINGS
    base = pathlib.Path(cwd) if cwd else pathlib.Path.cwd()
    tmp = base / ".scan-settings.json"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(settings))
    try:
        r = live.run_sandboxed(argv, tmp, cwd=str(base), timeout=timeout)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass

    denials = list(r["violations"])  # net-block / net-deny events
    for p in _eperm_paths(r["stderr"]):
        denials.append({"kind": "fs-deny", "target": p, "port": None})

    suggested = _build_suggested(denials, settings)

    rc_note = (f"rc={r['returncode']} (sandbox run complete)"
               if r["returncode"] == 0 else
               f"rc={r['returncode']} — tool failed during sandboxed smoke")
    note = rc_note + ("; NO extra permissions suggested" if not denials else
                      f"; {len(denials)} denial(s) → suggested permissions above")
    return {"suggested": suggested, "denials": denials,
            "rc": r["returncode"], "note": note}