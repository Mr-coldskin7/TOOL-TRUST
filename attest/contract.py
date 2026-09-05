"""Contract governance: who may define a tool's allowed boundaries.

Decision (2026-09-02): observation may only SUGGEST boundaries; the operator
(or their agent) holds the authority to approve. This kills the circular-trust
loop where a tool's own testimony defines its own fences.

Origins:
  - author-built        : written by the tool's author (trusted only for their own
                          tools; NOT law for third parties)
  - observed-suggested  : produced by --generate-claims from one run — a CANDIDATE,
                          never law; must be reviewed & approved manually
  - operator-approved   : reviewed + confirmed by the operator — only this origin
                          may be compiled into enforcement policies (Step 3)
  - missing/legacy      : pre-origin manifests are treated as author-built
                          (backwards compatible; never enforce by default)

Rule: auto-generated claims can NEVER auto-upgrade to operator-approved — that
is the "no auto-expansion" invariant.
"""
import datetime
import json
import pathlib

ORIGINS = ("author-built", "observed-suggested", "operator-approved")


def origin_of(claims: dict) -> str:
    """Effective origin; missing/None → 'author-built' (legacy compat)."""
    o = (claims or {}).get("origin")
    return o if o in ORIGINS else "author-built"


def can_enforce(claims: dict) -> bool:
    """Only operator-approved claims may become enforcement policy."""
    return origin_of(claims) == "operator-approved"


def mark_generated(claims: dict) -> dict:
    """Tag claims produced by observation as a candidate (observed-suggested).

    Never overwrite an existing operator-approved manifest: callers should
    refuse generation outright, this just stamps the origin field.
    """
    claims["origin"] = "observed-suggested"
    claims["approved_at"] = None
    return claims


def approve(claims: dict) -> dict:
    """Operator confirmation: observed-suggested → operator-approved.

    This is THE legislative step — only a human/agent acting for the operator
    may call it. Records when it happened.
    """
    if origin_of(claims) == "operator-approved":
        return claims  # idempotent
    claims["origin"] = "operator-approved"
    claims["approved_at"] = datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat(timespec="seconds")
    return claims

def contract_boundary(manifest: dict, tool_dir: pathlib.Path) -> str:
    """One-line human-readable summary of the tool's approved permissions.

    Read from the committed contract.json snapshot + the srt-settings.json it
    locked. Used to surface the authorization state where agents/users can see
    it (MCP tool descriptions, status views). Falls back to 'unmanaged'.
    """
    snap_path = pathlib.Path(tool_dir) / "contract.json"
    if not snap_path.exists():
        return "[contract] unmanaged (no contract) - legacy/unapproved"
    try:
        snap = json.loads(snap_path.read_text())
    except (json.JSONDecodeError, OSError):
        return "[contract] unreadable contract.json"

    sb = snap.get("sandbox") or {}
    settings = {}
    settings_name = sb.get("srt_settings")
    if settings_name:
        sp = pathlib.Path(tool_dir) / settings_name
        if sp.exists():
            try:
                settings = json.loads(sp.read_text())
            except (json.JSONDecodeError, OSError):
                settings = {}
    net = settings.get("network", {})
    doms = [d for d in (net.get("allowedDomains") or []) if isinstance(d, str)]
    fs = settings.get("filesystem", {})
    writes = [w for w in (fs.get("allowWrite") or []) if isinstance(w, str)]
    approved_at = str(snap.get("approved_at") or "?")[:16]
    return ("[contract] operator-approved "
            f"network=[{', '.join(doms) if doms else '-'}] "
            f"writes=[{', '.join(writes) if writes else '-'}] "
            f"approved {approved_at}")
