"""Authorization layer: human-in-the-loop permission governance.

Shared by the CLI wizard (`observe.py --onboard`) and the MCP management
tools (`tools/authorizer`). The point of this layer is that the OPERATOR (a
human, or their sanctioned agent) sees a permission table and confirms —
approval is legislation, not convenience.

State machine per tool:
  unmanaged        : no contract.json              (never enforced)
  proposed         : srt-settings.json.proposed    (scan evidence, not accepted)
  approved/ locked : contract.json commits claims + settings-content sha256
  revoked          : contract.json removed → back to unmanaged (settings kept)
"""
import hashlib
import json
import pathlib

import yaml

from attest import contract


DEFAULT_SETTINGS = {
    "network": {"allowedDomains": [], "deniedDomains": ["*"]},
    "filesystem": {
        "denyRead": ["~/.ssh", "~/.aws/credentials"],
        "denyWrite": [".env", "**/.env", "**/.git/**"],
        "allowWrite": ["/tmp", "/private/tmp"],
    },
}


# ---------------------------------------------------------------------------
# rendering — the "permission table" both surfaces share
# ---------------------------------------------------------------------------

def permission_rows(manifest: dict, settings: dict) -> list[list[str]]:
    """Rows for the permission table: [tag, value].

    Tags: NET / WRITE / NO-WRITE / NO-READ / CLAIMS-ALLOW / CLAIMS-DENY
    """
    rows: list[list[str]] = []
    net = settings.get("network", {})
    doms = [d for d in (net.get("allowedDomains") or []) if isinstance(d, str)]
    rows.append(["NET", ", ".join(doms) if doms else "(none)"])
    fs = settings.get("filesystem", {})
    writes = [w for w in (fs.get("allowWrite") or []) if isinstance(w, str)]
    rows.append(["WRITE", ", ".join(writes) if writes else "(none)"])
    no_w = [w for w in (fs.get("denyWrite") or []) if isinstance(w, str)]
    rows.append(["NO-WRITE", ", ".join(no_w) if no_w else "(none)"])
    no_r = [w for w in (fs.get("denyRead") or []) if isinstance(w, str)]
    rows.append(["NO-READ", ", ".join(no_r) if no_r else "(none)"])
    c = manifest.get("claims") or {}
    rows.append(["CLAIMS-ALLOW", ", ".join(str(x) for x in (c.get("allow") or []))])
    rows.append(["CLAIMS-DENY", ", ".join(str(x) for x in (c.get("deny") or []))])
    return rows


def render_table(rows: list[list[str]], title: str) -> str:
    """Simple aligned text table (CLI + MCP consumption both fine)."""
    w = max(len(r[0]) for r in rows) + 1
    out = [title]
    for tag, val in rows:
        out.append(f"  {tag:<{w}} {val}")
    return "\n".join(out)


def verify_snapshot(manifest: dict, tool_dir: pathlib.Path) -> tuple[bool, str]:
    """Check current manifest + settings against the committed contract snapshot.

    Mirrors gate Gate 4 exactly (single source of truth for 'is the approved
    contract still intact?'). Returns (ok, reason).
    """
    cpath = pathlib.Path(tool_dir) / "contract.json"
    if not cpath.exists():
        return True, "no contract (unmanaged)"
    try:
        snap = json.loads(cpath.read_text())
    except (json.JSONDecodeError, OSError):
        return False, "unreadable contract.json"
    if snap.get("tool") != manifest.get("name"):
        return True, "unrelated contract"
    if (manifest.get("claims") or {}) != (snap.get("claims") or {}):
        return False, "claims drifted from approved snapshot"
    sb = manifest.get("sandbox") or {}
    snap_sb = snap.get("sandbox") or {}
    if (sb.get("srt_settings") or "") != (snap_sb.get("srt_settings") or ""):
        return False, "sandbox.srt_settings reference changed"
    snap_hash = snap_sb.get("srt_settings_sha256")
    if sb.get("srt_settings") and snap_hash:
        sp = pathlib.Path(tool_dir) / sb["srt_settings"]
        if not sp.exists():
            return False, "srt-settings.json missing since approval"
        if hashlib.sha256(sp.read_bytes()).hexdigest() != snap_hash:
            approved = snap.get("summary") or {}
            ref = (f" (approved had net={approved.get('network')} "
                   f"writes={approved.get('writes')})")
            return False, "srt-settings.json content changed since approval" + ref
    return True, "ok"


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def tool_state(manifest: dict, tool_dir: pathlib.Path) -> dict:
    """One tool's authorization state (drives --status and authorizer.status)."""
    name = manifest.get("name", pathlib.Path(tool_dir).name)
    cpath = pathlib.Path(tool_dir) / "contract.json"
    if not cpath.exists():
        return {"tool": name, "state": "unmanaged",
                "network": "-", "writes": "-", "approved_at": "-"}
    ok, reason = verify_snapshot(manifest, tool_dir)
    if not ok:
        return {"tool": name, "state": "drifted", "detail": reason,
                "network": "-", "writes": "-", "approved_at": "-"}
    try:
        snap = json.loads(cpath.read_text())
    except (json.JSONDecodeError, OSError):
        return {"tool": name, "state": "unreadable",
                "network": "-", "writes": "-", "approved_at": "-"}
    sb = snap.get("sandbox") or {}
    settings = {}
    sn = sb.get("srt_settings")
    if sn and (pathlib.Path(tool_dir) / sn).exists():
        try:
            settings = json.loads((pathlib.Path(tool_dir) / sn).read_text())
        except (json.JSONDecodeError, OSError):
            settings = {}
    doms = [d for d in (settings.get("network", {}).get("allowedDomains") or [])
            if isinstance(d, str)]
    writes = [w for w in (settings.get("filesystem", {}).get("allowWrite") or [])
              if isinstance(w, str)]
    return {"tool": name, "state": "approved",
            "network": ", ".join(doms) if doms else "-",
            "writes": ", ".join(writes) if writes else "-",
            "approved_at": str(snap.get("approved_at") or "-")[:16]}


def status_all(tools_dir: pathlib.Path) -> list[dict]:
    """All tools under tools_dir, sorted by name."""
    out: list[dict] = []
    for d in sorted(tools_dir.iterdir()):
        ym = d / "tool.yaml"
        if not ym.is_file():
            continue
        try:
            m = yaml.safe_load(ym.read_text())
        except OSError:
            continue
        if not isinstance(m, dict):
            continue
        out.append(tool_state(m, d))
    return out


# ---------------------------------------------------------------------------
# approve core (shared by CLI --approve / --onboard and authorizer.approve)
# ---------------------------------------------------------------------------

def _settings_summary(settings: dict) -> dict:
    """Human-comparable summary of what approval locked in (for audit)."""
    net = settings.get("network", {})
    doms = [d for d in (net.get("allowedDomains") or []) if isinstance(d, str)]
    fs = settings.get("filesystem", {})
    writes = [w for w in (fs.get("allowWrite") or []) if isinstance(w, str)]
    return {"network": list(doms), "writes": list(writes)}


def approve_core(manifest: dict, tool_dir: pathlib.Path,
                 caller: str | None = None) -> dict:
    """Legislate: promote settings, set origin, lock settings content hash.

    Returns a summary dict. Callers decide whether/how to confirm (CLI y/N,
    MCP permissions gate). This is the ONLY place contract state is created.

    Args:
      caller: identity of the approving session/agent; recorded as
        approved_by so the audit chain links caller → approver.
    """
    from attest.provenance import compute_tool_hash

    tool_dir = pathlib.Path(tool_dir)
    claims = manifest.get("claims") or {}
    sb = manifest.get("sandbox") or {}
    sb_name = sb.get("srt_settings")
    if not sb_name:
        raise ValueError(f"no sandbox.srt_settings in {tool_dir}/tool.yaml; run --scan first")
    target = tool_dir / sb_name
    proposed = tool_dir / f"{sb_name}.proposed"
    if not target.exists():
        if not proposed.exists():
            raise ValueError(f"nothing to accept: {target} missing and no {proposed.name}")
        import shutil
        shutil.copyfile(proposed, target)
        promoted = True
    else:
        promoted = False

    contract.approve(claims)
    claims["approved_by"] = caller or "operator"
    (tool_dir / "tool.yaml").write_text(
        yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False))

    settings = json.loads(target.read_text())
    settings_hash = hashlib.sha256(target.read_bytes()).hexdigest()
    prov = manifest.get("provenance")
    snapshot = {
        "schema": 3,
        "tool": manifest.get("name", tool_dir.name),
        "verdict": "pass",
        "claims": claims,
        "sandbox": {"srt_settings": sb_name, "srt_settings_sha256": settings_hash},
        "summary": _settings_summary(settings),   # what was locked, readable
        "provenance": {
            "version": prov.get("version") if prov else None,
            "hash": compute_tool_hash(tool_dir),
        },
        "approved_by": claims.get("approved_by"),
        "approved_at": claims.get("approved_at"),
        "source": source_kind(manifest),
    }
    (tool_dir / "contract.json").write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2))
    (tool_dir / f"{sb_name}.proposed").unlink(missing_ok=True)
    return {
        "tool": tool_dir.name,
        "decision": "approved",
        "settings_sha256": settings_hash[:12],
        "promoted": promoted,
        "boundary": contract.contract_boundary(manifest, tool_dir),
    }


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------

def revoke(manifest: dict, tool_dir: pathlib.Path) -> dict:
    """Remove authorization: back to unmanaged. Settings file stays for review."""
    tool_dir = pathlib.Path(tool_dir)
    cpath = tool_dir / "contract.json"
    if not cpath.exists():
        return {"tool": tool_dir.name, "decision": "noop", "detail": "already unmanaged"}
    cpath.unlink()
    claims = manifest.get("claims") or {}
    if claims.get("origin") == "operator-approved":
        claims["origin"] = "author-built"
        for k in ("approved_at", "approved_by"):
            claims.pop(k, None)
        (tool_dir / "tool.yaml").write_text(
            yaml.safe_dump(manifest, allow_unicode=True, sort_keys=False))
    return {"tool": tool_dir.name, "decision": "revoked",
            "detail": "contract.json removed; srt-settings.json kept for re-review"}

def source_kind(manifest: dict) -> str:
    """Declared source of a tool ('unknown' when none declared)."""
    prov = manifest.get("provenance") or {}
    return (prov.get("source") or manifest.get("source") or "").strip() or "unknown"


def first_connect_warning(manifest: dict) -> str | None:
    """Warning when a tool has no declared source: first-connect human review."""
    if source_kind(manifest) != "unknown":
        return None
    return (
        "⚠ first-connect: no declared source for this tool.\n"
        "   Claims/settings come from a sandboxed run — NOT from reading the\n"
        f"   code. Inspect tools/{manifest.get('name', '?')} yourself before approving."
    )
