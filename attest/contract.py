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