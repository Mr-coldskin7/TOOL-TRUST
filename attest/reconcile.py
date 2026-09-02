"""Reconcile claims against observed events. Deterministic; default-deny.

Terms: claims = behavior the tool declares in tool.yaml; class = the behavior
bucket a syscall maps to (file-write / network / exec / ...).

Reconciliation (three levels for side effects):
  1. class   event.class must be in allow, else violation (not-claimed)
  2. paths   file-write must hit a declared paths whitelist (else out-of-scope)
  3. mode    actual write intent must be covered by declared mode (mode-exceeded)
  network.hosts: with a hosts whitelist, every network event's target IP must be
                 in the whitelisted hosts' resolved IP set (net-out-of-scope)

Innocuous classes (stdout/exit/file-read/...) only need level 1.
"""
import posixpath
import socket

from attest.rules import MODE_ALLOWS


def _normalize_allow(allow: list) -> list[dict]:
    """Normalize legacy string entries ('file-read') into dict form ({'class': ...})."""
    out = []
    for item in allow:
        out.append({"class": item} if isinstance(item, str) else item)
    return out


def _path_in_paths(path: str, paths: list[str]) -> bool:
    """Whether path lies under one of the whitelist prefixes (directory boundary).

    normpath collapses `..` first, then matches "equals prefix" or "inside
    prefix directory", so `/tmp/../etc/x` cannot escape a `/tmp` whitelist.
    """
    p = posixpath.normpath(path)
    for pref in paths:
        base = posixpath.normpath(pref)
        prefix = base.rstrip("/") + "/" if base != "/" else "/"
        if p == base or p.startswith(prefix):
            return True
    return False


def _default_resolver(hosts: list[str]) -> set[str]:
    """Resolve declared hosts to an IP set; unresolvable hosts are skipped."""
    out: set[str] = set()
    for h in hosts:
        try:
            for info in socket.getaddrinfo(h, None):
                out.add(info[4][0])
        except socket.gaierror:
            continue
    return out


def reconcile(
    events: list[dict], claims: dict, resolver=None
) -> list[dict]:
    """Reconcile events against claims; return violation list (empty = compliant).

    Args:
      events: classified events.
      claims: tool.yaml claims ({allow, deny}).
      resolver: optional host->IP resolver (deterministic for tests).

    Returns:
      List of violation dicts with class/reason/syscalls/evidence/detail.
    """
    allow = _normalize_allow(claims.get("allow", []))
    deny = set(claims.get("deny", []))
    host_resolver = resolver or _default_resolver

    by_class: dict[str, list[dict]] = {}
    for ev in events:
        by_class.setdefault(ev["class"], []).append(ev)

    violations = []
    for c in sorted(by_class):
        evs = by_class[c]
        decls = [a for a in allow if a["class"] == c]

        if c in deny:
            _add(violations, c, "denied", evs)
            continue
        if not decls:
            # events for an unclaimed side-effect class → default deny
            _add(violations, c, "not-claimed", evs)
            continue
        if c == "file-write":
            _check_file_write(decls, evs, violations)
        elif c == "network":
            _check_network_hosts(decls, evs, violations, host_resolver)

    return violations


def _check_network_hosts(
    decls: list[dict], evs: list[dict], violations: list[dict], resolver
) -> None:
    """network claims with hosts → events with a target IP must hit the set.

    Exempts infrastructure traffic that is not the tool's data target:
    port 53 (DNS resolution) and 127.x (container-internal, e.g. Docker DNS).
    """
    host_decls = [d for d in decls if isinstance(d, dict) and d.get("hosts")]
    if not host_decls:
        return
    allowed: set[str] = set()
    for d in host_decls:
        allowed |= resolver(d["hosts"])
    for ev in evs:
        ip = ev.get("ip")
        port = ev.get("port")
        if not ip:
            continue
        if port == 53 or ip.startswith("127."):
            continue
        if ip not in allowed:
            _add_one(
                violations,
                ev,
                "net-out-of-scope",
                f"ip={ip}:{port or '?'} not in declared network hosts",
            )


def _check_file_write(
    decls: list[dict], evs: list[dict], violations: list[dict]
) -> None:
    """file-write two-level check: paths whitelist, then mode coverage."""
    for ev in evs:
        path = ev.get("path")
        mode = ev.get("mode")
        # Events without a path (write(fd)) cannot be judged alone; their
        # openat already was. Conservative pass — the openat decision stands.
        if path is None:
            continue

        in_scope = [d for d in decls if _path_in_paths(path, d.get("paths", []))]
        if not in_scope:
            _add_one(
                violations,
                ev,
                "out-of-scope",
                f"path={path} not in any declared write whitelist",
            )
            continue

        allowed_modes = set()
        for d in in_scope:
            m = d.get("mode")
            allowed_modes |= (
                MODE_ALLOWS[m] if m and m in MODE_ALLOWS else MODE_ALLOWS["overwrite"]
            )
        if mode is not None and mode not in allowed_modes:
            _add_one(
                violations,
                ev,
                "mode-exceeded",
                f"path={path} mode={mode} not covered by declared modes",
            )


def _add(violations: list[dict], c: str, reason: str, evs: list[dict]) -> None:
    """Record one aggregated violation for a whole event class."""
    violations.append(
        {
            "class": c,
            "reason": reason,
            "syscalls": sorted({e["syscall"] for e in evs}),
            "evidence": evs[0].get("args", "") if evs else "",
        }
    )


def _add_one(violations: list[dict], ev: dict, reason: str, detail: str) -> None:
    """Record one violation for a single event, with detail."""
    violations.append(
        {
            "class": ev.get("class", "file-write"),
            "reason": reason,
            "syscalls": [ev["syscall"]],
            "evidence": ev.get("args", ""),
            "detail": detail,
        }
    )