"""Duplicate-tool detection (similarity candidates).

Scans the tool registry for NEAR-DUPLICATE tools by behavioral signature:
description + command + claims allow/deny + settings (domains / write paths).
Output is a CANDIDATE LIST only — it never deletes or merges anything; the
operator decides. Detection is cheap Jaccard on token sets.

Why useful: the hub grows ("should I add a weather tool?"), and before typing
the answer it's worth knowing there are already 2 quote tools with the same
Yahoo endpoint. This is the "registry / reuse" layer, kept intentionally
simple: notify, don't act.
"""
import pathlib
import re
import string

import yaml

_WORD_RE = re.compile(r"[a-z0-9_]+")

# noise that every tool shares: generic claim classes + default scratch dirs
_STOP = {"network", "stdout", "exit", "fd", "memory", "sync", "file-read",
         "file-write", "exec", "other", "perms", "process", "fork", "stderr",
         "none", "/tmp", "/private/tmp"}


def _tokens(text: str) -> set[str]:
    return {t for t in _WORD_RE.findall(text.lower()) if t not in _STOP}


def _load(tools_dir: pathlib.Path) -> list[dict]:
    out = []
    for d in sorted(tools_dir.iterdir()):
        ym = d / "tool.yaml"
        if not ym.is_file():
            continue
        try:
            m = yaml.safe_load(ym.read_text())
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(m, dict) or not m.get("name"):
            continue
        sig = _signature(m, d)
        out.append({"name": m["name"], "dir": d.name, **sig})
    return out


def _signature(manifest: dict, tool_dir: pathlib.Path) -> dict:
    text_bits = [manifest.get("description", ""), manifest.get("command", "")]
    claims = manifest.get("claims") or {}
    for key in ("allow", "deny"):
        for item in claims.get(key) or []:
            if isinstance(item, str):
                text_bits.append(item)
            else:
                text_bits.append(item.get("class", ""))
                text_bits.extend(item.get("hosts") or [])
                for p in (item.get("paths") or []):
                    text_bits.append(p)
    sb = manifest.get("sandbox") or {}
    settings = {}
    sn = sb.get("srt_settings")
    if sn and sn.endswith(".json") and (tool_dir / sn).exists():
        try:
            import json
            settings = json.loads((tool_dir / sn).read_text())
        except Exception:
            settings = {}
    doms = settings.get("network", {}).get("allowedDomains") or []
    writes = settings.get("filesystem", {}).get("allowWrite") or []
    text_bits.extend(str(x) for x in doms)
    custom_writes = {str(x) for x in writes if str(x) not in ("/tmp", "/private/tmp")}
    text_bits.extend(custom_writes)
    return {"tokens": _tokens(" ".join(text_bits)),
            "domains": set(str(x) for x in doms),
            "writes": custom_writes}


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def find_duplicates(tools_dir: pathlib.Path, threshold: float = 0.55) -> list[dict]:
    """Near-duplicate candidates: [{a, b, similarity, why, dirs}] sorted desc.

    Never mutates anything. threshold on Jaccard of the behavioral token set;
    a shared endpoint (same domain) bumps the signal.
    """
    tools = _load(tools_dir)
    pairs: list[dict] = []
    for i in range(len(tools)):
        for j in range(i + 1, len(tools)):
            a, b = tools[i], tools[j]
            sim = jaccard(a["tokens"], b["tokens"])
            shared_domain = a["domains"] & b["domains"]
            shared_write = a["writes"] & b["writes"]
            why = _why(sim, shared_domain, shared_write)
            if sim >= threshold or shared_domain:
                pairs.append({
                    "a": a["name"], "b": b["name"],
                    "similarity": round(sim, 3),
                    "why": why,
                    "dirs": [a["dir"], b["dir"]],
                })
    pairs.sort(key=lambda p: p["similarity"], reverse=True)
    return pairs


def _why(sim: float, dom: set, wr: set) -> str:
    if dom:
        return "same network endpoint: " + ", ".join(sorted(dom))
    if wr:
        return "same write path: " + ", ".join(sorted(wr))
    return f"token Jaccard {sim:.2f}"