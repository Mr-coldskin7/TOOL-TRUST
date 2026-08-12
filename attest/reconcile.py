"""claims vs 观察事件 对账。确定性逻辑，默认拒绝。"""


def reconcile(events: list[dict], claims: dict) -> list[dict]:
    """事件列表对账 claims。

    每个 class：
      ∈ deny            → violation (denied)
      ∈ allow           → pass
      ∉ allow ∪ deny    → violation (not-claimed，默认拒绝)

    返回 violation 列表，含证据（syscall 名 + 首事件 args）。
    """
    allow = set(claims.get("allow", []))
    deny = set(claims.get("deny", []))

    by_class: dict[str, list[dict]] = {}
    for ev in events:
        by_class.setdefault(ev["class"], []).append(ev)

    violations = []
    for c in sorted(by_class):
        if c in deny:
            reason = "denied"
        elif c in allow:
            continue
        else:
            reason = "not-claimed"
        evs = by_class[c]
        violations.append(
            {
                "class": c,
                "reason": reason,
                "syscalls": sorted({e["syscall"] for e in evs}),
                "evidence": evs[0]["args"] if evs else "",
            }
        )
    return violations
