"""JSON 报告：observed + violations + verdict。"""


def build_report(
    tool_name: str,
    inputs: list[str],
    claims: dict,
    events: list[dict],
    violations: list[dict],
    provenance: dict | None = None,
) -> dict:
    classes: dict[str, int] = {}
    for e in events:
        classes[e["class"]] = classes.get(e["class"], 0) + 1

    report = {
        "tool": tool_name,
        "input": inputs,
        "claims": claims,
        "observed": {
            "syscall_count": len(events),
            "classes": classes,
            "events": events,
        },
        "violations": violations,
        "verdict": "fail" if violations else "pass",
    }
    if provenance:
        report["provenance"] = provenance
    return report
