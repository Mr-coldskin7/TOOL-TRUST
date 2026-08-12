"""JSON 报告：observed + violations + verdict。"""


def build_report(
    tool_name: str,
    inputs: list[str],
    claims: dict,
    events: list[dict],
    violations: list[dict],
) -> dict:
    classes: dict[str, int] = {}
    for e in events:
        classes[e["class"]] = classes.get(e["class"], 0) + 1

    return {
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
