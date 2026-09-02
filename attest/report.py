"""JSON report: observed + violations + verdict."""


def build_report(
    tool_name: str,
    inputs: list[str],
    claims: dict,
    events: list[dict],
    violations: list[dict],
    provenance: dict | None = None,
) -> dict:
    """Assemble the attestation report dict.

    Args:
      tool_name: tool name.
      inputs:    argv passed to the tool during observation.
      claims:    declared behavior manifest.
      events:    classified strace events.
      violations: reconciliation findings (empty = verdict pass).
      provenance: optional provenance snapshot (hash/version/source/at).

    Returns:
      Report with tool/input/claims/observed/violations/verdict (+ provenance).
    """
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