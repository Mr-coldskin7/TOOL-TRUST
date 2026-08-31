"""量化指标:从 case 判定结果算混淆矩阵 + 派生指标,输出表格。

坐标定义(判定与 ground truth 一致 = 对):
  TP 恶意判 fail      TN 良性判 pass
  FP 良性误判 fail     FN 恶意漏判 pass(放跑)

precision = TP/(TP+FP)  定位准确率(判 fail 的里多少是真恶意)
recall    = TP/(TP+FN)  检出率(恶意里多少被抓)
f1        = 2PR/(P+R)
accuracy  = (TP+TN)/N
"""
from dataclasses import dataclass


@dataclass
class CaseResult:
    name: str
    label: str          # benign / malicious (ground truth)
    verdict: str        # pass / fail (pipeline 判定)
    violations: list    # 详情
    note: str = ""


@dataclass
class Metrics:
    tp: int
    tn: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    cases: list[CaseResult]   # 全量逐 case 结果(按 y/n/y/n 分组)
    wrong: list[CaseResult]   # 判定与标签不一致的 case


def compute(results: list[CaseResult]) -> Metrics:
    tp = sum(1 for r in results if r.label == "malicious" and r.verdict == "fail")
    tn = sum(1 for r in results if r.label == "benign" and r.verdict == "pass")
    fp = sum(1 for r in results if r.label == "benign" and r.verdict == "fail")
    fn = sum(1 for r in results if r.label == "malicious" and r.verdict == "pass")

    def _safe(num: int, den: int) -> float:
        return num / den if den else 0.0

    precision = _safe(tp, tp + fp)
    recall = _safe(tp, tp + fn)
    f1 = _safe(2 * precision * recall, precision + recall) if (precision + recall) else 0.0
    accuracy = _safe(tp + tn, len(results))

    wrong = [r for r in results if (r.label == "malicious") != (r.verdict == "fail")]
    return Metrics(
        tp=tp, tn=tn, fp=fp, fn=fn,
        precision=precision, recall=recall, f1=f1, accuracy=accuracy,
        cases=results, wrong=wrong,
    )


def first_reason(r: CaseResult) -> str:
    """取第一个 violation 的 reason,便于表格里一眼看出抓点。"""
    if not r.violations:
        return ""
    v = r.violations[0]
    detail = v.get("detail", "")
    return f"{v['reason']}" + (f" ({detail})" if detail else "")


def render(results: list[CaseResult], requires: dict | None = None) -> str:
    """人读表格(中文)。requires 为 {name: {files_ok, exec_ok, exact}}。"""
    m = compute(results)
    lines = []
    lines.append("┌─ 分类指标 (verdict vs ground truth) ────────────────")
    lines.append(f"  语料规模  {len(results):>4}  (benign {m.tn + m.fp} / malicious {m.tp + m.fn})")
    lines.append(f"  真阳 TP   {m.tp:>4}")
    lines.append(f"  真阴 TN   {m.tn:>4}")
    lines.append(f"  假阳 FP   {m.fp:>4}  ← 良性工具被误杀")
    lines.append(f"  假阴 FN   {m.fn:>4}  ← 恶意工具被放跑")
    lines.append("  精确率 precision  %.3f" % m.precision)
    lines.append("  召回率 recall     %.3f" % m.recall)
    lines.append("  F1               %.3f" % m.f1)
    lines.append("  准确率 accuracy   %.3f" % m.accuracy)
    lines.append("┌─ 逐 case ───────────────────────────────────────────")
    for r in m.cases:
        ok = (r.label == "malicious") == (r.verdict == "fail")
        mark = "✓" if ok else "✗ MISMATCH"
        cause = first_reason(r) if r.verdict == "fail" else ""
        lines.append(
            f"  {mark:<11} {r.label:<9} {r.verdict:<5} {r.name:<30} {cause}"
        )
    if m.wrong:
        lines.append("")
        lines.append("  ✗ 判定与标签不符的 case(需定位):")
        for r in m.wrong:
            lines.append(f"     - {r.name}: label={r.label} verdict={r.verdict}")
    if requires is not None:
        lines.append("┌─ requires 推断 (infer vs expected) ───────────────")
        for name, r in requires.items():
            lines.append(
                f"  {'✓' if r['exact'] else '✗'} {name:<20} files={r['files_ok']} exec={r['exec_ok']} exact={r['exact']}"
            )
    return "\n".join(lines)


def to_dict(m: Metrics) -> dict:
    return {
        "metrics": {
            "tp": m.tp, "tn": m.tn, "fp": m.fp, "fn": m.fn,
            "precision": m.precision, "recall": m.recall,
            "f1": m.f1, "accuracy": m.accuracy,
        },
        "cases": [
            {
                "name": r.name, "label": r.label, "verdict": r.verdict,
                "violations": r.violations, "note": r.note,
            }
            for r in m.cases
        ],
    }