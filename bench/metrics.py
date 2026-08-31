"""量化指标:从 case 判定结果算混淆矩阵 + 派生指标,输出表格。

坐标定义(判定与 ground truth 一致 = 对):
  TP 恶意判 fail      TN 良性判 pass
  FP 良性误判 fail     FN 恶意漏判 pass(放跑)

precision = TP/(TP+FP)  定位准确率(判 fail 的里多少是真恶意)
recall    = TP/(TP+FN)  检出率(恶意里多少被抓)
f1        = 2PR/(P+R)
accuracy  = (TP+TN)/N

小样本的 1.000 没统计意义 —— 用 Wilson score interval(95%)把样本量
读进数字里:22/22 全对的下界只有 ~0.85,数千样本全对下界 ~0.99。
"""
import math
from dataclasses import dataclass


_Z95 = 1.96


def wilson(k: int, n: int, z: float = _Z95) -> tuple[float, float]:
    """Wilson score interval:对极端值(precision=1.0)不退化到 0,适合误报率场景。"""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denom
    return (max(0.0, center - half), min(1.0, center + half))


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
    # 95% Wilson CI: (lower, upper),k = 正确数,n = 分母
    ci_precision: tuple[float, float]
    ci_recall: tuple[float, float]
    ci_accuracy: tuple[float, float]
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
        ci_precision=wilson(tp, tp + fp),
        ci_recall=wilson(tp, tp + fn),
        ci_accuracy=wilson(tp + tn, len(results)),
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
    lines.append("  95% CI (Wilson):")
    lines.append("    precision  [%.3f, %.3f]" % m.ci_precision)
    lines.append("    recall     [%.3f, %.3f]" % m.ci_recall)
    lines.append("    accuracy   [%.3f, %.3f]" % m.ci_accuracy)
    lines.append("  ※ 小样本全对=1.000 不代表系统安全:置信区间下界才是可宣称的底线")
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
    lines.append("┌─ 已知边界 (面试/评审时须主动声明) ──────────────────")
    lines.append("  1. claims 是行为采样画像,不是能力上界:conditional-evil 证明过")
    lines.append("  2. file-read 无路径白名单(读 /tmp 与读 /etc/shadow 同权)")
    lines.append("  3. 网络豁免偏宽:DNS(53)/127.x 全部放行,hosts 白名单才是主防线")
    lines.append("  4. bench 测对账引擎的判定精度,不测 Docker 隔离/运行时 gate 的 subprocess")
    lines.append("  5. 合成语料 ≠ 真实 strace:真实轨迹回放(dogfood)是后续工作")
    return "\n".join(lines)


def to_dict(m: Metrics) -> dict:
    return {
        "metrics": {
            "n_cases": len(m.cases),
            "tp": m.tp, "tn": m.tn, "fp": m.fp, "fn": m.fn,
            "precision": m.precision, "recall": m.recall,
            "f1": m.f1, "accuracy": m.accuracy,
            "ci": {
                "precision": list(m.ci_precision),
                "recall": list(m.ci_recall),
                "accuracy": list(m.ci_accuracy),
            },
        },
        "cases": [
            {
                "name": r.name, "label": r.label, "verdict": r.verdict,
                "violations": r.violations, "note": r.note,
            }
            for r in m.cases
        ],
    }