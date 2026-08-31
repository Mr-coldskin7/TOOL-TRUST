"""bench 回归测试:合成语料必须全部命中 ground truth,量化指标不低于阈值。

这是 tool-trust 的"量化指标"入口:
  - 逐 case:verdict 与 label 必须完全一致(任何一处回归都会立刻红)
  - 整体:precision/recall/f1/accuracy ≥ 0.95(留容错余量,便于将来加难例)
"""
from bench.corpus import CASES
from bench.metrics import compute
from bench.run_bench import run_case


def test_every_case_matches_ground_truth():
    mismatches = []
    for c in CASES:
        r = run_case(c)
        expected_fail = c.label == "malicious"
        if (r.verdict == "fail") != expected_fail:
            mismatches.append(f"{c.name}: label={c.label} verdict={r.verdict}")
    assert not mismatches, "判定与 ground truth 不一致:\n" + "\n".join(mismatches)


def test_metrics_above_threshold():
    results = [run_case(c) for c in CASES]
    m = compute(results)
    for name, value in [
        ("precision", m.precision),
        ("recall", m.recall),
        ("f1", m.f1),
        ("accuracy", m.accuracy),
    ]:
        assert value >= 0.95, f"{name}={value} 低于阈值"

    # 当前基线:全命中
    assert m.fp == 0, f"存在良性误杀: {[r.name for r in m.cases if r.label == 'benign' and r.verdict == 'fail']}"
    assert m.fn == 0, f"存在恶意漏放: {[r.name for r in m.cases if r.label == 'malicious' and r.verdict == 'pass']}"


def test_malicious_reason_tells_what_was_caught():
    """恶意 case 的 violates 原因要能教学:不是笼统 fail,而是具体抓点。"""
    reason_facts = {
        "dotdot-escape": "out-of-scope",
        "write-outside-whitelist": "out-of-scope",
        "silent-write": "not-claimed",
        "network-undeclared-host": "net-out-of-scope",
        "mode-exceeded": "mode-exceeded",
        "denied-write": "denied",
        "exfil": "net-out-of-scope",
        "exec-undeclared": "denied",
        "kill-process": "denied",
        "chmod-shadow": "denied",
        "conditional-evil": "not-claimed",
    }
    for name, expect in reason_facts.items():
        c = next(x for x in CASES if x.name == name)
        r = run_case(c)
        assert r.verdict == "fail"
        reasons = {v["reason"] for v in r.violations}
        assert expect in reasons, f"{name}: 期望 reason={expect},实际={reasons}"


def test_requires_inference_exact():
    from bench.run_bench import run_requires_cases

    req = run_requires_cases()
    assert len(req) == 4
    for name, r in req.items():
        assert r["exact"], f"requires 推断不精确: {name} → {r['inferred']}"