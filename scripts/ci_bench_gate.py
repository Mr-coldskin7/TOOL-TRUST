#!/usr/bin/env python3
"""CI 指标回归门：跑 bench --json --fuzz 500,断言量化阈值。

门槛与 tests/test_bench.py 保持一致:
  - precision / recall / accuracy ≥ 0.95
  - FP + FN ≤ 5(0 误杀 + 0 放跑是目标,给小容差防抖动)

失败 → exit 1 → CI 红,PR 不能合并。量化基准从"本地一锤子"变成"每次提交的硬门槛"。
"""
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

MIN_ACCURACY = 0.95
MIN_PRECISION = 0.95
MIN_RECALL = 0.95
MAX_BAD = 5  # fp + fn


def run_bench() -> dict:
    r = subprocess.run(
        ["uv", "run", "python", "bench/run_bench.py", "--json", "--fuzz", "500"],
        cwd=REPO, capture_output=True, text=True, timeout=600,
    )
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        raise SystemExit(f"bench failed: {r.returncode}")
    return json.loads(r.stdout)


def main() -> None:
    d = run_bench()
    m = d["metrics"]
    # 报告落盘供 CI artifact 收集
    pathlib.Path("/tmp/bench-report.json").write_text(json.dumps(d, ensure_ascii=False, indent=2))
    fp, fn = m["fp"], m["fn"]
    checks = [
        ("precision", m["precision"], MIN_PRECISION),
        ("recall", m["recall"], MIN_RECALL),
        ("accuracy", m["accuracy"], MIN_ACCURACY),
    ]
    bad = fp + fn
    print(f"bench: {m['n_cases']} cases | "
          f"precision={m['precision']:.3f} recall={m['recall']:.3f} "
          f"accuracy={m['accuracy']:.3f} | fp={fp} fn={fn}")
    print(f"CI: accuracy 95% CI lower bound = {m['ci']['accuracy'][0]:.3f}")

    failed = []
    for name, val, thr in checks:
        ok = val >= thr
        print(f"  {'✓' if ok else '✗'} {name} {val:.3f} ≥ {thr}")
        if not ok:
            failed.append(name)
    ok_bad = bad <= MAX_BAD
    print(f"  {'✓' if ok_bad else '✗'} fp+fn={bad} ≤ {MAX_BAD}")
    if not ok_bad:
        failed.append("fp+fn")

    if failed:
        print(f"BENCH GATE FAILED: {', '.join(failed)}")
        sys.exit(1)
    print("BENCH GATE PASSED")


if __name__ == "__main__":
    main()