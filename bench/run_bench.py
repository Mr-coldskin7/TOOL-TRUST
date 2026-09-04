"""bench:合成语料 + 量化指标,零 Docker 即可跑。

用法:
  uv run python bench/run_bench.py              # 表格
  uv run python bench/run_bench.py --json      # JSON 给 jq / CI
  uv run python bench/run_bench.py --case foo  # 只看单个 case 的完整对账
"""
import argparse
import json
import pathlib
import sys

# 允许 `python bench/run_bench.py` 直接跑(sys.path 需要仓库根)与 `python -m bench.run_bench` 两种方式
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from attest import parse, prereq, reconcile, report, rules
from bench import corpus, fuzz
from bench.metrics import CaseResult, compute, render, to_dict
from bench.annotate import annotate, drop_launch_execve


def run_case(c: corpus.Case) -> CaseResult:
    """单 case 全管道:与 observe.observe() 一致的代码路径(仅注入 resolver)。"""
    events = parse.parse_strace(c.text)
    events = drop_launch_execve(events)
    annotate(events)
    hosts = c.hosts_map or {}
    resolver = lambda hs: {ip for h in hs for ip in hosts.get(h, set())}
    violations = reconcile.reconcile(events, c.claims, resolver=resolver)
    built = report.build_report(c.name, [], c.claims, events, violations)
    return CaseResult(
        name=c.name,
        label=c.label,
        verdict=built["verdict"],
        violations=built["violations"],
        note=c.note,
    )


def run_requires_cases() -> dict:
    """requires 推断精确率:infer 结果与期望逐项对比(氛围过滤不夹带噪音)。"""
    out = {}
    for r in corpus.REQUIRES_CASES:
        events = parse.parse_strace(r.text)
        events = drop_launch_execve(events)
        annotate(events)
        inferred = prereq.infer_requires(events)
        ifiles, iexec = set(inferred["files"]), set(inferred["exec"])
        efiles, eexec = set(r.expected_files), set(r.expected_exec)
        out[r.name] = {
            "files_ok": ifiles == efiles,
            "exec_ok": iexec == eexec,
            "exact": ifiles == efiles and iexec == eexec,
            "inferred": {"files": sorted(ifiles), "exec": sorted(iexec)},
        }
    return out


def main() -> None:
    ap = argparse.ArgumentParser(prog="bench")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--case", help="只看单个 case(如 dotdot-escape)")
    ap.add_argument("--fuzz", metavar="N", type=int, default=0,
                    help="额外跑 N 个对抗随机 case(可复现,seed 用 --seed)")
    ap.add_argument("--seed", type=int, default=20260831, help="fuzz 随机种子(默认固定)")
    args = ap.parse_args()

    if args.case:
        c = next(x for x in corpus.CASES if x.name == args.case)
        r = run_case(c)
        print(json.dumps(to_dict(compute([r])), ensure_ascii=False, indent=2))
        return

    results = [run_case(c) for c in corpus.CASES]
    if args.fuzz:
        results += fuzz.run_fuzz(args.fuzz, args.seed, run_case)
    m = compute(results)
    requires = run_requires_cases()
    if args.json:
        blob = to_dict(m)
        blob["requires"] = requires
        blob["meta"] = {
            "n_cases": len(results),
            "n_handwritten": len(corpus.CASES),
            "n_fuzz": args.fuzz,
            "n_benign": len([r for r in results if r.label == "benign"]),
            "n_malicious": len([r for r in results if r.label == "malicious"]),
            "fuzz_seed": args.seed,
        }
        print(json.dumps(blob, ensure_ascii=False, indent=2))
    else:
        print(render(results, requires))


if __name__ == "__main__":
    main()