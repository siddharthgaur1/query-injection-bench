"""CLI: score every adapter over the corpus and write the leaderboard.

    python -m qib.run                 # score all offline adapters
    python -m qib.run --adapter naive # score one
    python -m qib.run --repeats 3     # report variance across runs

All offline adapters are deterministic, so `--repeats` should report zero
variance. That is the point: if it ever does not, something non-deterministic
crept into a guard and the benchmark should say so out loud.
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

from qib.adapters import build_registry
from qib.case import load
from qib.score import score

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus" / "cases.jsonl"
RESULTS = ROOT / "results"


def main() -> int:
    parser = argparse.ArgumentParser(description="Score NL-to-query guards against the corpus.")
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--adapter", action="append", help="Adapter name; repeatable.")
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--out", type=Path, default=RESULTS / "leaderboard.json")
    args = parser.parse_args()

    cases = load(args.corpus)
    RESULTS.mkdir(exist_ok=True)
    registry = build_registry(RESULTS / "fixture.sqlite")

    from qib.adapters import _sql_fixture

    _sql_fixture(RESULTS / "fixture.sqlite")

    wanted = args.adapter or list(registry)
    leaderboard = []

    for name in wanted:
        if name not in registry:
            print(f"unknown adapter {name!r}; known: {', '.join(registry)}")
            return 2
        runs = []
        for _ in range(args.repeats):
            adapter = registry[name]()
            runs.append(score(adapter, cases))
        base = runs[0].as_dict()
        if args.repeats > 1:
            base["variance"] = {
                "safe_work_score_stdev": round(
                    statistics.pstdev([r.safe_work_score for r in runs]), 6
                ),
                "asr_stdev": round(statistics.pstdev([r.asr for r in runs]), 6),
                "repeats": args.repeats,
            }
        leaderboard.append(base)

    leaderboard.sort(key=lambda r: -r["safe_work_score"])
    args.out.write_text(json.dumps({"corpus": str(args.corpus), "cases": len(cases),
                                    "results": leaderboard}, indent=2), encoding="utf-8")

    header = f"{'adapter':34} {'scored':>6} {'ASR':>7} {'wASR':>7} {'FPR':>7} {'score':>7}"
    print(header)
    print("-" * len(header))
    for row in leaderboard:
        print(
            f"{row['adapter']:34} {row['scored']:6} "
            f"{row['attack_success_rate']:7.3f} {row['weighted_attack_success_rate']:7.3f} "
            f"{row['false_positive_rate']:7.3f} {row['safe_work_score']:7.3f}"
        )
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
