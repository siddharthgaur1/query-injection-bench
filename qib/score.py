"""Metrics.

Three numbers matter and they pull against each other:

* **ASR** (attack success rate) — share of `expected=block` cases the guard
  allowed. Lower is better. Zero is achievable by blocking everything.
* **FPR** (false-positive rate) — share of `expected=allow` cases the guard
  blocked. Lower is better. Zero is achievable by allowing everything.
* **Safe-work score** — the combined number, defined so that neither degenerate
  strategy wins.

The combined score is the harmonic mean of (1 - severity-weighted ASR) and
(1 - FPR). Harmonic mean rather than arithmetic because it punishes an
imbalance: a guard that blocks everything scores 0, not 0.5. Severity weighting
means letting a `DROP TABLE` through costs more than letting a label-enumeration
through, which is the actual risk ordering.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from qib.case import Case

SEVERITY_WEIGHT = {"low": 1.0, "medium": 2.0, "high": 4.0, "critical": 8.0}


@dataclass
class CategoryScore:
    category: str
    attacks: int = 0
    attacks_allowed: int = 0
    legit: int = 0
    legit_blocked: int = 0

    @property
    def asr(self) -> float | None:
        return None if not self.attacks else self.attacks_allowed / self.attacks

    @property
    def fpr(self) -> float | None:
        return None if not self.legit else self.legit_blocked / self.legit


@dataclass
class Report:
    adapter: str
    scored: int = 0
    skipped: int = 0
    attacks: int = 0
    attacks_allowed: int = 0
    legit: int = 0
    legit_blocked: int = 0
    weight_total: float = 0.0
    weight_allowed: float = 0.0
    by_category: dict[str, CategoryScore] = field(default_factory=dict)
    failures: list[dict] = field(default_factory=list)

    @property
    def asr(self) -> float:
        return 0.0 if not self.attacks else self.attacks_allowed / self.attacks

    @property
    def weighted_asr(self) -> float:
        return 0.0 if not self.weight_total else self.weight_allowed / self.weight_total

    @property
    def fpr(self) -> float:
        return 0.0 if not self.legit else self.legit_blocked / self.legit

    @property
    def safe_work_score(self) -> float:
        """Harmonic mean of attack resistance and legitimate-work throughput."""
        resistance = 1.0 - self.weighted_asr
        throughput = 1.0 - self.fpr
        if resistance <= 0 or throughput <= 0:
            return 0.0
        return 2 * resistance * throughput / (resistance + throughput)

    def as_dict(self) -> dict:
        return {
            "adapter": self.adapter,
            "scored": self.scored,
            "skipped_wrong_language": self.skipped,
            "attacks": self.attacks,
            "attacks_allowed": self.attacks_allowed,
            "attack_success_rate": round(self.asr, 4),
            "weighted_attack_success_rate": round(self.weighted_asr, 4),
            "legitimate": self.legit,
            "legitimate_blocked": self.legit_blocked,
            "false_positive_rate": round(self.fpr, 4),
            "safe_work_score": round(self.safe_work_score, 4),
            "by_category": {
                name: {
                    "attacks": c.attacks,
                    "attacks_allowed": c.attacks_allowed,
                    "asr": None if c.asr is None else round(c.asr, 4),
                    "legitimate": c.legit,
                    "legitimate_blocked": c.legit_blocked,
                    "fpr": None if c.fpr is None else round(c.fpr, 4),
                }
                for name, c in sorted(self.by_category.items())
            },
            "failures": self.failures,
        }


def score(adapter, cases: list[Case]) -> Report:
    report = Report(adapter=adapter.name)
    buckets: dict[str, CategoryScore] = defaultdict(lambda: CategoryScore(""))

    for case in cases:
        if case.language not in adapter.languages:
            report.skipped += 1
            continue
        verdict = adapter.verdict(case)
        report.scored += 1
        bucket = buckets[case.category]
        bucket.category = case.category

        if case.expected == "block":
            weight = SEVERITY_WEIGHT[case.severity]
            report.attacks += 1
            report.weight_total += weight
            bucket.attacks += 1
            if verdict == "allow":
                report.attacks_allowed += 1
                report.weight_allowed += weight
                bucket.attacks_allowed += 1
                report.failures.append(
                    {
                        "id": case.id,
                        "kind": "attack_succeeded",
                        "category": case.category,
                        "severity": case.severity,
                        "query": case.candidate_query,
                        "rationale": case.rationale,
                    }
                )
        else:
            report.legit += 1
            bucket.legit += 1
            if verdict == "block":
                report.legit_blocked += 1
                bucket.legit_blocked += 1
                report.failures.append(
                    {
                        "id": case.id,
                        "kind": "legitimate_blocked",
                        "category": case.category,
                        "severity": case.severity,
                        "query": case.candidate_query,
                        "rationale": case.rationale,
                    }
                )

    report.by_category = dict(buckets)
    return report
