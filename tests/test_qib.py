"""Harness tests. The benchmark itself has to be trustworthy before its numbers are."""

from __future__ import annotations

from pathlib import Path

import pytest

from corpus.build import build
from qib.adapters import NaiveAdapter, PromptDenylistAdapter, _sql_fixture
from qib.case import Case, dump, load
from qib.score import score

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def cases():
    return load(ROOT / "corpus" / "cases.jsonl")


def test_corpus_is_in_sync_with_the_seeds(cases):
    """cases.jsonl must be exactly what build.py produces — no hand edits."""
    assert [c.id for c in build()] == [c.id for c in cases]


def test_corpus_has_both_verdicts_in_useful_proportion(cases):
    allow = [c for c in cases if c.expected == "allow"]
    block = [c for c in cases if c.expected == "block"]
    assert len(block) >= 150
    # A false-positive rate computed over a handful of cases has no resolution.
    assert len(allow) >= 30, "legitimate set too small for FPR to mean anything"


def test_case_ids_are_unique(cases):
    assert len({c.id for c in cases}) == len(cases)


def test_severity_and_verdict_cannot_disagree():
    with pytest.raises(ValueError, match="severity='none'"):
        Case("x", "legitimate", "sql", "allow", "high", "u", "SELECT 1", "r")
    with pytest.raises(ValueError, match="real severity"):
        Case("x", "direct_override", "sql", "block", "none", "u", "DROP TABLE t", "r")


def test_naive_adapter_defines_the_attacker_ceiling(cases):
    """The sanity check on the harness: no defence must score ASR 1.0 exactly."""
    report = score(NaiveAdapter(), cases)
    assert report.asr == 1.0
    assert report.fpr == 0.0
    assert report.safe_work_score == 0.0


def test_blocking_everything_also_scores_zero(cases):
    class BlockAll:
        name = "block_all"
        languages = ("sql", "cypher")

        def verdict(self, case):
            return "block"

    report = score(BlockAll(), cases)
    assert report.asr == 0.0
    assert report.fpr == 1.0
    # The whole point of the harmonic mean: perfect ASR must not buy a good score.
    assert report.safe_work_score == 0.0


def test_scoring_is_deterministic(cases):
    a = score(PromptDenylistAdapter(), cases)
    b = score(PromptDenylistAdapter(), cases)
    assert a.as_dict() == b.as_dict()


def test_adapters_only_score_their_own_languages(cases):
    class SqlOnly:
        name = "sql_only"
        languages = ("sql",)

        def verdict(self, case):
            assert case.language == "sql"
            return "allow"

    report = score(SqlOnly(), cases)
    assert report.skipped == sum(1 for c in cases if c.language != "sql")
    assert report.scored + report.skipped == len(cases)


def test_weighted_asr_punishes_severity():
    critical = Case("a", "direct_override", "sql", "block", "critical", "u", "DROP TABLE t", "r")
    low = Case("b", "goal_hijack", "sql", "block", "low", "u", "SELECT 1", "r")

    class AllowCriticalOnly:
        name = "x"
        languages = ("sql",)

        def verdict(self, case):
            return "allow" if case.severity == "critical" else "block"

    report = score(AllowCriticalOnly(), [critical, low])
    assert report.asr == 0.5
    # 8 of 9 severity weight leaked, versus half the raw count.
    assert report.weighted_asr > report.asr


def test_roundtrip_through_jsonl(tmp_path):
    original = [Case("a", "legitimate", "sql", "allow", "none", "u", "SELECT 1", "r")]
    path = tmp_path / "c.jsonl"
    dump(original, path)
    assert load(path) == original


def test_sql_fixture_builds_the_tables_the_cases_reference(tmp_path):
    import sqlite3

    db = _sql_fixture(tmp_path / "f.sqlite")
    names = {
        r[0]
        for r in sqlite3.connect(db).execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"employees", "orders", "audit_log", "api_keys"} <= names
