"""The counts in the documentation must match the repository.

Every count in this project has been wrong at least once. "14 rules" survived
several commits after there were 15. The README claimed 31 scenarios while
there were 43, then 43 while there were 52, then 52 while there were 53. Two
different files quoted two different test counts, and neither was right.

Correcting them by hand fixes the instance and not the class -- the next
scenario anyone adds puts them back out of date, silently, and the first
person to notice is whoever is reading the README to decide whether to take
the project seriously.

So each claim below is anchored to the exact sentence that makes it, and the
build fails when the sentence stops being true. If a number here fails, do not
edit the test: edit the document, because the document is the thing that is
wrong.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


# ---- ground truth, computed ----------------------------------------------


def _corpus(name: str) -> tuple[int, int]:
    raw = yaml.safe_load((ROOT / f"evals/scenarios/{name}.yaml")
                         .read_text(encoding="utf-8")) or {}
    scen = raw.get("scenarios") or []
    return len(scen), sum(len(s["calls"]) for s in scen)


def truth() -> dict[str, int]:
    a_s, a_c = _corpus("attacks")
    b_s, b_c = _corpus("benign")
    _, h_c = _corpus("holdout")
    rules = yaml.safe_load((ROOT / "policies/default.yaml")
                           .read_text(encoding="utf-8"))["rules"]
    return {
        "rules": len(rules),
        "scenarios": a_s + b_s,
        "calls": a_c + b_c,
        "attack_calls": a_c,
        "benign_calls": b_c,
        "holdout_calls": h_c,
        "adrs": (ROOT / "docs/DECISIONS.md").read_text(encoding="utf-8").count("\n## ADR"),
        "tests": _count_tests(),
    }


def _count_tests() -> int:
    """Every `def test_` in this directory, including parametrised ones once.

    Counting definitions rather than collected cases keeps this from importing
    pytest's internals, and it is the number the docs actually mean when they
    say "N tests".
    """
    n = 0
    for f in sorted((ROOT / "tests").glob("test_*.py")):
        n += len(re.findall(r"^def test_", f.read_text(encoding="utf-8"), re.M))
    return n


# ---- the claims, each anchored to the sentence that makes it -------------
#
# (file, regex with ONE capture group, key in truth()). The regex must be
# specific enough that it cannot match a different sentence -- a bare
# r"(\d+) rules" also matches "add 1-2 rules of your own".

CLAIMS: list[tuple[str, str, str]] = [
    ("README.md", r"`make eval` -- (\d+) scenarios", "scenarios"),
    ("README.md", r"`make eval` -- \d+ scenarios, (\d+) calls", "calls"),
    ("README.md", r"\| `evals/` \| (\d+) scenarios", "scenarios"),
    ("README.md", r"\| `evals/` \| \d+ scenarios / (\d+) calls", "calls"),
    ("README.md", r"\| `policies/default\.yaml` \| (\d+) rules", "rules"),
    ("README.md", r"\| `docs/DECISIONS\.md` \| (\d+) ADRs", "adrs"),
    ("README.md", r"Verdict match, whole attack corpus \| (\d+) / \d+", "attack_calls"),
    ("docs/BUILD_PLAN.md", r"- \[x\] (\d+) eval scenarios", "scenarios"),
    ("docs/BUILD_PLAN.md", r"- \[x\] \d+ eval scenarios / (\d+) calls", "calls"),
    ("docs/BUILD_PLAN.md", r"- \[x\] Unit tests, CI, Makefile, (\d+) ADRs", "adrs"),
    ("docs/BUILD_PLAN.md", r"- \[x\] Policy engine . (\d+) rules", "rules"),
    ("docs/SUBMISSION.md", r"`docs/DECISIONS\.md` \((\d+) ADRs\)", "adrs"),
]


@pytest.mark.parametrize("rel,pattern,key", CLAIMS,
                         ids=[f"{c[0]}:{c[2]}" for c in CLAIMS])
def test_a_documented_count_matches_the_repository(rel, pattern, key):
    text = (ROOT / rel).read_text(encoding="utf-8")
    found = re.search(pattern, text)
    assert found, (
        f"{rel} no longer contains the sentence this test anchors to "
        f"({pattern!r}). Either restore it or delete this claim from CLAIMS."
    )
    expected = truth()[key]
    assert int(found.group(1)) == expected, (
        f"{rel} says {found.group(0)!r}, but {key} is actually {expected}. "
        f"Fix the document, not this test."
    )


def test_the_holdout_score_is_quoted_consistently():
    """15/21 appears in four places. All four move together or none do."""
    n_calls = truth()["holdout_calls"]
    for rel in ("README.md", "THREAT_MODEL.md", "docs/DECISIONS.md",
                "docs/BUILD-DECISIONS.md"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        for m in re.finditer(r"(\d+)\s*/\s*(\d+)\s*(?:--|—)?\s*71\.4", text):
            assert int(m.group(2)) == n_calls, (
                f"{rel} quotes a held-out denominator of {m.group(2)}, but the "
                f"sealed set has {n_calls} calls")


def test_no_document_still_advertises_a_removed_make_target():
    """`make demo-live` was replaced by `make preflight` / `make live`.

    Only the make target is checked. `demo.py --live` still exists -- it
    prints a redirect and exits -- and BUILD-DECISIONS.md discusses it by
    name, which is a description of history rather than an instruction.
    """
    for f in [ROOT / "README.md", *(ROOT / "docs").glob("*.md")]:
        text = f.read_text(encoding="utf-8")
        assert "make demo-live" not in text,             f"{f.name} still tells the reader to run a make target that is gone"
