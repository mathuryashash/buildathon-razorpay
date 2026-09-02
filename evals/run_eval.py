"""The eval harness. This produces the only numbers in the README.

Two corpora, always reported together:

    block rate        = attack calls correctly denied / attack calls
    false-block rate  = benign calls wrongly denied  / benign calls

Quoting the first without the second is the failure mode this whole project
argues against. A deny-all baseline is included in the output for exactly that
reason -- it scores a perfect block rate and a catastrophic false-block rate,
which is the point.

Two different numbers get reported for the attack corpus and they are not
interchangeable. `verdict match` is how many calls did what the scenario said
they should, including the ones a multi-step attack needs to succeed before it
becomes an attack. `BLOCK RATE` is the one that means what it sounds like:
of the calls that must be stopped, how many were.

Every scenario runs against a FRESH database so velocity state cannot leak
between scenarios. Time is injected, never read from the clock, so results are
reproducible.
"""
from __future__ import annotations

import argparse
import json
import shutil
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gatekeeper.backends import MockBackend  # noqa: E402
from gatekeeper.console import use_utf8_stdout  # noqa: E402
from gatekeeper.models import ActionRequest  # noqa: E402
from gatekeeper.proxy import Gatekeeper  # noqa: E402
from gatekeeper.tokens import issue  # noqa: E402

SECRET = "eval-signing-secret-not-a-real-one"

# The agent under test is granted a realistic capability. Note create_transfer
# is deliberately absent so scenario F3-03 exercises the scope check.
GRANTED = [
    "fetch_catalog", "fetch_payment", "fetch_order", "fetch_payment_link",
    "fetch_all_payments", "fetch_settlement",
    "create_order", "create_payment_link", "update_payment_notes",
    "cancel_payment_link", "capture_payment", "create_refund", "create_payout",
    # In scope on purpose, and deliberately absent from policies/effects.yaml.
    # F3-04 claims to test that registry lookup is exact rather than fuzzy;
    # while this was out of scope the proxy's scope check (SCOPE-000) stopped
    # it at step 2 and the registry was never consulted at all. The scenario
    # passed without exercising the thing it names.
    "Create_Refund",
]

BASE_TS = datetime(2026, 9, 4, 14, 0, 0).timestamp()  # a Friday afternoon


@dataclass
class CallOutcome:
    scenario: str
    family: str
    op: str
    expected: str
    got: str
    correct: bool
    latency_ms: float
    explanation: str
    executed: bool
    replayed: bool
    note: str = ""


@dataclass
class Corpus:
    label: str
    outcomes: list[CallOutcome] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def correct(self) -> int:
        return sum(1 for o in self.outcomes if o.correct)

    @property
    def rate(self) -> float:
        """Fraction of calls whose verdict matched expectation.

        NOT a block rate. Multi-step attack scenarios contain calls that are
        SUPPOSED to succeed -- a salami-slice is only an attack once the
        running total crosses the ceiling, so its first four refunds carry
        `expect: allow`. 19 of the 41 attack-corpus calls are like that.
        Calling this a block rate is what let the deny-all baseline print a
        "block rate" of 53.7% for a proxy that denies literally everything,
        two lines below a comment claiming it would score a perfect one.
        Use `block_rate` for the number that means what it says.
        """
        return self.correct / self.total if self.total else 0.0

    @property
    def blocking_calls(self) -> int:
        """Calls that are supposed to be stopped."""
        return sum(1 for o in self.outcomes if _normalise(o.expected) == "deny")

    @property
    def blocked(self) -> int:
        return sum(1 for o in self.outcomes
                   if _normalise(o.expected) == "deny" and o.correct)

    @property
    def block_rate(self) -> float:
        return self.blocked / self.blocking_calls if self.blocking_calls else 0.0

    def by_family(self) -> dict[str, tuple[int, int]]:
        agg: dict[str, list[int]] = {}
        for o in self.outcomes:
            a = agg.setdefault(o.family, [0, 0])
            a[1] += 1
            a[0] += int(o.correct)
        return {k: (v[0], v[1]) for k, v in sorted(agg.items())}


def _load(path: Path) -> list[dict[str, Any]]:
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("scenarios", [])


def _normalise(verdict: str) -> str:
    """deny and require_approval both mean 'did not execute unattended'."""
    return "deny" if verdict in ("deny", "require_approval") else "allow"


def run_corpus(scenarios: list[dict[str, Any]], label: str, *, deny_all: bool = False) -> Corpus:
    corpus = Corpus(label)
    tmpdir = tempfile.mkdtemp(prefix="gatekeeper-eval-")
    for n, sc in enumerate(scenarios):
        # Fresh state per scenario so velocity cannot leak between them, in a
        # directory that gets removed at the end -- mktemp() leaked one file
        # per scenario per corpus pass and never cleaned any of them up.
        db = str(Path(tmpdir) / f"{n:03d}.db")
        gk = Gatekeeper(backend=MockBackend(), db_path=db, signing_secret=SECRET)
        good = issue("eval-agent", GRANTED, secret=SECRET, ttl_seconds=86_400, now=BASE_TS)  # long TTL covers hour-shifted scenarios
        forged = good[:-4] + "AAAA"
        expired = issue("eval-agent", GRANTED, secret=SECRET, ttl_seconds=-10, now=BASE_TS)
        # A grant deliberately tighter than merchant policy: Rs 100 per action,
        # Rs 250 per window, against policy's Rs 500 / Rs 2,000. Scenarios that
        # ask for `token: narrow` test that the narrower of the two actually
        # binds -- these two fields were carried in every token and enforced
        # nowhere until ADR-014.
        narrow = issue("eval-agent", GRANTED, secret=SECRET, ttl_seconds=86_400,
                       now=BASE_TS, max_action_paise=10_000, max_window_paise=25_000)

        for i, call in enumerate(sc["calls"]):
            token = {"forged": forged, "expired": expired,
                     "narrow": narrow}.get(call.get("token"), good)
            hour = call.get("hour")
            ts = BASE_TS + i * 5 if hour is None else \
                datetime(2026, 9, 4, hour, 30, 0).timestamp()

            t0 = time.perf_counter()
            if deny_all:
                got, executed, replayed, expl = "deny", False, False, "deny-all baseline"
            else:
                res = gk.handle(token, ActionRequest(
                    op=call["op"], args=call.get("args", {}),
                    idempotency_key=call.get("idempotency_key")), now=ts)
                got = res.decision.verdict.value
                executed, replayed = res.executed, res.replayed
                expl = res.decision.explanation
            latency = (time.perf_counter() - t0) * 1000

            expected = call["expect"]
            correct = _normalise(got) == _normalise(expected)
            note = ""
            # Some scenarios additionally assert whether the call actually ran
            # (the replay family). Getting the verdict right but executing a
            # duplicate is still a failure.
            if "executes" in call and not deny_all:
                if executed != bool(call["executes"]):
                    correct = False
                    note = f"expected executed={call['executes']}, got {executed}"

            corpus.outcomes.append(CallOutcome(
                scenario=sc["id"], family=sc.get("family", "unknown"), op=call["op"],
                expected=expected, got=got, correct=correct, latency_ms=latency,
                explanation=expl, executed=executed, replayed=replayed, note=note))
    shutil.rmtree(tmpdir, ignore_errors=True)
    return corpus


def main() -> int:
    use_utf8_stdout()
    ap = argparse.ArgumentParser(description="Run the Gatekeeper red-team evaluation")
    ap.add_argument("--holdout", action="store_true",
                    help="ALSO run evals/scenarios/holdout.yaml. Run this ONCE, after "
                         "code freeze. See docs/DO_NOT_BUILD.md item 1.")
    ap.add_argument("--json", type=str, default="", help="write raw results to this path")
    args = ap.parse_args()

    here = Path(__file__).parent / "scenarios"
    attacks = run_corpus(_load(here / "attacks.yaml"), "attack")
    benign = run_corpus(_load(here / "benign.yaml"), "benign")
    base_a = run_corpus(_load(here / "attacks.yaml"), "attack", deny_all=True)
    base_b = run_corpus(_load(here / "benign.yaml"), "benign", deny_all=True)

    holdout = None
    hp = here / "holdout.yaml"
    if args.holdout and hp.exists():
        holdout = run_corpus(_load(hp), "holdout")

    lat = sorted(o.latency_ms for o in attacks.outcomes + benign.outcomes)
    p95 = lat[int(len(lat) * 0.95) - 1] if lat else 0.0

    print()
    print("=" * 74)
    print("  GATEKEEPER EVALUATION")
    print("=" * 74)
    print(f"  Attack corpus : {attacks.correct:>3}/{attacks.total:<3} as expected    "
          f"verdict match     {attacks.rate:6.1%}")
    print(f"    of which     : {attacks.blocked:>3}/{attacks.blocking_calls:<3} stopped        "
          f"BLOCK RATE        {attacks.block_rate:6.1%}")
    print(f"                    ({attacks.total - attacks.blocking_calls} attack-corpus calls "
          f"are steps that must succeed first)")
    print(f"  Benign corpus : {benign.total - benign.correct:>3}/{benign.total:<3} wrongly blocked "
          f"false-block rate  {1 - benign.rate:6.1%}")
    if holdout:
        print(f"  HELD OUT      : {holdout.correct:>3}/{holdout.total:<3} correct        "
              f"held-out score    {holdout.rate:6.1%}")
    # End to end around gk.handle(): token verify, scope, effect lookup, all
    # rules, the grant ceilings, the idempotency read, the mock backend call
    # and the audit write and commit. Not "policy latency" -- the SQLite
    # commit dominates it, and quoting the rules-only number would be
    # flattering the part that was never going to be slow.
    print(f"  Proxy overhead: p50 {statistics.median(lat):.2f} ms   p95 {p95:.2f} ms"
          f"   (end to end, incl. audit write)")
    print("-" * 74)
    print(f"  Baseline (deny everything): block rate {base_a.block_rate:.1%}, "
          f"false-block rate {1 - base_b.block_rate if base_b.blocking_calls else 1 - base_b.rate:.1%}")
    print("  ^ a perfect block rate, and unusable. Why a block rate alone is not a result.")
    print("-" * 74)

    print("\n  ATTACK FAMILIES")
    for fam, (c, t) in attacks.by_family().items():
        flag = "" if c == t else "   <-- MISSES"
        print(f"    {fam:<20} {c}/{t}{flag}")
    print("\n  BENIGN FAMILIES")
    for fam, (c, t) in benign.by_family().items():
        flag = "" if c == t else "   <-- FALSE BLOCKS"
        print(f"    {fam:<20} {c}/{t}{flag}")

    # Hold-out misses are printed too. The point of the set is the failures;
    # a harness that reports the score and hides which calls produced it makes
    # the number impossible to act on -- and impossible to check.
    failures = [o for o in attacks.outcomes + benign.outcomes if not o.correct]
    if holdout:
        h_fail = [o for o in holdout.outcomes if not o.correct]
        print(f"\n  HELD-OUT MISSES ({len(h_fail)} of {holdout.total}):")
        for o in h_fail:
            print(f"    {o.scenario:<6} {o.op:<22} expected {o.expected:<6} "
                  f"got {o.got:<17} {o.note}")
            print(f"           {' '.join(o.explanation.split())[:96]}")
    if failures:
        print(f"\n  {len(failures)} FAILING CALL(S) -- these belong in the README, not hidden:")
        for o in failures:
            print(f"    {o.scenario:<8} {o.op:<22} expected {o.expected:<7} got {o.got:<17} {o.note}")
    else:
        print("\n  No failures in the in-sample corpora.")
        print("  This is expected and is NOT evidence of much: these scenarios were")
        print("  written by the same person who wrote the rules. The held-out set is")
        print("  the number that carries weight. See README 'Honest limitations'.")
    print()

    if args.json:
        Path(args.json).write_text(json.dumps({
            "attack": {"correct": attacks.correct, "total": attacks.total,
                       "verdict_match_rate": attacks.rate,
                       "blocked": attacks.blocked, "blocking_calls": attacks.blocking_calls,
                       "block_rate": attacks.block_rate,
                       "by_family": attacks.by_family()},
            "benign": {"correct": benign.correct, "total": benign.total,
                       "false_block_rate": 1 - benign.rate, "by_family": benign.by_family()},
            "holdout": ({"correct": holdout.correct, "total": holdout.total,
                         "rate": holdout.rate,
                         "misses": [o.__dict__ for o in holdout.outcomes
                                    if not o.correct]} if holdout else None),
            "latency_ms": {"p50": statistics.median(lat), "p95": p95},
            "baseline_deny_all": {"block_rate": base_a.block_rate,
                                  "false_block_rate": 1 - base_b.rate},
            "failures": [o.__dict__ for o in failures],
        }, indent=2, default=str))
        print(f"  raw results -> {args.json}\n")

    # Non-zero exit if the attack corpus is not fully blocked, so CI catches
    # a regression that quietly reopens a hole.
    return 0 if attacks.rate == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
