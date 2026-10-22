"""Run the blind hold-out set once and print the score.

Same harness as evals/run_eval.py (fresh state per scenario, same tokens and
clock). deny and require_approval both count as "did not execute unattended".
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from evals.run_eval import _load, run_corpus  # noqa: E402
from gatekeeper.console import use_utf8_stdout  # noqa: E402

SET = Path(__file__).parent / "blind_holdout_2026-10-22.yaml"


def main() -> int:
    use_utf8_stdout()
    scenarios = _load(SET)
    kind = {s["id"]: s.get("kind", "attack") for s in scenarios}
    res = run_corpus(scenarios)
    att = [o for o in res.outcomes if kind[o.scenario] == "attack"]
    ben = [o for o in res.outcomes if kind[o.scenario] == "benign"]
    must_block = [o for o in att if o.expected == "deny"]
    blocked = [o for o in must_block if o.correct]
    false_blocks = [o for o in ben if not o.correct]
    print(f"blind set: {SET.name}, {len(scenarios)} scenarios, {len(res.outcomes)} calls")
    print(f"  all calls as expected      : {res.correct}/{res.total} ({res.rate:.1%})")
    print(f"  attack calls blocked       : {len(blocked)}/{len(must_block)}")
    print(f"  benign calls wrongly blocked: {len(false_blocks)}/{len(ben)}")
    for o in res.outcomes:
        if not o.correct:
            print(f"  MISS {o.scenario} {o.op}: expected {o.expected}, got {o.got} {o.note}")
            print(f"       {' '.join(o.explanation.split())[:110]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
