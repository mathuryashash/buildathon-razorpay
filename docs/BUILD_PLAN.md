# Build Plan — 2 to 5 September 2026

The scaffold in this repo is the Wednesday and Thursday work, done. What
remains is verification, honesty, and packaging.

---

## Already done

- [x] Threat model written **before** feature code, 8 threats, explicit non-goals
- [x] Effect registry with deny-by-default on undeclared operations
- [x] Policy engine — 15 rules, 13 typed conditions, deny beats allow
- [x] Capability tokens; agent holds no credential; test enforces it
- [x] The grant's own ceilings enforced, not just carried (ADR-014)
- [x] Hash-chained audit log + independent `verify` CLI
- [x] Content-addressed idempotency, checked before execution, under a lock
- [x] Mock backend (Razorpay-shaped) and real test-mode backend
- [x] Reference merchant + buyer agent, checkout end to end
- [x] 52 eval scenarios / 145 calls across two corpora + deny-all baseline
- [x] 73 unit tests, CI, Makefile, 20 ADRs, docs
- [x] Ten real bugs found and written up — two by the eval during the build,
      three by a self-review, five by an adversarial review pass

## What the review pass changed, and why it is in this file

The Thursday plan said "add 1–2 rules of your own" and "widen the benign
corpus". Both happened. What was not planned, and mattered more, was pointing
an adversarial reviewer at the finished project with a single instruction:
break the enforcement.

It found five bugs, three of them in claims the README already made in the
present tense — a retry storm that double-charged under concurrency, a
destination allowlist that an agent could switch off by deleting a field, and
a velocity fix that had only ever been half applied. None of them were
findable by adding another rule. All of them were findable in an hour by
someone whose job was to disbelieve the documentation.

If there is one process lesson from this build, it is that: **the highest-yield
hour was not spent writing rules or scenarios. It was spent trying to break
the thing that already passed its own tests.**

## Thursday 3 September

| | Task | Done means |
|---|---|---|
| AM | Clone, `make install`, `make test`, `make eval`, `make demo` | All green on your machine |
| AM | `.env` with your own rotated test key + fresh signing secret | `make demo-live` creates a real test-mode payment link |
| PM | Read `THREAT_MODEL.md` and every rule until you can defend each one **unprompted** | You can say what breaks without each rule |
| PM | Add 1–2 rules of your own following `docs/HOW_TO_WORK.md` | Threat + rule + attack + benign + test, all five |
| EVE | Widen the benign corpus — it finds the bugs that matter | 77 benign calls |

## Friday 4 September

| | Task | Done means |
|---|---|---|
| AM | Any last rules. Widen coverage where a family looks thin. | Every rule has both an attack and a benign scenario |
| **12:00** | **CODE FREEZE.** No more rule edits, none, for any reason. | `git tag freeze` |
| PM | Write `evals/scenarios/holdout.yaml` — 5 scenarios, **without re-reading the rules**. Better: get someone else to write 3. | 5 scenarios written blind |
| PM | `make eval-holdout` — **once** | Number recorded, whatever it is |
| PM | Put the real number in the README. If it is bad, explain why in "Honest limitations". | README row filled |
| EVE | Record the video (`docs/DEMO_SCRIPT.md`) | Under 5:00, limits section intact |
| EVE | **Submit.** | Confirmation received |

## Saturday 5 September

Buffer only. If you are building on Saturday, something went wrong on Friday.

---

## If you fall behind — cut in this order

1. Extra rules of your own (11 is already a defensible set)
2. `make demo-live` (the mock demonstrates the same architecture)
3. The reference merchant's polish
4. Widening the benign corpus past 40 calls

## Never cut

1. The hold-out protocol — it is the only number with evidential weight
2. The README's "Honest limitations" section
3. The video's final minute on what is wrong with it
4. `tests/test_no_secrets_in_agent.py`

---

## The one-line test, again

> Does this change a number in the README, or make an existing number more
> trustworthy?

If no, it goes in "Future work" and you do something else.
