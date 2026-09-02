# Do Not Build This

A list of things that will feel productive and will cost you the submission.
Read it before every work session. The deadline is **5 September 2026** and the
single most common failure mode is building the wrong thing well.

---

## 1. Do not run the hold-out set early, and do not tune against it

> **This has now happened, and the rule holds harder than before.** The code
> was frozen at `git tag freeze`, the set was written blind by an agent with no
> access to the rules, it was committed before the run, and it was run once:
> **15/21, 71.4%.** Four of the six misses are real findings, one of them a
> whole category of attack the threat model never considered. **None of them
> are being fixed before submission**, because a fix would make the number
> meaningless and there is no second hold-out. See the README.

`evals/scenarios/holdout.yaml` is sealed. It is empty until code freeze.

The moment you write hold-out scenarios while the rules are still moving, you
have two in-sample corpora and zero held-out ones, and the only number in the
README that carries any evidential weight is gone. There is no recovering it —
you cannot un-see a test case.

**Rule:** freeze code → write hold-out → run once → publish whatever it says.
If you break this, say so in the README. A candidate who admits they
contaminated their hold-out reads as honest. One who quietly reports 100% reads
as either lucky or lying, and a panel cannot tell which.

## 2. Do not add rules without adding a benign scenario

Every rule in `policies/default.yaml` must ship with:
- at least one **attack** scenario it blocks, and
- at least one **benign** scenario it must *not* block.

Rules without benign coverage are how you end up with a firewall that scores a
100% block rate and is unusable. The deny-all baseline printed by `make eval`
exists to make that failure mode impossible to ignore.

## 3. Do not build an expression evaluator for policy conditions

You will be tempted. A rule will need something the ten conditions in
`gatekeeper/policy.py` don't express, and adding `eval()` or a mini-language
will look like the general solution.

Don't:
- It is a code-execution sink in the component whose entire job is enforcement
- A merchant cannot read it, which destroys the "explainable" property
- It is a two-day project and you have three days total

If a rule cannot be stated in one sentence with the existing conditions, the
rule is probably wrong. Add one narrowly-typed condition to `CONDITIONS` with a
test, or split it into two rules.

## 4. Do not build an approval web UI

The CLI queue and `GET /v1/approvals` are enough to prove the mechanism. A
React approval dashboard is a day of work that adds no measurement and no
architectural claim. Put it in "future work" and move on.

## 5. Do not build a real MCP wrapper unless everything else is done

Wrapping Razorpay's actual MCP server is the right long-term design and a good
line in the README as *intent*. It is also a rabbit hole of transport plumbing.
The mock backend mirrors Razorpay's response shapes, so the architecture above
the backend line is identical either way. Ship the architecture; note the
wrapper as next.

## 6. Do not turn the attack corpus into a tool

`evals/scenarios/attacks.yaml` is test fixture data describing generic agent
failure modes against a merchant in this repo. Keep it that way:

- No CLI that runs attacks against an arbitrary URL
- No scenarios targeting a real third-party endpoint
- No real-world exploit content, credentials, or bypass techniques
- Nothing that works outside this repository

Track 02's brief says anything offense-capable is disqualified. That instinct
applies here too. State the defensive intent in the README and keep the corpus
inert.

## 7. Do not put a credential anywhere except `gatekeeper/backends.py`

Not in the agent. Not in a test. Not in a notebook "just to check something".
Not in a commit you plan to amend later — git remembers.

`tests/test_no_secrets_in_agent.py` enforces this. If it ever fails, the fix is
to remove the credential, never to relax the test. This is the project's
central claim; a hard-coded key in the agent makes the README false.

**If a key does get committed:** rotate it in the Razorpay dashboard first,
then clean history. Rotating is the fix. Deleting the line is not — the key is
in the object store the moment you push.

## 8. Do not use floats for money

Every amount is an integer number of paise. `0.1 + 0.2 != 0.3`, and a
rounding error in a spend cap is a security bug, not a cosmetic one. If you
see `float` anywhere near an amount, that is a defect.

## 9. Do not read the wall clock in policy or tests

Time is injected (`now=`) everywhere, for two reasons: `TIME-001` makes
verdicts time-dependent, so an unpinned clock means the test suite passes in
the afternoon and fails at midnight; and reproducible evals require
reproducible inputs.

Two separate bugs during this build came from injecting time in one place and
not another — see `docs/DECISIONS.md`, ADR-008. If you add a component, inject
its clock from the start.

## 10. Do not make the agent smarter

The agent is deliberately thin. A better shopping agent does not improve this
submission, because the agent is not the contribution — the enforcement layer
underneath it is. A *more capable* agent that still cannot exceed its bounds is
the demo; a more capable agent with no bounds is everyone else's submission.

## 11. Do not gold-plate the reference merchant

Ten SKUs. That is enough to complete a purchase end to end. A hundred SKUs, a
storefront UI, or a cart-persistence layer proves nothing extra and eats hours.

## 12. Do not skip the README's "what doesn't work" section

It is the highest-value paragraph in the repo. The application form has a field
called *"What Broke and How You Got Out"* — they are explicitly asking for the
failure narrative. A repo that names its own limits is doing the reviewer's job
for them, and it is the strongest available signal that the numbers above it
are honest.

---

## The one-line test

Before starting any new piece of work, ask:

> **Does this change a number in the README, or make an existing number more
> trustworthy?**

If no, it is future work. Write it in the README's "Future work" section, feel
the small satisfaction of having captured it, and do something else.
