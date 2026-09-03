# Build Decisions

**Companion to `DECISIONS.md`.** That file is the architectural record — why
the proxy is shaped the way it is, and the ten bugs the enforcement layer
shipped with. This file is the *build* record: the judgement calls made while
producing the demo, the visualiser and the live path, and what changed when
each one first met reality.

Two audiences. If you are explaining this project in five minutes, the
headline sections are marked **▶**. If you are a reviewer asking "why is it
like this", every choice below has its reason attached.

---

## ▶ The one decision everything else follows from

**Measure the enforcement, not the model.**

Almost every entry in an agentic-commerce track will demo an agent that
*succeeds*. The interesting demo is an agent that *fails* — obediently,
plausibly, in the way real prompt-injected agents fail — and a layer
underneath that refuses to let the failure cost anything.

Consequences that fall straight out of it:

- The LLM is never in the pass/fail path. Every verdict is a deterministic
  predicate over a typed request, which is why each one can be explained in a
  sentence a merchant can act on.
- The agent is deliberately unimpressive. A cleverer agent would not make the
  demo better; a cleverer agent that still cannot exceed its bounds is exactly
  the point.
- The headline number is not "it worked". It is a **block rate beside a
  false-block rate**, because either alone is meaningless.

---

## ▶ Two corpora, always reported together

A proxy that denies everything scores a perfect block rate. So the harness
prints a **deny-everything baseline** on every run — 100% block, 100%
false-block — directly under the headline, where it cannot be quoted without
its counterweight.

This is not a hypothetical discipline. The harness once printed
`Baseline (deny everything): block rate 53.7%` — for a proxy that denies
literally everything — two lines below a comment predicting a perfect score.
Nobody read it for a week. The cause: 39 of the attack corpus's 68 calls carry
`expect: allow`, because a salami-slice is not an attack until the running
total crosses the ceiling. "Verdict match" and "block rate" are now separate
numbers with separate labels.

## ▶ The hold-out, and why nothing found by it is fixed

Scoring 100% against scenarios written by the same person who wrote the rules
demonstrates internal consistency and nothing else. So: freeze the code, tag
it, and only *then* have someone who has never seen the rules write five
scenarios. Run once. Publish whatever comes out.

**15 / 21 — 71.4%.**

Four of the six misses are real, and one is a category the threat model never
contained: every control in the project guards money *leaving*, and an agent
that can issue payment links controls money *arriving*. Cancel the merchant's
live link, reissue an identical one with an attacker's UPI handle, and the
customer pays a stranger while the merchant's balance never moves.

**None of it is fixed**, and that is the decision. Fixing after the run tunes
the proxy against the very scenarios scoring it, and a hold-out works once — a
test case cannot be un-seen. The choice was a better proxy with a meaningless
number, or a worse proxy with a real number and four findings written down.

*The generalisable version:* three kinds of reviewer found three kinds of bug.
Verifying the build found five. An adversarial reviewer who could read
everything found five more, worse. The missing *category* came from the
reviewer who could read **nothing** — because an author cannot see past their
own framing, and rereading a threat model is no escape, since the model *is*
the framing.

---

## Decisions about the demo

### The plan is one list, and it is the only source of truth

`AGENT_PLAN` in `demo.py` drives the terminal demo, the visualiser, and the
README transcript. Every alternative meant two lists that drift, and drift is
this project's recurring defect: the README's demo transcript was wrong twice,
the second time because a velocity fix changed the demo's own totals.

### Five acts, sized to exercise all eight lifecycle stages

The plan grew from 12 actions to 22 for one reason: the original only ever
reached **stage 4**. The other seven stages were asserted in prose and never
shown. Each addition earns its place by demonstrating something otherwise
invisible — a forged token for stage 1, an in-scope-but-undeclared operation
for stage 3, a deliberately tighter grant for stage 5, a timed-out retry for
stage 6.

### Act I ends in a capture, not a payment link

The Track 01 brief says *"makes a merchant transactable by an AI buyer **end to
end**"*. The demo previously stopped at creating a link nobody paid, which is
not end to end. One extra action closes the loop.

### ▶ The agent's reasoning is written, and the page says so

Each action carries the agent's stated reasoning, shown above the gate.

**These are authored, not captured from a live model.** A model call mid-run
would make the demo different every time, and this run is the number in the
README and the thing the pitch video records.

What the thoughts are faithful to is the *shape* of the failure: each is the
plausible, confident sentence an obedient model produces immediately before
doing the wrong thing — including the ones where it reasons its way from a
refusal to a workaround ("perhaps it needs to be sent as a decimal"). That
progression is the argument. If the reasoning looked deranged, no enforcement
layer would be needed to catch it.

An unlabelled synthetic LLM trace, in a project whose entire theme is honest
measurement, would be the worst available finding. A reviewer caught that the
disclosure existed only in a source docstring; the page now carries it beside
the text.

---

## Decisions about the visualiser

### ▶ The page renders a real run, and cannot be edited into lying

`tools/build_visualiser.py` executes the agent plan through the real proxy and
rewrites the page's `<script id="trace">` block with what actually happened.
Nothing on that page is typed by hand: every verdict, rule id, threat id,
amount, explanation and audit hash comes from the run.

The alternative — a hand-written mockup — was rejected because every
hand-written figure in this project drifted from the code at least once. A page
of numbers nobody re-checks would have been wrong a third time, and it is the
artifact most likely to be looked at and least likely to be verified.

### The deciding stage is read from the audit log, not from the decision object

A first version derived it from `decision.hits`, which labelled every
proxy-level rejection "stage 4, policy" — because rejections at stages 1, 2 and
5 never reach the policy engine and carry no hits. **The page must not be able
to claim a stage the audit log does not support.**

### Stage 8 is never skipped

The gate greyed out every stage after the deciding one, including "Append to
the audit chain", whose own caption reads *"Always — including on a denial"* —
while the panel beside it visibly wrote a record on that very step. The page
was rendering the exact opposite of its central claim, on all thirteen blocked
actions.

### The rule count is computed

The page said "14 rules of YAML". There are 15, and have been for many commits.
It was the one hand-typed number *inside the generator whose docstring argues
that hand-typed numbers drift*, with `len()` available eight lines below it.

### An unreadable amount shows its raw value

A row whose amount the proxy cannot parse used to render as an em dash, which
hid the entire attack that row exists to demonstrate. It now shows
`250000.0 ?` in amber — visibly the thing the agent sent, visibly not a number
the proxy accepted.

---

## ▶ Decisions about going live

### There is one live path, and it is not `demo.py --live`

Running the 22-action script against Razorpay would have thrown a wall of API
errors in front of a judge. Over half of it is refunds and captures, and those
need a real captured payment behind them — which test mode will not
manufacture headlessly. It also called `fetch_catalog`, which is not a Razorpay
operation at all; the merchant serves its own catalogue.

`demo.py --live` now prints where to go and exits. `demo.py` stays
deterministic and offline so CI can keep running it.

### The live run is interactive on purpose

`live.py` creates a real order and a real payment link, prints the URL, and
**waits while a human pays it with a test card**. Only then does the injected
attack sequence run.

That interactive step is not a limitation worked around — it is the point.
With a real, paid, captured payment behind them, every refund the injection
attempts is one that *would* have succeeded had the proxy allowed it. Blocking
a refund that could not have worked anyway proves nothing.

### Architecture proven live, measurements proven offline

Every *number* in the README — block rate, false-block rate, the held-out
71.4% — comes from the mock backend, and always will. An eval that needs the
network cannot run in CI, cannot be re-run two hundred times, and gives a
different answer on a bad wifi day. Razorpay test mode also cannot generate
batches at all.

Stating that split plainly beats either pretending the numbers are live or
pretending the live path does not exist.

### A preflight that creates nothing

`make preflight` validates the key is a test key, hits the API with a *read*,
and confirms the signing secret — before anything is created against the
account. A demo that discovers a bad credential halfway through has already
left half-finished records behind.

---

## ▶ What the first live run found

Two things no offline test could have caught. Both are in the code now, with
tests.

### The payment link was malformed, and every test passed

```
razorpay call create_payment_link failed:
  incorrect JSON object received - faulty key: customer
```

The backend sent `"customer": args.get("customer", {})`. **An empty customer
object is not "no customer" — it is a malformed one.** The mock accepted it
without complaint, all 78 tests were green, and the failure surfaced one line
into the first run against a real key.

The fix extracts `payment_link_payload()` as a pure function so the *shape* is
testable without a network or a credential, and omits the key entirely when
there is no customer. This is the clearest possible demonstration of why the
mock/live split needs both halves: a shape-compatible mock proves the
architecture, and only a real API proves the payload.

### TIME-001 fired against a real clock, at 23:11

The legitimate refund in Act III was **held for a human** — correctly. The
run happened at 23:11 local, outside the 08:00–21:00 window.

The decision was *not* to weaken the rule for the demo. Instead the run now
detects the hour and says so before it starts, so a held refund reads as the
control working rather than the demo breaking. Re-run inside business hours to
watch the allowed refund execute.

This one is worth showing in the video precisely because it was not staged.

### And one thing that worked first time

`create_order` returned a real order id on the first attempt, through the
proxy, with the agent holding no credential. Everything above the backend line
— token verification, scope, effect classification, all fifteen rules, the
grant ceilings, idempotency, the hash-chained audit — behaved identically
against the live API and the mock. That is the mock's job, and it did it.

### The run, as recorded

Six audit records against the real API. Two real Razorpay objects, both
visible in the Dashboard:

```
allow             create_order          ₹177.00   order_TXeMcCl05WFWOn   [REAL]
allow             create_payment_link   ₹177.00   plink_TXeMcl9ZoleJCt   [REAL]
deny              create_refund       ₹2,500.00   over the per-action cap
deny              create_refund               —   amount 250000.0 unreadable
deny              create_payout       ₹5,000.00   over the per-action cap
require_approval  create_refund          ₹74.00   outside business hours
chain intact across 6 records
```

**The link was not paid within the window**, so the run took its unpaid
branch: the injected refunds were denied at *policy*, before the backend was
consulted, which the audit trail shows. That is the correct behaviour and it
is honestly labelled in the output — but it is the weaker version of the demo.

The stronger version needs somebody to pay the link, and needs to happen
between 08:00 and 21:00. Then the injected refunds are refused against a real
captured payment they *could* have drained, and the legitimate ₹74 refund in
Act III executes for real. Re-running is one command; nothing about the code
changes.

---

### What the live run does NOT prove, and should not be claimed to

Worth being precise about, because the temptation in a pitch is to let "it
runs against the real API" do more work than it can.

- It does not validate the **numbers**. Block rate, false-block rate and the
  held-out 71.4% all come from the mock, by design.
- With the link unpaid, it does not prove the **refund path** end to end
  against Razorpay. The order and the payment link are real; the refunds were
  stopped by policy before any API call, which is the proxy working, not the
  API being exercised.
- It exercises **six** operations. The offline demo exercises twenty-two,
  across all eight lifecycle stages, because most of those cannot happen
  against a fresh test account at all.

What it does prove is the thing that was actually in doubt: the proxy sits in
front of a real payments API, holds the only credential, and its decisions and
audit records are identical whether the backend is a mock or Razorpay.

## Things deliberately not built

Each of these would have felt productive.

| Not built | Why |
|---|---|
| An approval **web UI** | The CLI queue and `GET /v1/approvals` prove the mechanism. A React dashboard adds no measurement and no architectural claim. |
| An **expression evaluator** for policy conditions | A code-execution sink in the component whose entire job is enforcement, unreadable by the merchant it protects, and a two-day project. If a rule cannot be stated in one sentence with the existing vocabulary, the rule is probably wrong. |
| A **real MCP wrapper** | The right long-term design and a rabbit hole of transport plumbing. The mock mirrors Razorpay's response shapes, so the architecture above the backend line is identical either way. |
| A **learned risk model** | It would need to be defended statistically in a panel, and it cannot produce a one-sentence explanation. Named as future work feeding `require_approval`, never replacing the deterministic deny path. |
| **Fixes for the hold-out findings** | Covered above. This is the one that cost something real. |

---

## The pattern worth naming

Across ten shipped bugs and three review passes, **nine were a test that
existed, passed, and tested something else.**

- A scenario named "amount smuggled as a string" tested the one non-integer
  type the parser happened to handle, while a plain JSON float switched off
  every cap.
- The whole velocity family scored 15/15 because the eval's base timestamp was
  in the future.
- The retry-storm test fired its retries sequentially, asserting a property the
  code did not have about a scenario that is concurrent by definition.
- A scenario titled "empty destination" was bound by the payout rule and
  counted as exfiltration coverage for a rule it never reached.

Counting scenarios measures nothing. What matters is **which rule actually
fired** — which is why `tests/test_rule_coverage.py` replays both corpora,
records the rule behind every verdict, and fails the build on a rule nothing
reaches. That test is the most useful thing in the repository, and it exists
because the number at the top of the README was wrong for a week in five
different ways.
