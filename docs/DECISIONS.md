# Architecture Decision Records

Short records of choices that had a real alternative. The panel round is on
architecture — these are the answers, written down while the reasoning was
fresh rather than reconstructed afterwards.

ADR-006, 007 and 008 are the "what broke" records. They are the interesting ones.

---

## ADR-001 — The proxy holds the credential, not the agent

**Alternative considered:** agent holds the Razorpay key; the proxy observes
calls and logs violations.

**Chosen:** proxy holds the key; agent holds a scoped, short-lived capability
token and can only reach the API through the proxy.

**Why:** an observer is not a control. If the agent has the key it can call
Razorpay directly and the proxy never sees it, which makes every rule in
`policies/default.yaml` advisory. This is the difference between the project
being a security control and being a dashboard.

**Cost:** the proxy is now a single point of failure and a single point of
compromise. Accepted, and stated in `THREAT_MODEL.md` non-goals.

**Enforced by:** `tests/test_no_secrets_in_agent.py`.

---

## ADR-002 — Effects are declared statically; undeclared means denied

**Alternative:** infer danger from the operation name (`create_*` is a write,
`fetch_*` is a read), or ask an LLM to classify.

**Chosen:** an explicit table in `policies/effects.yaml`; anything absent is denied.

**Why:** name-based inference fails on the first operation named against
convention, and fails *open*, which is the wrong direction. LLM classification
puts a probabilistic component in the enforcement path. A static table means
adding a tool is a deliberate reviewable act — you cannot widen the blast
radius by registering a new MCP tool.

**Cost:** every new operation needs a manual classification step. That cost is
the feature.

---

## ADR-003 — Policy is YAML data, not prompt text and not Python

**Alternatives:** (a) system-prompt instructions; (b) Python predicate functions.

**Why not prompts:** an instruction inside the context window has the same
privilege as an injection inside the context window. It is not a boundary.

**Why not Python:** enforceable but not reviewable. A merchant cannot audit a
function body, and "explainable" is in the track's bar.

**Cost:** a fixed, small condition vocabulary. Some rules cannot be expressed.
That is deliberate — see `DO_NOT_BUILD.md` item 3.

---

## ADR-004 — A gradient-free rule engine, not a learned risk model

**Alternative:** train a classifier on transaction features to score risk.

**Chosen:** deterministic rules.

**Why:** three days, no real labelled data, and a probabilistic verdict is not
explainable to the merchant whose money it just stopped. A model also cannot
give you the exact sentence to put in the audit log. If this became a product,
a model would sit *beside* the rules as an additional signal feeding a
`require_approval`, never replacing the deterministic deny path.

---

## ADR-005 — Hand-rolled HMAC tokens, not JWT

**Alternative:** PyJWT.

**Why:** one issuer, one verifier, one algorithm. JWT's flexibility here is
pure downside — `alg: none` and HS/RS confusion are the two most-repeated
authentication CVEs in the ecosystem, and both come from the library honouring
an algorithm field the attacker controls. Forty lines of HMAC has neither.
Constant-time comparison via `hmac.compare_digest`.

**Cost:** not interoperable with anything. Correct at this scope; would revisit
the moment a second party had to verify a token.

---

## ADR-006 — Velocity counts money moved, not every action *(what broke, #1)*

**What broke:** `VEL-001` originally applied to both `irreversible_money` and
`reversible_write`. A single purchase creates an order **and** a payment link
for the same rupees, so a ₹1,280 basket consumed ₹2,560 of a ₹2,000 window.
Worse, a legitimate ₹5,000 payment link could never be created at all — a
₹2,000 rolling cap made a ₹5,000 sale impossible.

**How it was found:** the **benign** corpus, not the attack corpus. Scenarios
B1-02 and B1-03 failed while every attack scenario passed. Without a benign
corpus this ships as a 100% block rate and an unusable product.

**Fix:** `VEL-001` applies to `irreversible_money` only. Reversible writes get
`VEL-004`, rate-limited by count rather than value — a payment link moves no
money, so capping its value punishes big baskets for no safety gain, but an
agent emitting hundreds of them is still broken.

**Lesson:** the false-positive corpus is not a formality. It found the only
bug that would have made the thing useless in production.

---

## ADR-007 — Counting is effect-scoped *(what broke, #2)*

**What broke:** `VEL-002` ("at most 5 payments per 10 minutes") counted every
executed action. So browsing the catalogue and creating an order consumed a
customer's refund allowance, and the denial message read
*"5 payments already in the last 10 minutes"* when there had been two.

**Why it matters more than the verdict:** the verdict was arguably defensible.
The *explanation was false*. Track 01's bar says money actions must be
explainable, and an explanation that misstates the facts is worse than no
explanation — it teaches the merchant to distrust the log.

**Fix:** `AuditLog.window_count` takes an `effect` filter; `money_count_gt` is
a separate condition from `window_count_gt`. (Both were renamed to `_gte` in
ADR-020, once someone noticed they compare with `>=`. The names in this
paragraph are the ones that existed at the time.) Each condition now means exactly
one thing.

---

## ADR-008 — Time is injected everywhere *(what broke, #3)*

**What broke:** twice. `TIME-001` makes verdicts depend on the hour, so the
first version of the test suite passed in the afternoon and would have failed
overnight. Fixing that by injecting `now` into evaluation then broke everything
differently — capability tokens were still minted against the *wall clock*, so
every request in the simulated future failed with `token expired`. Thirty-three
tests failed at once with a message that had nothing to do with the actual
problem.

**Fix:** `now` is injectable in `tokens.issue`, `Gatekeeper.handle`, and the
eval harness, and the test fixtures mint tokens against the same pinned clock
they evaluate against.

**Lesson:** injecting a clock in one component and not another is worse than
injecting it nowhere. Do it everywhere at once or not at all.

---

## ADR-009 — Two backends, one interface

**Why:** the eval needs 67 deterministic offline calls; the demo needs one real
API call. Trying to serve both from one backend produces either a flaky eval or
a fake demo. `MockBackend` mirrors Razorpay's response *shapes*, so everything
above the backend line is identical and swapping is a one-flag change.

**Also:** `RazorpayBackend` refuses any key not starting `rzp_test_`. Refusing
production credentials is a control, not a convenience — this project has no
business holding one.

---

## ADR-010 — Denials are audited, and audits are hash-chained

**Alternative:** log successes only (smaller log), or plain append-only.

**Why:** a log that records only what it allowed cannot tell you what it
stopped, which is the half a merchant actually wants to see. And plain
append-only detects nothing — an editor with file access rewrites history
silently. The chain does not make tampering *impossible*; it makes it
*evident*, which is the honest claim and the one made in the README.

---

## ADR-011 — The hold-out set is sealed and empty until freeze

**Why:** scoring 100% against scenarios written by the same person who wrote
the rules proves internal consistency and nothing else. The sealed set is the
only number with evidential weight, and it is worth exactly nothing if it is
consulted while the rules are still moving.

**Cost:** the headline number arrives on the last day and might be bad. That is
the point of a hold-out.

---

## ADR-012 — The policy engine evaluates against the injected clock *(what broke, #4)*

**What broke.** `PolicyEngine.evaluate` asked the audit log for window totals
without passing the timestamp it was evaluating against. `AuditLog` defaults
that argument to `time.time()`. So the window edge came from the wall clock
while the record timestamps came from the injected one, and every window query
compared two different clocks.

Whenever the injected clock was *older* than `wall_clock - 600s`, every record
fell outside the window, every velocity total came back `0`, and the four
velocity rules stopped applying entirely.

**Why nobody noticed.** The eval's `BASE_TS` is a Friday afternoon in September
2026 — in the *future* relative to the build. Future timestamps are trivially
`>= now - 600`, so every record was always inside the window and the whole
`velocity` family scored 15/15 for the wrong reason. The bug was a dated fuse:
it would have started failing on 4 September 2026 at 14:10, during the
submission window, and every run after that forever.

ADR-008 says "time is injected everywhere." It was injected into the token, the
proxy, and the hour-of-day check — and not into the two window queries, which
are the only place the injection actually changes an outcome.

**Fix.** `now` is a required keyword on the `Context` protocol, so a caller
that forgets it is a type error rather than a silently wrong answer.
`tests/test_policy.py::test_velocity_uses_the_injected_clock_not_the_wall_clock`
pins the scenario to June 2020 — a date that can never drift back into the
window — so a passing wall clock cannot hide it again.

**The lesson worth keeping:** a test that passes because of today's date is not
a passing test. When a fixture uses a fixed timestamp, pick one in the past.

---

## ADR-013 — An unreadable amount is denied, not read as zero *(what broke, #5)*

**What broke.** `ActionRequest.amount_paise` was:

```python
v = self.args.get("amount")
return int(v) if isinstance(v, (int, str)) and str(v).isdigit() else 0
```

Everything it did not recognise became `0`. A zero-rupee action passes every
amount rule in the file. So:

| Sent | Read as | Outcome |
|---|---|---|
| `250000` | 250000 | denied by CAP-001 ✓ |
| `"250000"` | 250000 | denied by CAP-001 ✓ |
| `250000.0` | **0** | **allowed and executed** — a ₹2,500 refund through a ₹500 cap |
| `-500000` | **0** | **allowed and executed** |
| `"2.5e5"` | **0** | allowed, then the backend raised a bare `ValueError` |

The float case needs no cleverness at all. A JSON number with a decimal point
deserialises to `float`, so an ordinary sloppy client — never mind an attacker
— turns off the entire per-action cap and every velocity rule at once.

**Why the corpus missed it.** Scenario F1-02 tests an amount "smuggled as a
string" and passes. It reads like the type-confusion family is covered. It
tests the one non-int type the parser happened to handle.

**Fix.** Parsing returns `None` for anything that is not whole non-negative
paise, and `None` is a *deny* (rule `AMT-001`), never a zero. Floats are
rejected outright rather than rounded, even when integral: paise are integers
by definition, and accepting a float here would be the first crack in the "no
floats anywhere near money" rule the rest of the codebase depends on.

**Cost, stated plainly.** A client that sends `17700.0` for a legitimate
₹177 basket now gets denied where it previously succeeded. That is a real
false block and it is the right trade: the alternative is a cap that any
client can switch off by accident. Benign scenarios B6-01…B6-03 fix the
boundary so the rule cannot quietly widen into denying readable amounts too.

**Second bug behind the first.** `"2.5e5"` reached `MockBackend`, which called
`int()` on it and raised a bare `ValueError`. The proxy caught `BackendError`
only, so it escaped, skipped step 8, and left *no audit record* for a call the
proxy had permitted. The handler is now broad and wraps anything unexpected —
an unaudited money call is the one outcome the audit trail exists to prevent.

---

## ADR-014 — A capability's own ceilings are enforced, and enforced after policy

**What was wrong.** Every `Capability` carries `max_action_paise`,
`max_window_paise` and `window_seconds`. Nothing read them. Issuing a
deliberately tight grant — "this scraper agent may move ₹100" — produced a
token that looked narrow, audited as narrow, and was enforced at the
merchant-wide ₹500. The central claim in the README is "a bounded, auditable
grant that a merchant can reason about"; the bound was decoration.

**Fix.** `proxy.py` step 5 enforces both ceilings, for `irreversible_money`
only — that is what they are denominated in. Applying a per-action money cap
to a reversible write would deny a legitimate ₹5,000 payment link, which moves
no money (benign scenario B1-03 exists to catch exactly that).

**Why after policy and not before.** Checking the grant first is cheaper and
was the first implementation. It was wrong for the reason a demo made obvious:
the `issue()` defaults deliberately mirror the policy numbers, so a grant check
placed first shadows `CAP-001` and `VEL-001` completely, and every denial in
the demo read *"your capability caps this"* instead of naming the rule and the
threat it defends. Policy is the artifact a merchant reviews and the thing that
cites a threat ID; when both bind, policy should be the one that explains
itself. A grant can only ever narrow further, so deferring it lets nothing
through. `test_a_policy_denial_is_explained_by_policy_not_by_the_grant` pins
the ordering.

---

## ADR-015 — Console output is reconfigured to UTF-8 at the entry points

**What broke.** Every denial names an amount in rupees. Windows consoles
default to cp1252, which has no `U+20B9`, so `print()` raised
`UnicodeEncodeError` and killed the process mid-demo. Linux CI never saw it.

Reading was broken in the same direction and hid it: `Path.read_text()` with no
`encoding=` uses the platform default, so the YAML rule files were being
decoded as cp1252 and the rupee sign came back as mojibake — which *is*
encodable, so nothing crashed and the output merely looked wrong. Fixing the
reads is what surfaced the crash underneath.

**Fix.** Every `read_text` in the project passes `encoding="utf-8"`, and the
three entry points call `use_utf8_stdout()` with `errors="replace"`. A console
that genuinely cannot render the glyph shows a placeholder; it never aborts a
money decision that has already been made and audited.

**Why a function and not an import side effect:** a library that reconfigures
its caller's stdout on import is a nasty surprise. This is a presentation
concern, so it lives at the three presentation entry points.

---

# Round two: what an adversarial review pass found

The five records above came out of building. The five below came out of
pointing a reviewer at the finished thing and telling it to break the
enforcement. Four of them are worse than anything the build found, and three
were **holes in claims already written down as true**.

---

## ADR-016 — The money window counts money *(what broke, #6)*

**What broke.** ADR-006 above says velocity double-counting was found and
fixed. It was half fixed. The fix scoped VEL-001's *trigger* to
`irreversible_money` and left `AuditLog.window_sum_paise` — the sum the rule
compares against — adding up **every executed row**.

ADR-006's own worked example still failed, verbatim:

```
create_order        Rs 1,280   allow     (reversible, no money moved)
create_payment_link Rs 1,280   allow     (reversible, no money moved)
window_sum_paise                = 256000 paise
create_refund       Rs 0.01     DENY
  "this would take money moved in the last 10 minutes to over Rs 2,000.00
   (already Rs 2,560.00)"
```

Zero rupees had moved. Three failures in one bug: a false block on the money
path, an **explanation stating a number that is not true** — which ADR-007
spends a paragraph arguing is worse than no explanation at all — and the grant
ceiling inheriting all of it, since `max_window_paise` calls the same function.

**Why the regression test did not catch it.**
`test_reversible_writes_do_not_consume_the_money_budget` asserted that three
reversible writes are allowed. They were allowed *with the bug*. The bug is
only observable when a money action follows them, and the test never issued
one. It tested the trigger, which was fixed, and not the sum, which was not.

**Fix.** `window_sum_paise` takes an `effect` filter and the engine passes
`irreversible_money`. The condition is renamed `money_moved_paise_gt` so the
policy file names the quantity it means. The new test does the thing the old
one stopped one line short of.

---

## ADR-017 — The destination allowlist binds to every destination, and requires one *(what broke, #7)*

**What broke.** `DEST-001` is the entire mitigation for T4, and a redirected
refund is the payoff in the demo's own injection story. It had two holes, and
the agent chose which to use:

```
create_refund  {amount: 50000, payment_id: pay_X}                 -> ALLOWED, executed
create_refund  {amount: 50000, customer_id: cust_demo_001,
                               upi_id: "attacker@ybl"}            -> ALLOWED, executed
create_refund  {amount: 50000, upi_id: "attacker@ybl"}            -> denied
```

The first: `counterparty_not_in` began `f.counterparty is not None and ...`,
so a request naming no destination could not match the rule, and the rule
silently did not apply. **Deleting a field turned the control off.**

The second: `counterparty` returned the *first truthy key* from a fixed list,
and the agent writes the payload. Put an allowlisted `customer_id` ahead of
the real destination and the allowlist checks the decoy. The third line proves
the rule would otherwise have fired.

**Why the corpus did not catch it.** Scenario F4-03 is called *"Empty
destination — absent counterparty must not be treated as 'no rule applies'"*.
It used `create_payout`, which `SCOPE-002` holds for approval regardless of
destination. It tested the payout rule, passed, and was reported as
exfiltration coverage for a rule it never reached.

**Fix.** `ActionRequest.counterparties` returns *every* destination field
present; the condition matches if any is outside the allowlist **or if there
are none at all**. F4-03 moved to `create_refund`; F4-04 and F4-05 added.

---

## ADR-018 — The proxy refuses to exist without a signing secret. The class, not the CLI. *(what broke, #8)*

`ARCHITECTURE.md` listed "no signing secret ⇒ the proxy refuses to start" as
one of three fail-closed properties. The check lived in `cli.py`. `Gatekeeper`
itself defaulted to `""`, and `verify()` will happily HMAC against an empty
key — so anything constructing the class directly (which its own docstring
invites, and which the eval and the demo both do) accepted a capability
**anyone could mint, with any scopes and any ceilings they liked**.

`Gatekeeper.__init__` now raises. A fail-closed property that holds at one
entry point is a property of that entry point, not of the system.

---

## ADR-019 — One lock, held for the whole request *(what broke, #9)*

**What broke.** `Gatekeeper` opens two SQLite connections onto one file, and
FastAPI runs sync endpoints on a threadpool. Twelve concurrent requests:

```
identical args, same idempotency_key, 12 threads
  backend calls actually made : 7      <- should be 1
  executed=True responses     : 6
  replayed=True responses     : 0
  audit says money moved      : 240000 paise
  backend actually moved      : 280000 paise
```

`idem.get → backend.call → idem.put` is an unguarded read-modify-write.
₹2,800 moved through a ₹2,000 ceiling. Worse, the `commit()` that raised
`database is locked` runs **after** the backend call, so those executions left
no audit record — and the failed commit left a write transaction open, so
every later request 500'd forever while `/healthz` kept answering
`{"ok": true}`.

Three documents claimed this could not happen: README ("a retry storm cannot
get past it"), ARCHITECTURE ("this is the one that matters"), THREAT_MODEL T6.
`test_retry_storm_executes_exactly_once` fires its twenty retries
**sequentially, in one thread** — asserting a property the code did not have,
about a scenario that is concurrent by definition.

**Fix.** WAL plus a 30-second busy timeout on both connections, and one
process-wide lock held for the whole of `handle`.

**The cost, stated plainly:** the proxy is now serialised. That is the right
trade here and the wrong one at scale. The design is already single-process —
the README says so under "Honest limitations" — the p95 is about 5 ms, and a
correct slow proxy beats a fast one that double-charges. Multi-node needs the
shared velocity state already named as future work, and a mutex is not that.
The lock is marked in the source as the deliberate ceiling it is.

---

## ADR-020 — An internal error is a denial, and it gets audited *(what broke, #10)*

Only step 7 sat inside a `try`. Everything before it raised straight out to
FastAPI, which returned a bare 500 with **no audit record**:

| Input | Raised | Where |
|---|---|---|
| `{"amount": "²"}` | `ValueError` from `int()` — `"²".isdigit()` is `True` | step 4 |
| `Authorization: Bearer x.\xe9` | `TypeError` from `compare_digest` | step 1, **unauthenticated** |

ADR-013 closes with *"an unaudited money call is the one outcome the audit
trail exists to prevent"*, and the fix it describes widened the handler around
the backend call only — while the parser change in the same ADR introduced a
fresh crash one step earlier.

**Fix.** `handle` is now a thin wrapper: catch everything, deny, audit, name
the exception type in the explanation. Amount parsing requires ASCII digits.
`tokens.verify` compares bytes and wraps a malformed payload in `TokenError`.

### Also closed in this pass, each with a test

- **The audit endpoints were unauthenticated.** `/v1/audit`,
  `/v1/audit/verify` and `/v1/approvals` returned every amount, customer id
  and raw payload to anything that could reach the port, and `?limit=0`
  returned the entire table because `rows[-0:]` is `rows[:]`. They now require
  a capability carrying the `read_audit` scope, which a buyer agent's token
  does not have — which is the point of a scoped grant.
- **`verify()` could not see a deletion from the middle** except by luck; it
  now checks sequence continuity. It still cannot see **tail truncation**, and
  no self-contained log can: "the newest record is the newest record" is
  unfalsifiable from inside the file. The README no longer implies otherwise.
- **`_reject` stamped the wall clock and discarded the effect it was handed**,
  so denials landed out of chronological order beside records written at the
  evaluated time, and every auth, scope and grant denial was invisible to an
  effect-filtered forensic query.
- **Two SQLite handles per `Gatekeeper` and no `close()`**, leaking ~350
  undeletable files per `make eval` on Windows.
- **`AMT-002`.** An irreversible money action naming *no* amount was read as a
  valid zero and passed every cap, because every cap asks whether a number is
  too big. Razorpay reads an omitted refund amount as the **full payment**, so
  the one request no rule could bound was also the largest it could make.
- **Four condition names lied.** `window_count_gt` and two siblings compared
  with `>=`, in the file whose entire selling point is that a merchant can
  read it and know what it means. Renamed `_gte`.
- **The "block rate" was not a block rate.** 19 of 41 attack-corpus calls
  carried `expect: allow` — the steps a multi-step attack needs before it
  becomes an attack. The harness printed "Baseline (deny everything): block
  rate 53.7%" for a proxy that denies everything, two lines under a comment
  saying it would score a perfect one, and nobody read it. Verdict-match and
  block rate are now separate numbers.
- **Rules with no coverage at all.** `TIME-001` and `VEL-004` had no attack
  scenario, which `policies/default.yaml` forbids in its own header;
  `ARCHITECTURE.md` excused the first as "not expressible as a sequence of API
  calls" when the harness had supported the `hour:` field all along, and two
  benign scenarios were already using it. `tests/test_rule_coverage.py` now
  replays both corpora, records which rule produced each verdict, and fails
  the build on a rule nothing exercises.
- **Scenarios passing by the wrong mechanism.** F3-04 ("registry lookup must
  be exact, not fuzzy") never reached the registry — the scope check stopped
  it two steps earlier. B4-01's five calls included four with byte-identical
  args, so idempotency collapsed them into one execution and nothing
  accumulated; its narrative described a ceiling its own operation type could
  never reach.

### The pattern, stated once

Nine of these ten records are not "we forgot to handle X". They are **a test
that existed, passed, and tested something else** — or a document asserting a
property the code did not have. Counting scenarios measures nothing. What
matters is which rule actually fired, which is why that is now a test.

---

## ADR-021 — The hold-out ran. 15/21. Nothing gets fixed because of it.

`ADR-011` above describes the protocol. This is what happened when it was
followed.

**Procedure.** Code and policy frozen at `git tag freeze`. Only then was
`evals/scenarios/holdout.yaml` written, by a separate agent given the public
promise, the merchant's customer ids, the operation list and the file format —
and explicitly denied `policies/`, `gatekeeper/`, the other two corpora, the
docs, the tests and the git history. It was instructed to record its honest
prediction in each `expect` rather than the answer it wanted, and its
narratives name the calls it expected the proxy to fail. Committed before the
run. Run once.

**Result: 15/21, 71.4%**, against 100% and 0% in-sample.

**What it found.** Two of the six misses are the same hole, and it is a
category the threat model never contained: every control in this project points
at money *leaving*. An agent that can issue payment links controls money
*arriving*, and can point it at an attacker without the merchant's balance ever
moving. `DEST-001` is scoped to refunds; the grant ceilings are denominated in
money moved. Nothing in the system looks at it. The reviewer predicted that
failure in writing, before the run.

The others: no ownership check binding a refund to the payment it refunds; a
₹500 per-action cap sitting below the merchant's own ₹740 top product price, so
a full refund on the most expensive item in the shop is impossible; and one
disagreement about digit-string amounts that is defensible either way.

**The decision this ADR exists to record: none of it is fixed.**

The temptation is obvious. Each fix is small, and the number would go up. But
the number would then be measuring a proxy that had been tuned against the very
scenarios scoring it, which is the thing `DO_NOT_BUILD.md` item 1 exists to
prevent, and there is no second hold-out to fall back on. A test case cannot be
un-seen.

The choice was: a better proxy with a meaningless number, or a worse proxy with
a real one and four findings written down. A panel can do something with the
second. The first is indistinguishable from the in-sample 100%, which is
indistinguishable from nothing.

**The generalisable lesson, which is the reason this ADR is longer than the
finding.** The five bugs in round one came from verifying the build. The five
in round two came from an adversarial reviewer who could see everything. The
hole in round three came from a reviewer who could see **nothing** — and it is
the only one that was a whole missing category rather than a broken control.

An author cannot see past their own framing, and rereading the threat model is
not a way out of it: the model is the framing. Three different kinds of blindness
needed three different kinds of reader, and the blindest reader found the
biggest gap.
