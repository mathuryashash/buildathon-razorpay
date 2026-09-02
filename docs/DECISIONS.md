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
a separate condition from `window_count_gt`. Each condition now means exactly
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
