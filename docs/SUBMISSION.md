# Submission Checklist and Form Answers

**Deadline: 5 September 2026. Submit on the 4th.**
The completed project is due *with* the application — repo URL, 5-minute video,
architecture walkthrough. There is no apply-now-build-later path.

---

## Pre-submission gate

```bash
make clean && make test && make eval && make demo
git status                                             # clean; no .env, no *.db
grep -rn "rzp_test_[A-Za-z0-9]\{10,\}" --exclude-dir=.git .   # must return nothing
```

- [ ] All tests pass
- [ ] `make eval` exits 0
- [ ] `make demo` prints two different money totals
- [ ] **Code frozen.** No more rule edits.
- [ ] `evals/scenarios/holdout.yaml` written *after* freeze, 5 scenarios, no peeking
- [ ] `make eval-holdout` run **once**; number in the README whatever it says
- [ ] README "Held-out set" row filled in
- [ ] Repo is public; README renders correctly on GitHub
- [ ] Video recorded, unlisted, under 5:00
- [ ] `.env` is **not** in the repo; test key rotated if it was ever pasted anywhere

---

## Form answers

### Project name
**Gatekeeper**

### Track
Track 01 — AI Growth & Agentic Commerce

### One-line description
An AI buyer agent that completes checkout end to end while holding no payment
credentials — every money action passes a fail-closed policy proxy with a
tamper-evident audit trail.

### What it does (elevator pitch)

> Razorpay is shipping agentic payments — in-app commerce, UPI Reserve Pay, an
> MCP server with 45 tools. The open question isn't whether an AI agent can pay;
> it's what stops one that's been prompt-injected or has simply gone wrong.
> Gatekeeper is an AI buyer that completes checkout end to end while holding no
> payment credentials at all: every money action is exchanged through a
> fail-closed capability proxy that enforces spend bounds, velocity limits and
> approval thresholds, and writes a tamper-evident audit trail in language a
> merchant can read. I measured it on 20 adversarial and 14 benign scenarios —
> 145 calls — because a firewall that blocks everything scores 100%, and only the
> false-block rate tells you whether it's usable.

### Technical summary

> A proxy sits between the agent and the payments API, holding the credential
> the agent never sees and exchanging scoped, short-lived capability tokens for
> real calls. Every operation is statically annotated `read`,
> `reversible_write` or `irreversible_money`, and any unannotated operation is
> denied by default — so registering a new tool cannot silently widen what an
> agent can do. Declarative YAML rules then gate each call on amount, velocity,
> counterparty and approval threshold, and every verdict is written to a
> hash-chained log an independent CLI can verify for tampering. The LLM
> generates shopping intent and explanations but never appears in the pass/fail
> path: every verdict is a deterministic predicate over a typed request.

### Impact

> Merchants adopting agentic checkout are being asked to let software they don't
> control spend their customers' money, and the only controls available today
> are all-or-nothing — give the agent keys or don't. Gatekeeper makes the middle
> position possible: a bounded, auditable grant a merchant can reason about, and
> that a compromised agent cannot exceed.

### Architecture decisions
See `ARCHITECTURE.md` and `docs/DECISIONS.md` (24 ADRs). The three worth
defending: the proxy holds the credential rather than observing the agent
(ADR-001); undeclared operations are denied rather than inferred (ADR-002);
policy is data rather than prompt text (ADR-003).

---

### "What Broke and How You Got Out"

**Write the real one.** This field exists to surface the failure narrative — a
polished non-answer wastes the single best opportunity in the form. The
strongest candidate, and it is genuinely what happened:

> The first version had the agent holding the Razorpay key, with the proxy
> sitting alongside it observing calls and logging violations. It demoed fine.
> Then I tried to write the test that proves an agent can't exceed its bounds
> and realised I couldn't write it — because the agent could just call the API
> directly and the proxy would never see it. Every rule I'd written was a
> suggestion, not a control.
>
> I inverted the trust boundary: the proxy holds the credential, the agent gets
> a scoped short-lived capability token, and there's now a test that fails the
> build if a Razorpay credential ever appears in the agent package. That test is
> the first one I'd point a reviewer at, because the whole project's claim rests
> on it.
>
> Two smaller ones, both caught by the eval rather than by me. The velocity rule
> originally counted reversible writes toward the spend window — but a single
> purchase creates an order *and* a payment link for the same rupees, so a
> ₹1,280 basket ate ₹2,560 of a ₹2,000 allowance and a legitimate ₹5,000 payment
> link could never be created at all. The *benign* corpus caught it while every
> attack test passed, which is exactly why that corpus exists. And a rate limit
> reading "5 payments in 10 minutes" was counting every action, so the denial
> message said "5 payments already" when there had been two — the verdict was
> defensible but the explanation was false, and a false explanation in an audit
> log is worse than none. Both are written up as ADR-006 and ADR-007.

---

## Likely panel questions

| Question | Where the answer is |
|---|---|
| "How do you know it works?" | Two corpora, deny-all baseline, sealed hold-out. README Results. |
| "Isn't 100% suspicious?" | Yes. Say so first. README "Honest limitations". |
| "What if the agent gets the key anyway?" | Bypassed entirely. THREAT_MODEL non-goals. State it before they do. |
| "Why not just prompt the model?" | An instruction in the context window has the same privilege as an injection in the context window. ADR-003. |
| "Why not a learned risk model?" | Three days, no labelled data, and a probabilistic verdict isn't explainable to the merchant it just stopped. ADR-004. |
| "Why not JWT?" | One issuer, one verifier, one algorithm. `alg:none` and HS/RS confusion are pure downside. ADR-005. |
| "Does this scale?" | Not as built. Single SQLite node, velocity state is the blocker. ARCHITECTURE "what I would change". |
| "What would you build next?" | Wrap Razorpay's real MCP server — 45 tools, no capability scoping today. |

**The general rule:** name the weakness before the panel does. Every one of
these has an honest answer already written down, and reaching for it beats
improvising a defence.
