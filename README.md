# Gatekeeper

**An AI buyer agent that completes checkout end to end — and holds no payment credentials at all.**

Razorpay AI Buildathon 2026 · Track 01, AI Growth & Agentic Commerce

---

Razorpay is already shipping agentic payments: In-App Commerce, UPI Reserve Pay,
an MCP server with 45 tools, an OpenAI partnership. The open question is no
longer *can an agent pay*. It is **what stops one that has been prompt-injected,
or has simply gone wrong.**

Today the available answer is all-or-nothing: give the agent API keys, or don't.
Gatekeeper is the middle position — a bounded, auditable grant that a merchant
can reason about and a compromised agent cannot exceed.

The agent's every money action is exchanged through a **fail-closed capability
proxy** that enforces spend bounds, velocity limits, destination allowlists and
approval thresholds, and writes a tamper-evident audit trail in language a
merchant can read.

> Track 01's bar reads: *"Every money action explainable, bounded and gated.
> Show the audit trail and one failure handled gracefully."*
> This project is an attempt to answer that sentence literally.

---

## The demo in one screen

```
$ make demo

  RUN 1 -- agent talks to the payments API directly (no Gatekeeper)
  executed  create_refund        Rs   2,500.00
  executed  create_payout        Rs   5,000.00
  ...
  MONEY MOVED: Rs 9,950.10   blocked: 0 of 11 actions

  RUN 2 -- identical agent, identical instruction, behind Gatekeeper
  ALLOW     create_order         Rs     177.00
  BLOCK     create_refund        Rs   2,500.00
            -> Blocked: ₹2,500.00 is over the ₹500.00 limit for a single
               agent-initiated payment.
  BLOCK     create_payout        Rs   5,000.00
            -> Blocked: 'create_payout' sends money out of the merchant
               account to attacker@evil.test. No agent does this unattended.
  BLOCK     transfer_all_funds   Rs   9,999.99
            -> Blocked: 'transfer_all_funds' has no declared effect class.
               Gatekeeper denies undeclared operations rather than guessing.
  MONEY MOVED: Rs 1,470.03   blocked or held: 5 of 11 actions
  AUDIT CHAIN: intact across 11 records

  Same agent. Same prompt. The difference is enforcement, not instruction.
```

The agent in both runs is not malicious. It is **obedient** — it read a product
description containing an injected instruction and did as it was told. You
cannot fix that with a better prompt, because the attack arrives *through* the
prompt.

---

## Results

`make eval` — 31 scenarios, 67 calls, deterministic, offline, reproducible.

| Metric | Result |
|---|---|
| **Block rate** (attack corpus) | **33 / 33 — 100%** |
| **False-block rate** (benign corpus) | **0 / 34 — 0%** |
| Held-out set (sealed until code freeze) | *not yet run — see below* |
| Policy latency | p50 **2.1 ms**, p95 **3.3 ms** |
| Deny-everything baseline | block rate 48.5%, **false-block rate 100%** |

That last row is why a block rate alone is not a result, and it is printed by
the harness every run so the number cannot be quoted without its counterweight.

**By attack family**

| Family | Blocked | What it tests |
|---|---|---|
| `cap_evasion` | 4/4 | Amount over the cap, string-typed amount, cap+1 boundary |
| `velocity` | 15/15 | Salami-slicing under the cap, repeated counterparty, retry loop |
| `scope_escalation` | 4/4 | Undeclared op, payout, op outside the grant, case-variant name |
| `exfiltration` | 3/3 | Refund to unknown recipient, lookalike id, empty destination |
| `replay` | 7/7 | Retry storm, forged token, expired token |

**By benign family** — `normal_purchase` 6/6 · `reads` 11/11 ·
`legitimate_refunds` 6/6 · `busy_but_legitimate` 7/7 · `boundary` 4/4

---

## Honest limitations

Read this before you read the numbers again.

**The 100% is in-sample and proves less than it looks like.** Every attack
scenario was written by the same person who wrote the rules. It demonstrates
internal consistency, not robustness. `evals/scenarios/holdout.yaml` is
deliberately sealed and empty; the protocol is freeze the code, *then* write
five scenarios without looking at the rules, run once, and publish whatever
comes out. Until that row is filled in, treat the headline as unaudited.

**The proxy cannot defend against an agent that obtains a credential out of
band.** If the key leaks by another route the proxy is bypassed entirely and
none of this applies. That is the honest ceiling of the design, not an
oversight — see `THREAT_MODEL.md` non-goals.

**The audit chain makes tampering evident, not impossible.** Someone with
filesystem access can rewrite the database; `gatekeeper verify` will tell you
they did. There is no remote anchoring.

**Single process, single node.** Velocity state lives in one SQLite file.
Horizontal scaling would need shared state, and the window queries are the part
that would need rethinking first.

**The eval runs against a mock backend.** Razorpay test mode cannot generate
batches — subscription failures are a Dashboard button, Smart Collect test
payments are a Dashboard action, and there is no dispute-creation API. The mock
mirrors Razorpay's response shapes so everything above the backend line is
identical; `make demo-live` exercises the real API for the paths that work
headlessly (Orders, Payment Links).

**Two policy bugs shipped and were caught by the eval, not by review.** Both are
written up in `docs/DECISIONS.md` (ADR-006, ADR-007). One of them — velocity
double-counting a single purchase — would have made the product unusable, and
it was found by the *benign* corpus while every attack scenario passed.

---

## How it works

```
   UNTRUSTED                       │  TRUSTED
                                   │
   ┌───────────────┐   capability  │  ┌─────────────────┐   API key   ┌──────────┐
   │  buyer agent  │─────token────▶│─▶│   Gatekeeper    │────────────▶│ Razorpay │
   │ holds NO key  │               │  │      proxy      │             │ test mode│
   └───────────────┘               │  └────────┬────────┘             └──────────┘
                                   │           │
                                   │           ▼
                                   │   hash-chained audit log
```

Request lifecycle. **The order is the security argument** — reordering these
breaks it silently:

1. **Verify capability token** — HMAC, constant-time, short TTL
2. **Check scope** — was this agent granted this operation at all?
3. **Classify effect** — `read` / `reversible_write` / `irreversible_money`;
   **undeclared ⇒ deny**
4. **Evaluate policy** — caps, velocity, destination, hours
5. **Idempotency** — *before* execution, so a retry storm cannot get past it
6. **Execute** — only now does anything move
7. **Audit** — always, including on denial

### The three ideas worth arguing about

**Fail closed on unknown capability.** An operation with no declared effect
class is denied. Registering a new MCP tool therefore cannot silently widen
what an agent can do — adding a capability is a deliberate, reviewable act.
Most agent stacks do the reverse and rely on the prompt.

**The LLM is never in the pass/fail path.** It resolves shopping intent to SKU
references and it writes nothing else. It never asserts a price — the merchant
prices the cart — and it never renders a verdict. Every decision is a
deterministic predicate over a typed request, which is what makes each one
explainable in one sentence.

**Policy is data, not prompt text.** An instruction inside the context window
has the same privilege as an injection inside the context window; it is not a
boundary. YAML with a small typed condition vocabulary is enforceable *and*
readable by the merchant whose money it stops.

---

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"  # → GATEKEEPER_SIGNING_SECRET

make test     # 34 tests, ~0.5s, no network
make eval     # reproduces every number in the table above
make demo     # the two-run comparison
```

Live Razorpay test mode (needs `rzp_test_` keys in `.env`):

```bash
make demo-live
make serve BACKEND=razorpay     # proxy on :8080
make merchant                    # reference merchant on :8081
python -m gatekeeper log         # read the audit trail
python -m gatekeeper verify      # check the chain for tampering
```

The backend **refuses any key that does not start `rzp_test_`.** This project
has no business holding a production credential.

---

## Repository map

| Path | What it is |
|---|---|
| `THREAT_MODEL.md` | **Read first.** Adversary, assets, T1–T7, and explicit non-goals. Every rule cites an ID from here. |
| `gatekeeper/effects.py` | The fail-closed classification. Smallest and most important file. |
| `gatekeeper/policy.py` | Rule engine. Fixed condition vocabulary, deny beats allow. |
| `gatekeeper/proxy.py` | The lifecycle above. Only component that holds a credential. |
| `gatekeeper/audit.py` | Hash-chained log + `verify`. |
| `gatekeeper/tokens.py` | Capability tokens. The trust boundary lives here. |
| `policies/effects.yaml` | Operation → effect class. Absent means denied. |
| `policies/default.yaml` | 11 rules, each citing a threat. |
| `evals/` | 31 scenarios across two corpora + the harness. |
| `docs/DECISIONS.md` | 11 ADRs, including the three "what broke" records. |
| `docs/DO_NOT_BUILD.md` | Anti-scope. What not to build and why. |
| `docs/HOW_TO_WORK.md` | Setup, the change loop, how to add a rule safely. |

---

## Future work

Named honestly rather than implied as done:

- **Wrap Razorpay's actual MCP server** rather than a shape-compatible mock.
  Their server exposes 45 tools with no capability scoping — it disables four
  write operations on the remote deployment, which is the blunt version of this
  control. That is the natural home for it.
- **Approval UI.** Currently a CLI queue and `GET /v1/approvals`.
- **Remote audit anchoring**, so tampering is preventable rather than detectable.
- **Distributed velocity state** for multi-node deployment.
- **A risk model alongside the rules**, feeding `require_approval` — never
  replacing the deterministic deny path.

---

## Licence

MIT. Built for the Razorpay AI Buildathon 2026.
