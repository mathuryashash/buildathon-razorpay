# Architecture

The document to read before the panel round. `docs/DECISIONS.md` has the
records for individual choices; this is how the pieces fit.

---

## Components

| Component | File | Responsibility | Holds a credential? |
|---|---|---|---|
| Buyer agent | `agent/buyer.py` | Resolve intent → SKUs, drive checkout | **No — never** |
| Reference merchant | `merchant/app.py` | Catalogue, the only source of price truth | No |
| Capability tokens | `gatekeeper/tokens.py` | Mint and verify scoped grants | Signing secret only |
| Effect registry | `gatekeeper/effects.py` | Static op → danger classification | No |
| Policy engine | `gatekeeper/policy.py` | Rules → verdict + explanation | No |
| Idempotency | `gatekeeper/idempotency.py` | Content-addressed replay protection | No |
| Audit log | `gatekeeper/audit.py` | Hash-chained record + verification | No |
| Proxy | `gatekeeper/proxy.py` | Orchestrates the lifecycle | No |
| Backends | `gatekeeper/backends.py` | Mock or real Razorpay | **Yes — only here** |

One row holds a payment credential. That is the design.

## Request lifecycle

```
agent                proxy                                    backend
  │                    │
  ├── POST /v1/act ───▶│
  │   Bearer <cap>     │
  │                    ├─ 1. verify token ────── bad ─▶ DENY + audit
  │                    ├─ 2. check scope ─────── no ──▶ DENY + audit
  │                    ├─ 3. classify effect ─ undecl ─▶ (policy denies)
  │                    ├─ 4. evaluate policy ── deny ─▶ DENY + audit
  │                    │                    ── approve ▶ HOLD + audit + queue
  │                    ├─ 5. grant ceilings ── over ─▶ DENY + audit
  │                    ├─ 6. idempotency ───── hit ──▶ replay cached + audit
  │                    ├─ 7. execute ──────────────────────▶ │
  │                    │◀───────────────────────────────────┤
  │                    ├─ 8. append audit (hash-chained)
  │◀── ActionResult ───┤
```

The whole of this runs under one process-wide lock, and anything that raises
anywhere inside it is caught, denied and audited. Neither was true before
ADR-019 and ADR-020: twelve concurrent requests executed the same idempotency
key seven times, and an unhandled exception in steps 1-6 returned a bare 500
with no audit record at all.

**Why this order.** Token before scope: you cannot check a grant you have not
authenticated. Scope before policy: a cheap exact-match rejection before the
more expensive window queries, and it keeps "you were never given this" a
distinct message from "you were given this but not right now". Effect before
policy: the policy's fail-closed rule needs the classification, including its
absence. **Idempotency before execution:** this is the one that matters — after
execution, a retry storm has already charged the customer twenty times and the
cache only prevents the twenty-first. **Grant ceilings after policy**, though
they are cheaper: the default grant mirrors the default policy numbers, so
checking it first shadows `CAP-001` and `VEL-001` entirely and every denial
reads "your capability caps this" instead of naming the rule and the threat
behind it (ADR-014). A grant can only ever narrow further, so deferring it
lets nothing through. Audit last and always, including denials.

**Ordering alone is not enough.** For most of this project's life the order
above was correct and the retry-storm guarantee was still false, because the
read-modify-write it describes was not atomic. See ADR-019.

## Data contracts

```python
ActionRequest  { op, args, idempotency_key? }
                 # amount is int PAISE. Never a float. Ever.

Decision       { verdict: allow|deny|require_approval,
                 effect: read|reversible_write|irreversible_money|None,
                 hits: [RuleHit], explanation: str, latency_ms }

RuleHit        { rule_id, threat, verdict, explanation }
                 # threat cites an ID in THREAT_MODEL.md

Capability     { agent_id, scopes[], max_action_paise, max_window_paise,
                 window_seconds, exp, nonce }

AuditRecord    { seq, ts, agent_id, op, effect, verdict, amount_paise,
                 counterparty, rule_ids, explanation, executed, payload,
                 prev_hash, hash }
                 # hash = sha256(canonical(fields) + prev_hash)
```

## Verdict precedence

`deny` (3) > `require_approval` (2) > `allow` (1). All matching rules are
collected; the highest precedence wins, and its explanation becomes the message
the merchant sees.

**Never reorder this so allow can override deny.** The baseline grants
(`ALLOW-READ`, `ALLOW-REVERSIBLE`, `ALLOW-MONEY-SMALL`) exist because the engine
fails closed — with no matching rule at all, everything is denied, so something
has to say yes. Those grants overlapping with a deny rule is normal and
expected; deny simply wins.

## Fail-closed in three places

1. **Unknown operation** — no effect class ⇒ `SCOPE-001` denies
2. **No matching rule** — `PolicyEngine.evaluate` returns deny when `hits` is empty
3. **No signing secret** — the proxy refuses to start rather than use a default

A default signing secret is the same as no signature, which is why (3) is a
hard exit rather than a warning.

## Threat → rule → test traceability

Every threat has a rule; every rule has an attack scenario **and** a benign
scenario; interesting interactions also have a unit test.

| Threat | Rules | Attack | Benign |
|---|---|---|---|
| T1 single large action | CAP-001, CAP-002 | F1-01…04 | B1-03, B1-04, B5-01 |
| T2 aggregate drain | VEL-001…004 | F2-01…03 | B3-01, B3-02, B4-01 |
| T3 scope escalation | SCOPE-001, SCOPE-002, proxy step 2 | F3-01…04 | B2-01, B2-02 |
| T4 exfiltration | DEST-001 | F4-01…03 | B3-01 |
| T5 out of hours | TIME-001 | — | B5-03, B5-04 |
| T6 duplicate execution | idempotency layer | F5-01 | B4-02 |
| T7 log tampering | hash chain | — | `tests/test_audit_chain.py` |

The two gaps are real and worth naming rather than papering over: T5 and T7
have no attack *scenario* because the harness drives the proxy through its
normal API, and neither threat is expressible as a sequence of API calls — one
needs a clock shift, the other needs direct database access. Both are covered
by unit tests instead.

## What I would change with more time

- **Velocity state in Redis**, not SQLite, so the proxy scales horizontally
- **Anchor the audit chain remotely** — tamper-*proof* rather than tamper-evident
- **Wrap Razorpay's real MCP server**; the shape-compatible mock proves the
  architecture but not the integration
- **Per-counterparty caps as data**, not a hardcoded allowlist in DEST-001 —
  the current allowlist does not survive contact with a real customer base
- **A second signer for high-value approvals**, so the proxy operator is not
  the sole root of trust
