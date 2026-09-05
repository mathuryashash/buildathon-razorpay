"""Declarative policy engine.

Design decision you will be asked about in the panel:

    Rules are DATA (YAML), not prompt text, and not Python.

Prompt text is not a control -- a model that is told "never spend more than
5000" can be talked out of it. Python would be a control but not a reviewable
one: a merchant cannot audit a function body. YAML with a fixed, small set of
typed conditions is enforceable AND readable, and it means adding a rule does
not mean shipping code.

The condition vocabulary is deliberately tiny. Every condition below maps to
something a merchant can state in one sentence. If you need a condition that
cannot be stated in one sentence, that is a signal the rule is wrong, not that
the vocabulary is too small. Do NOT add an expression evaluator here -- see
docs/DO_NOT_BUILD.md, item 3.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

import yaml

from .models import ActionRequest, Decision, Effect, RuleHit, Verdict

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "policies" / "default.yaml"

# Precedence: a single deny beats any number of allows. require_approval sits
# between them. This ordering is the whole safety argument -- never reorder it
# so that allow can override deny.
PRECEDENCE = {Verdict.DENY: 3, Verdict.REQUIRE_APPROVAL: 2, Verdict.ALLOW: 1}


class Context(Protocol):
    """What the engine can ask about history. Implemented by AuditLog.

    `now` is not optional here on purpose. Both implementations default it to
    the wall clock, and an engine that silently took that default while the
    proxy evaluated against an injected timestamp compared window edges from
    one clock against record timestamps from another -- velocity simply stopped
    applying. See docs/DECISIONS.md ADR-012.
    """

    def window_sum_paise(
        self, agent_id: str, seconds: int, *,
        effect: str | None = ..., now: float,
    ) -> int: ...
    def window_count(
        self, agent_id: str, seconds: int, *,
        counterparty: str | None = ..., effect: str | None = ..., now: float,
    ) -> int: ...


@dataclass
class EvalFacts:
    """Everything a condition may look at. Nothing else is reachable."""

    op: str
    effect: Effect | None
    amount_paise: int
    counterparty: str | None
    agent_id: str
    money_moved_paise: int     # value of executed IRREVERSIBLE_MONEY only
    window_count: int          # every executed action
    money_count: int           # executed irreversible_money actions only
    counterparty_count: int    # executed money actions to THIS counterparty
    hour_local: int
    amount_valid: bool = True  # False when the agent sent an unreadable amount
    amount_missing: bool = False   # no `amount` key on the request at all
    raw_amount: str = ""       # as sent, for the denial message only
    counterparties: tuple[str, ...] = ()   # EVERY destination named, not just the first
    # H-02 (sealed hold-out): true only when THIS process has itself recorded
    # who a payment_id really belongs to (via a capture it handled) and the
    # current request names someone else. See ADR-022.
    owner_mismatch: bool = False
    true_owner: str = ""       # who the payment was actually captured for
    # H-05 (sealed hold-out): true only for a payment link re-issued, within
    # the velocity window, for the same customer and the same amount as one
    # just cancelled, but pointed at a different destination. See ADR-024.
    relink_destination_changed: bool = False


ConditionFn = Callable[[Any, EvalFacts], bool]

# Every name here says exactly what the predicate does, including whether the
# comparison is strict. Four of these used to end `_gt` while comparing with
# `>=`, in the one file whose entire selling point is that a merchant can read
# it and know what it means.
CONDITIONS: dict[str, ConditionFn] = {
    "amount_paise_gt": lambda v, f: f.amount_paise > int(v),
    "amount_paise_lte": lambda v, f: f.amount_paise <= int(v),
    # Would THIS action push money moved in the window past the ceiling?
    # Counts irreversible_money only -- see EvalFacts.money_moved_paise.
    "money_moved_paise_gt": lambda v, f: f.money_moved_paise + f.amount_paise > int(v),
    "window_count_gte": lambda v, f: f.window_count >= int(v),
    "money_count_gte": lambda v, f: f.money_count >= int(v),
    "counterparty_count_gte": lambda v, f: f.counterparty_count >= int(v),
    "op_in": lambda v, f: f.op in set(v),
    "effect_in": lambda v, f: f.effect is not None and f.effect.value in set(v),
    "effect_undeclared": lambda v, f: (f.effect is None) is bool(v),
    # True when ANY destination on the request is outside the allowlist, and
    # also when the request names no destination at all. Both used to pass:
    # an absent field could not match, and with several destination fields set
    # only the first was ever examined, so an allowlisted decoy hid the real
    # one. See ADR-017.
    "counterparty_not_in": lambda v, f: (
        not f.counterparties or any(c not in set(v) for c in f.counterparties)
    ),
    "hour_outside": lambda v, f: not (int(v[0]) <= f.hour_local < int(v[1])),
    "amount_invalid": lambda v, f: (not f.amount_valid) is bool(v),
    "amount_missing": lambda v, f: f.amount_missing is bool(v),
    "owner_mismatch": lambda v, f: f.owner_mismatch is bool(v),
    "relink_destination_changed": lambda v, f: f.relink_destination_changed is bool(v),
}


@dataclass
class Rule:
    id: str
    threat: str
    description: str
    when: dict[str, Any]
    action: Verdict
    explain: str

    def matches(self, facts: EvalFacts) -> bool:
        # A rule with no conditions matches everything. All conditions must
        # hold (AND). There is no OR -- write two rules instead. This keeps
        # every rule explainable as a single sentence.
        for key, value in self.when.items():
            fn = CONDITIONS.get(key)
            if fn is None:
                raise ValueError(
                    f"rule {self.id}: unknown condition {key!r}. "
                    f"Known: {sorted(CONDITIONS)}"
                )
            if not fn(value, facts):
                return False
        return True

    def render(self, facts: EvalFacts) -> str:
        return self.explain.format(
            amount=f"₹{facts.amount_paise / 100:,.2f}",
            amount_paise=facts.amount_paise,
            op=facts.op,
            effect=facts.effect.value if facts.effect else "undeclared",
            counterparty=facts.counterparty or "unknown recipient",
            window_total=f"₹{facts.money_moved_paise / 100:,.2f}",
            window_count=facts.window_count,
            money_count=facts.money_count,
            counterparty_count=facts.counterparty_count,
            raw_amount=facts.raw_amount,
            counterparties=", ".join(facts.counterparties) or "no destination at all",
            true_owner=facts.true_owner or "a different customer",
        )


class PolicyEngine:
    def __init__(self, rules: list[Rule], *, window_seconds: int = 600):
        self.rules = rules
        self.window_seconds = window_seconds

    @classmethod
    def load(cls, path: Path | str | None = None) -> "PolicyEngine":
        p = Path(path) if path else DEFAULT_PATH
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        rules = []
        seen: set[str] = set()
        for r in raw.get("rules") or []:
            rid = r["id"]
            if rid in seen:
                raise ValueError(f"duplicate rule id {rid!r} in {p}")
            seen.add(rid)
            rules.append(
                Rule(
                    id=rid,
                    threat=r.get("threat", "UNSPECIFIED"),
                    description=r.get("description", ""),
                    when=r.get("when") or {},
                    action=Verdict(r["action"]),
                    explain=r.get("explain", "Blocked by rule {op}."),
                )
            )
        return cls(rules, window_seconds=int(raw.get("window_seconds", 600)))

    def evaluate(
        self,
        request: ActionRequest,
        effect: Effect | None,
        *,
        agent_id: str,
        ctx: Context,
        hour_local: int,
        now: float,
        owner_mismatch: bool = False,
        true_owner: str = "",
        relink_destination_changed: bool = False,
    ) -> Decision:
        cp = request.counterparty
        w = self.window_seconds
        facts = EvalFacts(
            op=request.op,
            effect=effect,
            amount_paise=request.amount_paise,
            counterparty=cp,
            agent_id=agent_id,
            money_moved_paise=ctx.window_sum_paise(
                agent_id, w, now=now, effect=Effect.IRREVERSIBLE_MONEY.value),
            window_count=ctx.window_count(agent_id, w, now=now),
            money_count=ctx.window_count(agent_id, w, now=now,
                                         effect=Effect.IRREVERSIBLE_MONEY.value),
            counterparty_count=(
                ctx.window_count(agent_id, w, now=now, counterparty=cp,
                                 effect=Effect.IRREVERSIBLE_MONEY.value) if cp else 0),
            hour_local=hour_local,
            amount_valid=request.amount_is_valid,
            amount_missing=request.amount_missing,
            raw_amount=request.raw_amount,
            counterparties=tuple(request.counterparties),
            owner_mismatch=owner_mismatch,
            true_owner=true_owner,
            relink_destination_changed=relink_destination_changed,
        )

        hits: list[RuleHit] = []
        for rule in self.rules:
            if rule.matches(facts):
                hits.append(
                    RuleHit(
                        rule_id=rule.id,
                        threat=rule.threat,
                        verdict=rule.action,
                        explanation=rule.render(facts),
                    )
                )

        if not hits:
            # No rule matched at all. Fail closed: a request nobody wrote a
            # rule about is a request nobody reviewed.
            return Decision(
                verdict=Verdict.DENY,
                effect=effect,
                explanation=(
                    f"Blocked: no policy rule covers '{request.op}'. "
                    "Gatekeeper denies anything it has not been told to allow."
                ),
            )

        worst = max(hits, key=lambda h: PRECEDENCE[h.verdict])
        return Decision(
            verdict=worst.verdict,
            effect=effect,
            hits=hits,
            explanation=worst.explanation,
        )
