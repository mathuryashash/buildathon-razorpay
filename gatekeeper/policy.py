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
    """What the engine can ask about history. Implemented by AuditLog."""

    def window_sum_paise(self, agent_id: str, seconds: int) -> int: ...
    def window_count(
        self, agent_id: str, seconds: int, *,
        counterparty: str | None = ..., effect: str | None = ...,
    ) -> int: ...


@dataclass
class EvalFacts:
    """Everything a condition may look at. Nothing else is reachable."""

    op: str
    effect: Effect | None
    amount_paise: int
    counterparty: str | None
    agent_id: str
    window_sum_paise: int
    window_count: int          # every executed action
    money_count: int           # executed irreversible_money actions only
    counterparty_count: int    # executed money actions to THIS counterparty
    hour_local: int


ConditionFn = Callable[[Any, EvalFacts], bool]

CONDITIONS: dict[str, ConditionFn] = {
    "amount_paise_gt": lambda v, f: f.amount_paise > int(v),
    "amount_paise_lte": lambda v, f: f.amount_paise <= int(v),
    "window_sum_paise_gt": lambda v, f: f.window_sum_paise + f.amount_paise > int(v),
    "window_count_gt": lambda v, f: f.window_count >= int(v),
    "money_count_gt": lambda v, f: f.money_count >= int(v),
    "counterparty_count_gt": lambda v, f: f.counterparty_count >= int(v),
    "op_in": lambda v, f: f.op in set(v),
    "effect_in": lambda v, f: f.effect is not None and f.effect.value in set(v),
    "effect_undeclared": lambda v, f: (f.effect is None) is bool(v),
    "counterparty_not_in": lambda v, f: f.counterparty is not None and f.counterparty not in set(v),
    "hour_outside": lambda v, f: not (int(v[0]) <= f.hour_local < int(v[1])),
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
            window_total=f"₹{facts.window_sum_paise / 100:,.2f}",
            window_count=facts.window_count,
            money_count=facts.money_count,
            counterparty_count=facts.counterparty_count,
        )


class PolicyEngine:
    def __init__(self, rules: list[Rule], *, window_seconds: int = 600):
        self.rules = rules
        self.window_seconds = window_seconds

    @classmethod
    def load(cls, path: Path | str | None = None) -> "PolicyEngine":
        p = Path(path) if path else DEFAULT_PATH
        raw = yaml.safe_load(p.read_text()) or {}
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
    ) -> Decision:
        cp = request.counterparty
        facts = EvalFacts(
            op=request.op,
            effect=effect,
            amount_paise=request.amount_paise,
            counterparty=cp,
            agent_id=agent_id,
            window_sum_paise=ctx.window_sum_paise(agent_id, self.window_seconds),
            window_count=ctx.window_count(agent_id, self.window_seconds),
            money_count=ctx.window_count(agent_id, self.window_seconds,
                                         effect=Effect.IRREVERSIBLE_MONEY.value),
            counterparty_count=(
                ctx.window_count(agent_id, self.window_seconds, counterparty=cp,
                                 effect=Effect.IRREVERSIBLE_MONEY.value) if cp else 0),
            hour_local=hour_local,
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
