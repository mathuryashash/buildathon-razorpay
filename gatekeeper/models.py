"""Typed contracts shared across the proxy.

Every amount in this codebase is an integer number of PAISE. There are no
floats anywhere near money. If you find yourself writing `float` in a money
path, stop -- see docs/DO_NOT_BUILD.md.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Effect(str, Enum):
    """How dangerous is this operation?

    The classification is *static* and lives in policies/effects.yaml. An
    operation with no declared effect is denied -- see effects.py.
    """

    READ = "read"
    REVERSIBLE_WRITE = "reversible_write"
    IRREVERSIBLE_MONEY = "irreversible_money"


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ActionRequest(BaseModel):
    """What the agent is asking the proxy to do on its behalf."""

    op: str = Field(..., description="Operation name, e.g. 'create_payment_link'")
    args: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(
        default=None,
        description="Client-supplied key. If omitted the proxy derives one from the payload.",
    )

    @property
    def amount_paise(self) -> int:
        v = self.args.get("amount")
        return int(v) if isinstance(v, (int, str)) and str(v).isdigit() else 0

    @property
    def counterparty(self) -> str | None:
        for k in ("customer_id", "contact", "email", "upi_id", "account_id"):
            if self.args.get(k):
                return str(self.args[k])
        return None


class RuleHit(BaseModel):
    rule_id: str
    threat: str
    verdict: Verdict
    explanation: str


class Decision(BaseModel):
    verdict: Verdict
    effect: Effect | None = None
    hits: list[RuleHit] = Field(default_factory=list)
    explanation: str = ""
    latency_ms: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW


class ActionResult(BaseModel):
    decision: Decision
    executed: bool = False
    replayed: bool = False
    audit_seq: int | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


class Capability(BaseModel):
    """A scoped, short-lived grant handed to an agent.

    The agent NEVER receives Razorpay credentials. It receives one of these.
    """

    agent_id: str
    scopes: list[str] = Field(..., description="Operation names this agent may request")
    max_action_paise: int
    max_window_paise: int
    window_seconds: int = 600
    exp: int = Field(..., description="Unix expiry timestamp")
    nonce: str


Channel = Literal["mock", "razorpay_test"]
