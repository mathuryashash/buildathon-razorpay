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


# Every argument key that can name where money ends up. Adding a payout or
# transfer field to a backend without adding it here is how a destination
# stops being policed, so this list and `backends.py` are read together.
DESTINATION_FIELDS = (
    "customer_id", "contact", "email", "upi_id", "account_id",
    "fund_account_id", "vpa", "destination",
)


class ActionRequest(BaseModel):
    """What the agent is asking the proxy to do on its behalf."""

    op: str = Field(..., description="Operation name, e.g. 'create_payment_link'")
    args: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(
        default=None,
        description="Client-supplied key. If omitted the proxy derives one from the payload.",
    )

    def _parse_amount(self) -> int | None:
        """Whole non-negative paise, or None if the field cannot be read.

        None is the important return. An earlier version collapsed every
        unreadable amount to 0, which meant `{"amount": 250000.0}` -- a
        perfectly ordinary JSON float -- was evaluated as a zero-rupee action
        and sailed straight past the per-action cap. So did a negative
        integer. See docs/DECISIONS.md ADR-013.

        Floats are rejected rather than rounded even when they are integral.
        Paise are integers by definition; a float in a money field is a client
        bug or an attack, and accepting it here would be the first crack in
        the "no floats anywhere near money" rule this codebase is built on.
        """
        if "amount" not in self.args:
            return 0
        v = self.args["amount"]
        if isinstance(v, bool):
            return None          # bool is an int in Python. It is not an amount.
        if isinstance(v, int):
            return v if v >= 0 else None
        if isinstance(v, str):
            s = v.strip()
            # isascii() before isdigit(): str.isdigit() is True for characters
            # int() refuses ("²" is a digit to Python and a ValueError to
            # int()), and True for non-ASCII decimals that int() does accept
            # ("١٠٠" -> 100). The first crashed the proxy; the
            # second is un-normalised money input. Neither belongs in a
            # payments field.
            return int(s) if s.isascii() and s.isdigit() else None
        return None              # float, None, list, dict -> unreadable

    @property
    def amount_paise(self) -> int:
        """The amount, or 0 when absent OR unreadable.

        Callers must not treat 0 as "safe" without also checking
        `amount_is_valid`. The policy engine denies on invalid via AMT-001.
        """
        v = self._parse_amount()
        return v if v is not None else 0

    @property
    def amount_is_valid(self) -> bool:
        return self._parse_amount() is not None

    @property
    def raw_amount(self) -> str:
        """The amount exactly as the agent sent it, for the denial message.

        Truncated: this is attacker-controlled text on its way into the audit
        log. It is substituted as a value, never used as a format template.
        """
        return repr(self.args.get("amount"))[:40]

    @property
    def amount_missing(self) -> bool:
        """No `amount` key at all.

        Distinct from unreadable. A read legitimately has no amount; an
        irreversible money action with no amount is a request whose size no
        rule can bound, and Razorpay's refund API reads an omitted amount as
        the FULL payment. Policy rule AMT-002 denies that combination.
        """
        return "amount" not in self.args

    @property
    def counterparties(self) -> list[str]:
        """EVERY destination named on this request, in declaration order.

        Not just the first. The destination allowlist used to read one field
        and stop, so a request carrying an allowlisted `customer_id` next to
        an attacker's `upi_id` was checked against the decoy and passed --
        the agent got to choose which of its own fields was policed. Every
        destination present is now checked. See ADR-017.
        """
        return [str(self.args[k]) for k in DESTINATION_FIELDS if self.args.get(k)]

    @property
    def counterparty(self) -> str | None:
        """The primary destination, for display and per-counterparty counting.

        The allowlist deliberately does NOT use this -- see `counterparties`.
        """
        cps = self.counterparties
        return cps[0] if cps else None


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
