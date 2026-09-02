"""The proxy. This is the only process that holds a Razorpay credential.

Request lifecycle -- the order of these steps IS the security argument, so do
not reorder them:

    1. verify capability token        (is this agent who it says it is?)
    2. check scope                    (was it granted this operation at all?)
    3. classify effect                (undeclared => deny, fail closed)
    4. evaluate policy                (caps, velocity, destination, hours)
    5. idempotency check              (have we already done exactly this?)
    6. execute against backend        (only now does anything move)
    7. append to hash-chained audit   (always, including on denial)

Denials are audited. A firewall that only logs what it allowed cannot tell you
what it stopped, which is the interesting half.
"""
from __future__ import annotations

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .audit import AuditLog
from .backends import Backend, BackendError, get_backend
from .effects import EffectRegistry
from .idempotency import IdempotencyStore, derive_key
from .models import ActionRequest, ActionResult, Decision, Verdict
from .policy import PolicyEngine
from .tokens import TokenError, verify as verify_token


class Gatekeeper:
    """Framework-free core so it is unit-testable without HTTP."""

    def __init__(
        self,
        *,
        backend: Backend,
        db_path: str = "gatekeeper.db",
        policy_path: str | None = None,
        effects_path: str | None = None,
        signing_secret: str | None = None,
        dry_run: bool = False,
    ):
        self.backend = backend
        self.audit = AuditLog(db_path)
        self.idem = IdempotencyStore(db_path)
        self.effects = EffectRegistry.load(effects_path)
        self.policy = PolicyEngine.load(policy_path)
        self.secret = signing_secret or os.environ.get("GATEKEEPER_SIGNING_SECRET", "")
        self.dry_run = dry_run
        self.pending_approvals: list[dict[str, Any]] = []

    def handle(self, token: str, request: ActionRequest, *, now: float | None = None) -> ActionResult:
        t0 = time.perf_counter()
        now = now if now is not None else time.time()

        # 1. identity
        try:
            cap = verify_token(token, secret=self.secret, now=now)
        except TokenError as e:
            return self._reject(
                "unknown", request, None,
                f"Blocked: {e}. The proxy could not establish which agent this is.",
                "AUTH-001",
            )

        # 2. scope -- granted at issue time, narrower than policy
        if request.op not in cap.scopes:
            return self._reject(
                cap.agent_id, request, None,
                f"Blocked: this agent was not granted '{request.op}'. "
                f"Its capability covers only: {', '.join(sorted(cap.scopes)) or '(nothing)'}.",
                "SCOPE-000",
            )

        # 3. effect classification (None => undeclared => policy denies)
        effect = self.effects.classify(request.op)

        # 4. policy
        decision = self.policy.evaluate(
            request, effect,
            agent_id=cap.agent_id, ctx=self.audit,
            hour_local=datetime.fromtimestamp(now).hour,
        )
        decision.latency_ms = (time.perf_counter() - t0) * 1000

        if decision.verdict != Verdict.ALLOW:
            seq = self.audit.append(
                agent_id=cap.agent_id, op=request.op,
                effect=effect.value if effect else None,
                verdict=decision.verdict.value,
                amount_paise=request.amount_paise, counterparty=request.counterparty,
                rule_ids=[h.rule_id for h in decision.hits],
                explanation=decision.explanation, executed=False,
                payload=request.args, ts=now,
            )
            if decision.verdict == Verdict.REQUIRE_APPROVAL:
                self.pending_approvals.append(
                    {"seq": seq, "op": request.op, "args": request.args,
                     "agent_id": cap.agent_id, "explanation": decision.explanation}
                )
            return ActionResult(decision=decision, executed=False, audit_seq=seq)

        # 5. idempotency -- before execution, so a retry storm cannot double-charge
        key = derive_key(cap.agent_id, request.op, request.args, request.idempotency_key)
        if (cached := self.idem.get(key)) is not None:
            seq = self.audit.append(
                agent_id=cap.agent_id, op=request.op,
                effect=effect.value if effect else None, verdict="allow",
                amount_paise=0,  # a replay moves no new money; do not double-count velocity
                counterparty=request.counterparty,
                rule_ids=[h.rule_id for h in decision.hits],
                explanation="Replayed: identical request already executed; returned the original result.",
                executed=False, payload={"idem_key": key}, ts=now,
            )
            return ActionResult(decision=decision, executed=False, replayed=True,
                                audit_seq=seq, result=cached)

        # 6. execute
        if self.dry_run:
            result: dict[str, Any] = {"dry_run": True, "would_call": request.op, "args": request.args}
            executed = False
        else:
            try:
                result = self.backend.call(request.op, request.args)
                executed = True
            except BackendError as e:
                seq = self.audit.append(
                    agent_id=cap.agent_id, op=request.op,
                    effect=effect.value if effect else None, verdict="allow",
                    amount_paise=0, counterparty=request.counterparty,
                    rule_ids=[h.rule_id for h in decision.hits],
                    explanation=f"Allowed by policy but the payment provider rejected it: {e}",
                    executed=False, payload=request.args, ts=now,
                )
                return ActionResult(decision=decision, executed=False, audit_seq=seq, error=str(e))
            self.idem.put(key, cap.agent_id, request.op, result)

        # 7. audit
        seq = self.audit.append(
            agent_id=cap.agent_id, op=request.op,
            effect=effect.value if effect else None, verdict="allow",
            amount_paise=request.amount_paise if executed else 0,
            counterparty=request.counterparty,
            rule_ids=[h.rule_id for h in decision.hits],
            explanation=decision.explanation, executed=executed,
            payload={"args": request.args, "result_id": result.get("id")}, ts=now,
        )
        return ActionResult(decision=decision, executed=executed, audit_seq=seq, result=result)

    def _reject(self, agent_id: str, request: ActionRequest, effect, explanation: str, rule_id: str) -> ActionResult:
        d = Decision(verdict=Verdict.DENY, effect=effect, explanation=explanation)
        seq = self.audit.append(
            agent_id=agent_id, op=request.op, effect=None, verdict="deny",
            amount_paise=request.amount_paise, counterparty=request.counterparty,
            rule_ids=[rule_id], explanation=explanation, executed=False, payload=request.args,
        )
        return ActionResult(decision=d, executed=False, audit_seq=seq)


# ---------------------------------------------------------------- HTTP ----

class ActionBody(BaseModel):
    op: str
    args: dict[str, Any] = {}
    idempotency_key: str | None = None


def create_app(gk: Gatekeeper) -> FastAPI:
    app = FastAPI(title="Gatekeeper", version="0.1.0",
                  description="Fail-closed capability proxy for money-moving agents")

    @app.post("/v1/act")
    def act(body: ActionBody, authorization: str = Header(default="")):
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing capability token (expected 'Authorization: Bearer <token>')")
        res = gk.handle(authorization[7:], ActionRequest(**body.model_dump()))
        return res.model_dump()

    @app.get("/v1/audit")
    def audit(limit: int = 100):
        rows = [dict(r) for r in gk.audit.rows()]
        return {"count": len(rows), "records": rows[-limit:]}

    @app.get("/v1/audit/verify")
    def verify_chain():
        c = gk.audit.verify()
        return {"ok": c.ok, "checked": c.checked, "broken_at": c.broken_at, "reason": c.reason}

    @app.get("/v1/approvals")
    def approvals():
        return {"pending": gk.pending_approvals}

    @app.get("/healthz")
    def health():
        return {"ok": True, "backend": gk.backend.name,
                "rules": len(gk.policy.rules), "operations": len(gk.effects)}

    return app
