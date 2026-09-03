"""The proxy. This is the only process that holds a Razorpay credential.

Request lifecycle -- the order of these steps IS the security argument, so do
not reorder them:

    1. verify capability token        (is this agent who it says it is?)
    2. check scope                    (was it granted this operation at all?)
    3. classify effect                (undeclared => deny, fail closed)
    4. evaluate policy                (caps, velocity, destination, hours)
    5. enforce the grant's own caps   (a grant may only narrow policy further)
    6. idempotency check              (have we already done exactly this?)
    7. execute against backend        (only now does anything move)
    8. append to hash-chained audit   (always, including on denial)

Denials are audited. A firewall that only logs what it allowed cannot tell you
what it stopped, which is the interesting half.
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .audit import AuditLog
from .backends import Backend, BackendError
from .effects import EffectRegistry
from .idempotency import IdempotencyStore, derive_key
from .models import ActionRequest, ActionResult, Decision, Effect, Verdict
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
        if not self.secret:
            # The guard used to live only in cli.py, so anything constructing
            # Gatekeeper directly -- which this docstring invites, and the eval
            # and demo both do -- got secret="" and verified every token
            # against an empty key. A token signed with "" then passed, which
            # means anyone could mint a capability with any scopes and any
            # ceilings they liked. ARCHITECTURE.md listed "no signing secret =>
            # refuses to start" as a fail-closed property of the proxy; it was
            # a property of one entry point. See docs/DECISIONS.md ADR-018.
            raise ValueError(
                "Gatekeeper requires a signing secret. Pass signing_secret=, or set "
                "GATEKEEPER_SIGNING_SECRET. There is no default: a default signing "
                "secret is the same as no signature."
            )
        self.dry_run = dry_run
        # ponytail: one process-wide lock, held for the whole request.
        #
        # `idem.get -> backend.call -> idem.put` is a read-modify-write across
        # two SQLite connections, and FastAPI runs sync endpoints on a thread
        # pool. Twelve concurrent requests executed the same idempotency key
        # seven times, moved Rs 2,800 through a Rs 2,000 window ceiling, and
        # threw "database is locked" out of the commit that runs AFTER the
        # money has moved -- losing the audit record for calls that succeeded.
        # A retry storm is concurrent by definition, so the README's claim that
        # idempotency stops one was false in exactly the case it describes.
        #
        # This serialises the proxy. That is the right trade here: the whole
        # design is already single-process (README "Honest limitations"), the
        # p95 is ~6 ms, and a correct slow proxy beats a fast one that double
        # -charges. Multi-node needs the shared velocity state that is already
        # named as future work, and the lock is the wrong tool there.
        # See docs/DECISIONS.md ADR-019.
        self._lock = threading.Lock()

    def close(self) -> None:
        """Release both SQLite handles.

        Long-lived in the server, but the eval builds one Gatekeeper per
        scenario and the tests build one per test. On Windows an open handle
        makes the temp directory undeletable, so every run leaked its
        databases -- ~350 files per `make eval`, silently, because the
        cleanup used ignore_errors.
        """
        self.audit.close()
        self.idem.close()

    def __enter__(self) -> "Gatekeeper":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def handle(self, token: str, request: ActionRequest, *, now: float | None = None) -> ActionResult:
        now = now if now is not None else time.time()
        with self._lock:
            try:
                return self._handle(token, request, now)
            except Exception as e:  # noqa: BLE001
                # Fail closed on an internal error, and audit it.
                #
                # Only step 7 used to be guarded. Everything before it could
                # raise straight out to FastAPI, which returned a bare 500 with
                # no audit record -- reachable unauthenticated, via a token
                # containing a non-ASCII byte (hmac.compare_digest raises
                # TypeError), and via {"amount": "²"} (str.isdigit() is
                # True where int() refuses). A proxy whose failure mode is an
                # unlogged 500 is not fail-closed. ADR-020.
                return self._reject(
                    "unknown", request, None,
                    f"Blocked: the proxy could not evaluate this request "
                    f"({type(e).__name__}). Gatekeeper denies what it cannot decide.",
                    "INTERNAL-001", ts=now,
                )

    def _handle(self, token: str, request: ActionRequest, now: float) -> ActionResult:
        t0 = time.perf_counter()

        # 1. identity
        try:
            cap = verify_token(token, secret=self.secret, now=now)
        except TokenError as e:
            return self._reject(
                "unknown", request, None,
                f"Blocked: {e}. The proxy could not establish which agent this is.",
                "AUTH-001", ts=now,
            )

        # 2. scope -- granted at issue time, narrower than policy
        if request.op not in cap.scopes:
            return self._reject(
                cap.agent_id, request, None,
                f"Blocked: this agent was not granted '{request.op}'. "
                f"Its capability covers only: {', '.join(sorted(cap.scopes)) or '(nothing)'}.",
                "SCOPE-000", ts=now,
            )

        # 3. effect classification (None => undeclared => policy denies)
        effect = self.effects.classify(request.op)

        # 4. policy
        decision = self.policy.evaluate(
            request, effect,
            agent_id=cap.agent_id, ctx=self.audit,
            hour_local=datetime.fromtimestamp(now).hour,
            now=now,
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
            # No in-memory approval queue. There was one, and nothing ever
            # read it: the CLI and GET /v1/approvals both go to the audit log,
            # which is the only copy that survives a restart.
            return ActionResult(decision=decision, executed=False, audit_seq=seq)

        # 5. the grant's OWN bounds, applied only where policy already said yes
        #
        # Every capability carries max_action_paise and max_window_paise. Until
        # this block existed they were decoration: a token issued to say "this
        # scraper may move Rs 100" got the merchant-wide Rs 500 rule instead,
        # so narrowing a grant did nothing whatsoever. ADR-014.
        #
        # It runs AFTER policy, not before, even though checking it first would
        # be cheaper. The default grant mirrors the default policy numbers, so
        # a grant check placed first shadows CAP-001 and VEL-001 completely and
        # every denial in the demo reads "your capability caps this" instead of
        # naming the rule and the threat it came from. Policy is the artifact a
        # merchant reviews; when both bind, policy explains it. The grant only
        # ever narrows further, so nothing is let through by deferring it.
        #
        # Restricted to irreversible_money, because that is what both ceilings
        # are denominated in. Applying max_action_paise to a reversible write
        # would deny a legitimate Rs 5,000 payment link, which moves no money
        # -- benign scenario B1-03 exists to catch exactly that.
        if effect is Effect.IRREVERSIBLE_MONEY:
            spent = self.audit.window_sum_paise(
                cap.agent_id, cap.window_seconds, now=now,
                effect=Effect.IRREVERSIBLE_MONEY.value)
            grant_reason = None
            if request.amount_paise > cap.max_action_paise:
                grant_reason = (
                    f"Blocked: this agent's own capability caps a single payment at "
                    f"₹{cap.max_action_paise / 100:,.2f}; this one is "
                    f"₹{request.amount_paise / 100:,.2f}. A grant may only ever be "
                    f"narrower than merchant policy, and the narrower bound wins."
                )
            elif spent + request.amount_paise > cap.max_window_paise:
                grant_reason = (
                    f"Blocked: this agent's own capability allows "
                    f"₹{cap.max_window_paise / 100:,.2f} per "
                    f"{cap.window_seconds // 60} minutes and ₹{spent / 100:,.2f} is "
                    f"already spent. Issue a wider capability if this is intended."
                )
            if grant_reason is not None:
                return self._reject(cap.agent_id, request, effect, grant_reason,
                                    "GRANT-001", ts=now)

        # 6. idempotency -- before execution, so a retry storm cannot double-charge
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

        # 7. execute
        if self.dry_run:
            result: dict[str, Any] = {"dry_run": True, "would_call": request.op, "args": request.args}
            executed = False
        else:
            try:
                result = self.backend.call(request.op, request.args)
                executed = True
            except Exception as e:  # noqa: BLE001 -- see below
                # Deliberately broad. Backends raise BackendError by contract,
                # but a malformed payload can make one raise something else
                # entirely (a bare ValueError out of int(), for one). If that
                # escapes, the request never reaches step 8 and a money call
                # the proxy permitted leaves no audit record at all -- the one
                # outcome the audit trail exists to make impossible.
                if not isinstance(e, BackendError):
                    e = BackendError(f"{type(e).__name__}: {e}")
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

        # 8. audit
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

    def _reject(self, agent_id: str, request: ActionRequest, effect, explanation: str,
                rule_id: str, *, ts: float | None = None) -> ActionResult:
        # `ts` and `effect` are both threaded through deliberately. This used
        # to stamp the wall clock and write effect=None regardless of what it
        # was handed, so denials landed out of chronological order beside
        # records written at the evaluated time, and every auth, scope and
        # grant denial was invisible to an effect-filtered forensic query.
        d = Decision(verdict=Verdict.DENY, effect=effect, explanation=explanation)
        seq = self.audit.append(
            agent_id=agent_id, op=request.op,
            effect=effect.value if effect else None, verdict="deny",
            amount_paise=request.amount_paise, counterparty=request.counterparty,
            rule_ids=[rule_id], explanation=explanation, executed=False,
            payload=request.args, ts=ts,
        )
        return ActionResult(decision=d, executed=False, audit_seq=seq)


# ---------------------------------------------------------------- HTTP ----

class ActionBody(BaseModel):
    op: str
    args: dict[str, Any] = {}
    idempotency_key: str | None = None


READ_AUDIT_SCOPE = "read_audit"


def create_app(gk: Gatekeeper) -> FastAPI:
    app = FastAPI(title="Gatekeeper", version="0.1.0",
                  description="Fail-closed capability proxy for money-moving agents")

    def _bearer(authorization: str) -> str:
        if not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing capability token (expected 'Authorization: Bearer <token>')")
        return authorization[7:]

    def _require_audit_reader(authorization: str) -> None:
        """The audit trail is not public.

        These three endpoints were open to anything that could reach the port,
        and they return every amount, customer id and raw payload the proxy
        has ever seen. Reading the log is an operator action, so it needs a
        capability that says so -- a buyer agent's token does not carry
        `read_audit`, which is the point.

            python -m gatekeeper issue-token --agent-id ops --scopes read_audit
        """
        try:
            cap = verify_token(_bearer(authorization), secret=gk.secret)
        except TokenError as e:
            raise HTTPException(401, f"invalid capability token: {e}") from e
        if READ_AUDIT_SCOPE not in cap.scopes:
            raise HTTPException(
                403, f"this capability does not carry the '{READ_AUDIT_SCOPE}' scope")

    @app.post("/v1/act")
    def act(body: ActionBody, authorization: str = Header(default="")):
        res = gk.handle(_bearer(authorization), ActionRequest(**body.model_dump()))
        return res.model_dump()

    @app.get("/v1/audit")
    def audit(limit: int = 100, authorization: str = Header(default="")):
        _require_audit_reader(authorization)
        # max(1, ...): limit=0 made rows[-0:] return the entire table, which is
        # the opposite of what the caller asked for.
        limit = max(1, min(int(limit), 1000))
        rows = [dict(r) for r in gk.audit.rows()]
        return {"count": len(rows), "records": rows[-limit:]}

    @app.get("/v1/audit/verify")
    def verify_chain(authorization: str = Header(default="")):
        _require_audit_reader(authorization)
        c = gk.audit.verify()
        return {"ok": c.ok, "checked": c.checked, "broken_at": c.broken_at, "reason": c.reason}

    @app.get("/v1/approvals")
    def approvals(authorization: str = Header(default="")):
        _require_audit_reader(authorization)
        # From the log, not from memory: the in-process list dies with the
        # process, and a queue that forgets on restart is not a queue.
        return {"pending": gk.audit.pending_approvals()}

    @app.get("/healthz")
    def health():
        return {"ok": True, "backend": gk.backend.name,
                "rules": len(gk.policy.rules), "operations": len(gk.effects)}

    return app
