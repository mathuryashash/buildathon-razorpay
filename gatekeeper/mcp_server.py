"""Gatekeeper as an MCP server.

    python -m gatekeeper.mcp_server                  # stdio (Claude Desktop / Claude Code)
    python -m gatekeeper.mcp_server --http --port 8765   # streamable-http

THE TRUST BOUNDARY, RESTATED FOR MCP
------------------------------------
The MCP *client* (the LLM host) sees typed tools and nothing else. It never
sees a Razorpay key, the signing secret, or the capability token: none of them
appears in any tool schema, argument or result. This process holds a scoped
capability token for the session and pushes every tool call through
`Gatekeeper.handle()` -- the exact same verify -> scope -> effect -> policy ->
grant -> idempotency -> execute -> audit path the HTTP proxy uses. There is no
second, MCP-only decision path to drift out of sync with the first.

Results are structured so an agent can act on them without parsing prose:

    executed / replayed   -> isError false, `result` holds the provider object
    pending_approval      -> isError false; a human must approve (rule id given)
    denied                -> isError true, `rule_id` names the rule that fired
    provider_error        -> isError true, allowed by policy, provider refused

Configuration is environment only (so an MCP client config can set it):

    GATEKEEPER_SIGNING_SECRET  required; the proxy refuses to start without it
    GATEKEEPER_MCP_BACKEND     mock (default) | razorpay | auto
                               auto = razorpay iff an rzp_test_ key is present
    GATEKEEPER_MCP_DB          audit/idempotency db (default gatekeeper-mcp.db)
    GATEKEEPER_MCP_AGENT_ID    agent id stamped on the token (default mcp-agent)
    GATEKEEPER_MCP_SCOPES      comma list; default = the ops the tools expose
    GATEKEEPER_MCP_TOKEN       use this pre-issued token instead of minting one
    GATEKEEPER_MCP_TTL         minted token lifetime, seconds (default 3600)
    GATEKEEPER_MCP_FIXED_NOW   tests/eval only: pin the clock (unix seconds)

Credentials for the razorpay backend are read by gatekeeper/backends.py and
nowhere else (tests/test_no_secrets_in_agent.py). A `.env` next to the repo
root is loaded with setdefault semantics, so the MCP client config never needs
to contain a key.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolResult, TextContent, ToolAnnotations
from pydantic import Field, Strict

from .backends import get_backend
from .models import ActionRequest, ActionResult, Verdict
from .proxy import Gatekeeper
from .tokens import TokenError, issue, verify

ROOT = Path(__file__).resolve().parent.parent

# The operations the MCP tools can reach. A minted token gets exactly these
# and no more: create_payout, create_transfer and capture_payment are NOT
# exposed over MCP and are not in the default grant either.
TOOL_OPS = ["create_refund", "create_payment_link", "cancel_payment_link", "fetch_payment"]

# An amount is passed through to the proxy EXACTLY as the client sent it.
# Typing it as a plain `int` would let pydantic's lax mode coerce first --
# int("２５０") is 250 and 250000.0 becomes 250000 -- so a unicode or float
# amount would reach the policy engine already "fixed" and never be audited
# as the trick it was. Strict types keep the raw value; models.ActionRequest
# then denies anything that is not whole ASCII paise (AMT-001).
Amount = Annotated[int, Strict()] | Annotated[str, Strict()] | Annotated[float, Strict()]

# Bounded free text. An agent stuffing a 1 MB "note" into the audit log is a
# denial-of-service on the forensic record, not a refund.
Short = Annotated[str, Field(max_length=256)]
Ident = Annotated[str, Field(max_length=128)]


def _load_dotenv() -> None:
    p = ROOT / ".env"
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


class Clock:
    """Injectable time. Production uses the wall clock."""

    def __init__(self, fixed: float | None = None):
        self.fixed = fixed

    def __call__(self) -> float:
        return self.fixed if self.fixed is not None else time.time()


def _rule_id(gk: Gatekeeper, res: ActionResult) -> tuple[str, list[str]]:
    d = res.decision
    if d.hits:
        decisive = [h.rule_id for h in d.hits if h.verdict == d.verdict]
        return (decisive[0] if decisive else d.hits[0].rule_id), [h.rule_id for h in d.hits]
    # _reject() paths (AUTH/SCOPE/GRANT/INTERNAL/IDEM) record the rule id only
    # in the audit row, and the fail-closed "no rule matched" path records none.
    ids = gk.audit.rule_ids(res.audit_seq) if res.audit_seq is not None else []
    return (ids[0] if ids else "DEFAULT-DENY"), ids or ["DEFAULT-DENY"]


def to_tool_result(gk: Gatekeeper, op: str, res: ActionResult) -> CallToolResult:
    d = res.decision
    out: dict[str, Any] = {
        "op": op,
        "verdict": d.verdict.value,
        "explanation": " ".join(d.explanation.split()),
        "audit_seq": res.audit_seq,
    }
    if d.verdict == Verdict.ALLOW:
        if res.error:
            out.update(status="provider_error", error=res.error)
        else:
            out.update(status="replayed" if res.replayed else "executed", result=res.result)
            if res.result and res.result.get("dry_run"):
                out["status"] = "dry_run"
    else:
        rid, rids = _rule_id(gk, res)
        out.update(rule_id=rid, rule_ids=rids,
                   status="pending_approval" if d.verdict == Verdict.REQUIRE_APPROVAL else "denied")
        if out["status"] == "pending_approval":
            out["next_step"] = ("A human must approve this in the Gatekeeper console "
                                "(python -m gatekeeper approvals). Do not retry it.")
    is_error = out["status"] in ("denied", "provider_error")
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(out, default=str))],
                          structured_content=out, is_error=is_error)


def build_server(gk: Gatekeeper, token: str | Callable[[], str],
                 clock: Callable[[], float] | None = None,
                 *, name: str = "gatekeeper") -> MCPServer:
    """`token` may be a callable so the red-team runner can swap in forged /
    expired / tampered capabilities per call without rebuilding the server."""
    clock = clock or Clock()
    _tok: Callable[[], str] = token if callable(token) else (lambda: token)
    mcp = MCPServer(
        name=name,
        instructions=(
            "Payment tools for an Indian D2C merchant, enforced by the Gatekeeper policy "
            "proxy. Amounts are integer PAISE (Rs 1 = 100 paise). A 'denied' result names "
            "the policy rule that blocked it; do not try to work around it. A "
            "'pending_approval' result means a human will review it; do not retry."),
    )

    def act(op: str, args: dict[str, Any], idem: str | None) -> CallToolResult:
        # Drop absent optionals so the proxy sees exactly what the agent named.
        clean = {k: v for k, v in args.items() if v is not None}
        res = gk.handle(_tok(), ActionRequest(op=op, args=clean, idempotency_key=idem), now=clock())
        return to_tool_result(gk, op, res)

    money = ToolAnnotations(destructive_hint=True, idempotent_hint=False, open_world_hint=True)

    @mcp.tool(annotations=money)
    def create_refund(payment_id: Ident, amount_paise: Amount, customer_id: Ident,
                      reason: Short | None = None, idempotency_key: Ident | None = None) -> CallToolResult:
        """Refund part or all of a captured payment back to the customer who paid.

        amount_paise: integer paise (Rs 120.00 = 12000). customer_id must be the
        merchant's customer id (e.g. cust_demo_001). Policy: <= Rs 500 executes,
        Rs 500-1,000 is held for a human, > Rs 1,000 is denied; Rs 2,000 per
        10 minutes rolling."""
        return act("create_refund", {"payment_id": payment_id, "amount": amount_paise,
                                     "customer_id": customer_id,
                                     "notes": {"reason": reason} if reason else None},
                   idempotency_key)

    @mcp.tool(annotations=ToolAnnotations(destructive_hint=False, open_world_hint=True))
    def create_payment_link(amount_paise: Amount, customer_id: Ident,
                            description: Short | None = None, upi_id: Ident | None = None,
                            customer_email: Ident | None = None, customer_contact: Ident | None = None,
                            idempotency_key: Ident | None = None) -> CallToolResult:
        """Create a Razorpay payment link asking a customer to pay the merchant.

        amount_paise: integer paise. Links above Rs 5,000 need human approval."""
        customer = {k: v for k, v in (("email", customer_email), ("contact", customer_contact)) if v}
        return act("create_payment_link", {"amount": amount_paise, "customer_id": customer_id,
                                           "description": description, "upi_id": upi_id,
                                           "customer": customer or None}, idempotency_key)

    @mcp.tool(annotations=ToolAnnotations(destructive_hint=True, idempotent_hint=True))
    def cancel_payment_link(payment_link_id: Ident) -> CallToolResult:
        """Cancel a payment link that has not been paid yet."""
        return act("cancel_payment_link", {"payment_link_id": payment_link_id}, None)

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    def fetch_payment(payment_id: Ident) -> CallToolResult:
        """Look up a payment by id (read-only)."""
        return act("fetch_payment", {"payment_id": payment_id}, None)

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    def check_budget() -> dict[str, Any]:
        """How much this agent may still move before policy stops it.

        Reports the merchant policy ceilings and this session's capability
        ceilings; the smaller of the two is what actually binds."""
        now = clock()
        try:
            cap = verify(_tok(), secret=gk.secret, now=now)
        except TokenError as e:
            return {"status": "denied", "rule_id": "AUTH-001", "explanation": str(e)}
        w = gk.policy.window_seconds
        spent = gk.audit.window_sum_paise(cap.agent_id, w, now=now, effect="irreversible_money")
        count = gk.audit.window_count(cap.agent_id, w, now=now, effect="irreversible_money")
        window_ceiling = min(200_000, cap.max_window_paise)
        return {
            "agent_id": cap.agent_id,
            "backend": gk.backend.name,
            "scopes": sorted(cap.scopes),
            "window_seconds": w,
            "window_spent_paise": spent,
            "window_remaining_paise": max(0, window_ceiling - spent),
            "money_actions_in_window": count,
            "money_actions_limit": 5,
            "per_action_auto_limit_paise": min(50_000, cap.max_action_paise),
            "per_action_hard_limit_paise": 100_000,
            "token_expires_in_s": int(cap.exp - now),
        }

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=True))
    def list_my_decisions(limit: Annotated[int, Field(ge=1, le=100)] = 20) -> dict[str, Any]:
        """This agent's own recent Gatekeeper decisions from the hash-chained audit log
        (oldest first). Only rows for this session's agent id are returned."""
        try:
            cap = verify(_tok(), secret=gk.secret, now=clock())
        except TokenError as e:
            return {"status": "denied", "rule_id": "AUTH-001", "explanation": str(e)}
        rows = gk.audit.recent_for_agent(cap.agent_id, limit)
        return {"agent_id": cap.agent_id, "decisions": rows,
                "chain_ok": gk.audit.verify().ok}

    _forbid_unknown_arguments(mcp)
    return mcp


def _forbid_unknown_arguments(mcp: MCPServer) -> None:
    """Reject, rather than silently drop, arguments a tool does not declare.

    The SDK's argument models ignore extra keys. For a payments tool that is
    the wrong failure mode: an injected `upi_id`/`vpa`/`account_id` on a refund
    vanished before the policy engine saw it, so the call executed and the
    audit log never recorded that anyone tried to redirect it. Red-team finding
    RT-01 (docs/MCP_REDTEAM.md). Now the call fails validation and the schema
    advertises `additionalProperties: false`.
    """
    for tool in mcp._tool_manager.list_tools():  # noqa: SLF001 -- no public hook in mcp 2.x
        model = tool.fn_metadata.arg_model
        model.model_config["extra"] = "forbid"
        model.model_rebuild(force=True)
        tool.parameters = model.model_json_schema(by_alias=True)


def from_env() -> tuple[Gatekeeper, str, Clock]:
    _load_dotenv()
    secret = os.environ.get("GATEKEEPER_SIGNING_SECRET", "")
    if not secret:
        raise SystemExit("FATAL: GATEKEEPER_SIGNING_SECRET is not set; refusing to start.")
    backend = get_backend(os.environ.get("GATEKEEPER_MCP_BACKEND", "mock"))
    fixed = os.environ.get("GATEKEEPER_MCP_FIXED_NOW")
    clock = Clock(float(fixed) if fixed else None)
    gk = Gatekeeper(backend=backend, db_path=os.environ.get("GATEKEEPER_MCP_DB", "gatekeeper-mcp.db"),
                    signing_secret=secret)
    token = os.environ.get("GATEKEEPER_MCP_TOKEN", "")
    if not token:
        scopes = [s.strip() for s in os.environ.get("GATEKEEPER_MCP_SCOPES", ",".join(TOOL_OPS)).split(",")
                  if s.strip()]
        token = issue(os.environ.get("GATEKEEPER_MCP_AGENT_ID", "mcp-agent"), scopes, secret=secret,
                      ttl_seconds=int(os.environ.get("GATEKEEPER_MCP_TTL", "3600")), now=clock())
    return gk, token, clock


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Gatekeeper MCP server")
    ap.add_argument("--http", action="store_true", help="serve streamable-http instead of stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    a = ap.parse_args(argv)
    gk, token, clock = from_env()
    print(f"gatekeeper-mcp: backend={gk.backend.name} rules={len(gk.policy.rules)}",
          file=sys.stderr)
    server = build_server(gk, token, clock)
    try:
        if a.http:
            server.run("streamable-http", host=a.host, port=a.port)
        else:
            server.run("stdio")
    finally:
        gk.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
