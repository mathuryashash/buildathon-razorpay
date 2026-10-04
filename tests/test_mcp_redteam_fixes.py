"""Regression tests for the gaps the MCP red-team suite found.

Each test reproduces a miss from evals/mcp_redteam (see docs/MCP_REDTEAM.md
for the before/after numbers). They run against the Gatekeeper core, so the
fix lives in the policy path and protects the HTTP proxy too, not just MCP.
"""
from __future__ import annotations

import anyio

from gatekeeper.models import ActionRequest

from .conftest import BUSINESS_HOURS_TS as T


def _refund(gk, token, amount, pid, cust="cust_demo_001", key=None, now=T, **extra):
    return gk.handle(token, ActionRequest(
        op="create_refund",
        args={"payment_id": pid, "amount": amount, "customer_id": cust, **extra},
        idempotency_key=key), now=now)


# ---- RT-02: splitting a held/denied refund into under-cap pieces ----------

def test_refund_on_a_payment_whose_refund_was_just_held_is_also_held(gk, token):
    held = _refund(gk, token, 90_000, "pay_SPLIT")
    assert held.decision.verdict.value == "require_approval"
    piece = _refund(gk, token, 45_000, "pay_SPLIT", now=T + 5)
    assert not piece.executed
    assert piece.decision.verdict.value == "require_approval"
    assert "SPLIT-001" in [h.rule_id for h in piece.decision.hits]


def test_refund_on_a_payment_whose_refund_was_denied_is_held(gk, token):
    _refund(gk, token, 250_000, "pay_SPLIT2")
    piece = _refund(gk, token, 40_000, "pay_SPLIT2", now=T + 5)
    assert not piece.executed and "SPLIT-001" in [h.rule_id for h in piece.decision.hits]


def test_a_held_refund_does_not_affect_a_different_payment(gk, token):
    _refund(gk, token, 90_000, "pay_A")
    other = _refund(gk, token, 12_000, "pay_B", now=T + 5)
    assert other.executed


def test_split_hold_expires_with_the_velocity_window(gk, token):
    _refund(gk, token, 90_000, "pay_W")
    later = _refund(gk, token, 12_000, "pay_W", now=T + 700)
    assert later.executed


# ---- RT-03: duplicate refund of one payment under a fresh idempotency key --

def test_same_payment_same_amount_with_a_new_key_is_held_not_paid_twice(gk, token):
    first = _refund(gk, token, 30_000, "pay_DUP", key="a")
    assert first.executed
    dup = _refund(gk, token, 30_000, "pay_DUP", key="b", now=T + 5)
    assert not dup.executed
    assert dup.decision.verdict.value == "require_approval"
    assert "DUP-001" in [h.rule_id for h in dup.decision.hits]


def test_two_different_partial_refunds_of_one_payment_both_execute(gk, token):
    assert _refund(gk, token, 12_000, "pay_TWO").executed
    assert _refund(gk, token, 8_000, "pay_TWO", now=T + 5).executed


def test_same_amount_refund_after_the_window_is_not_a_duplicate(gk, token):
    assert _refund(gk, token, 20_000, "pay_LATE").executed
    assert _refund(gk, token, 20_000, "pay_LATE", key="second", now=T + 700).executed


# ---- RT-04: resend after cancel replayed the CANCELLED link ---------------

def test_resending_a_cancelled_link_creates_a_new_link_not_a_replay(gk, token):
    args = {"amount": 21_000, "customer_id": "cust_demo_001", "upi_id": "priya@okhdfcbank"}
    first = gk.handle(token, ActionRequest(op="create_payment_link", args=args), now=T)
    gk.handle(token, ActionRequest(op="cancel_payment_link",
                                   args={"payment_link_id": first.result["id"]}), now=T + 5)
    again = gk.handle(token, ActionRequest(op="create_payment_link", args=args), now=T + 10)
    assert again.executed and not again.replayed
    assert again.result["id"] != first.result["id"]


def test_a_plain_retry_of_a_live_link_is_still_a_replay(gk, token):
    args = {"amount": 21_000, "customer_id": "cust_demo_001"}
    gk.handle(token, ActionRequest(op="create_payment_link", args=args), now=T)
    again = gk.handle(token, ActionRequest(op="create_payment_link", args=args), now=T + 5)
    assert again.replayed and not again.executed


# ---- RT-01: MCP silently dropped undeclared destination arguments ---------

def test_mcp_rejects_an_undeclared_destination_argument(gk, token):
    from mcp.client import Client

    from gatekeeper.mcp_server import build_server

    srv = build_server(gk, token, lambda: T)

    async def go():
        async with Client(srv) as c:
            return await c.call_tool("create_refund", {
                "payment_id": "pay_X", "amount_paise": 1000,
                "customer_id": "cust_demo_001", "upi_id": "attacker@ybl"})
    res = anyio.run(go)
    assert res.is_error
    assert "upi_id" in res.content[0].text
    assert not any(r["op"] == "create_refund" and r["executed"] for r in gk.audit.rows())
