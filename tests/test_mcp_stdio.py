"""A REAL MCP client talks to the Gatekeeper MCP server over stdio.

This spawns `python -m gatekeeper.mcp_server` as a subprocess and drives it
with the official SDK client -- the same path Claude Desktop / Claude Code
take. No in-process shortcut: if the stdio wiring, the tool schemas or the
structured results are wrong, these fail.

The server is pinned to the mock backend and to a 14:00 clock so TIME-001
does not make the result depend on when CI happens to run.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import anyio
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

ROOT = Path(__file__).resolve().parent.parent
FIXED_NOW = str(datetime(2020, 6, 5, 14, 0, 0).timestamp())


def _params(db: str, **extra_env: str) -> StdioServerParameters:
    env = {
        "GATEKEEPER_SIGNING_SECRET": "test-secret-for-mcp-stdio-only",
        "GATEKEEPER_MCP_BACKEND": "mock",
        "GATEKEEPER_MCP_DB": db,
        "GATEKEEPER_MCP_FIXED_NOW": FIXED_NOW,
        # A Razorpay key in the parent env must never reach this child.
        "RAZORPAY_KEY_ID": "",
        "RAZORPAY_KEY_SECRET": "",
        **extra_env,
    }
    return StdioServerParameters(command=sys.executable,
                                 args=["-m", "gatekeeper.mcp_server"],
                                 env=env, cwd=str(ROOT))


def _payload(res) -> dict:
    if res.structured_content is not None:
        return res.structured_content
    return json.loads(res.content[0].text)


def run(fn, **env):
    db = str(Path(tempfile.mkdtemp(prefix="gk-mcp-")) / "mcp.db")

    async def main():
        async with Client(_params(db, **env), mode="legacy") as c:
            return await fn(c)
    return anyio.run(main)


def test_lists_the_gatekeeper_tools():
    async def fn(c):
        return sorted(t.name for t in (await c.list_tools()).tools)
    names = run(fn)
    for t in ["create_refund", "create_payment_link", "cancel_payment_link",
              "check_budget", "list_my_decisions"]:
        assert t in names


def test_tool_schemas_never_ask_for_a_token_or_key():
    async def fn(c):
        return (await c.list_tools()).tools
    for t in run(fn):
        props = json.dumps(t.input_schema).lower()
        for bad in ("token", "secret", "key_id", "authorization"):
            # idempotency_key is the one legitimate "key"
            assert bad not in props.replace("idempotency_key", ""), (t.name, bad)


def test_allowed_refund_executes_and_is_audited():
    async def fn(c):
        r = await c.call_tool("create_refund", {"payment_id": "pay_A", "amount_paise": 12000,
                                                "customer_id": "cust_demo_001"})
        d = await c.call_tool("list_my_decisions", {"limit": 5})
        return r, d
    r, d = run(fn)
    p = _payload(r)
    assert not r.is_error
    assert p["status"] == "executed"
    assert p["result"]["entity"] == "refund"
    rows = _payload(d)["decisions"]
    assert rows[-1]["op"] == "create_refund" and rows[-1]["verdict"] == "allow"


def test_denied_refund_returns_structured_error_with_rule_id():
    async def fn(c):
        return await c.call_tool("create_refund", {"payment_id": "pay_A", "amount_paise": 250000,
                                                   "customer_id": "cust_demo_001"})
    r = run(fn)
    p = _payload(r)
    assert r.is_error
    assert p["status"] == "denied"
    assert p["rule_id"] == "CAP-001"
    assert "CAP-001" in p["rule_ids"]


def test_attacker_destination_is_denied_by_dest_rule():
    async def fn(c):
        return await c.call_tool("create_refund", {"payment_id": "pay_A", "amount_paise": 9000,
                                                   "customer_id": "cust_attacker_999"})
    p = _payload(run(fn))
    assert p["status"] == "denied" and p["rule_id"] == "DEST-001"


def test_held_refund_returns_pending_approval_not_error():
    async def fn(c):
        return await c.call_tool("create_refund", {"payment_id": "pay_A", "amount_paise": 74000,
                                                   "customer_id": "cust_demo_002"})
    r = run(fn)
    p = _payload(r)
    assert not r.is_error
    assert p["status"] == "pending_approval"
    assert p["rule_id"] == "CAP-003"
    assert isinstance(p["audit_seq"], int)


def test_check_budget_reflects_spend():
    async def fn(c):
        await c.call_tool("create_refund", {"payment_id": "pay_A", "amount_paise": 30000,
                                            "customer_id": "cust_demo_001"})
        return await c.call_tool("check_budget", {})
    b = _payload(run(fn))
    assert b["window_spent_paise"] == 30000
    assert b["window_remaining_paise"] == 200000 - 30000
    assert b["per_action_auto_limit_paise"] == 50000


def test_scoped_token_without_refund_scope_is_denied_scope_000():
    async def fn(c):
        return await c.call_tool("create_refund", {"payment_id": "pay_A", "amount_paise": 100,
                                                   "customer_id": "cust_demo_001"})
    p = _payload(run(fn, GATEKEEPER_MCP_SCOPES="create_payment_link,cancel_payment_link"))
    assert p["status"] == "denied" and p["rule_id"] == "SCOPE-000"


def test_forged_token_is_denied_auth_001():
    async def fn(c):
        return await c.call_tool("create_payment_link", {"amount_paise": 1000,
                                                         "customer_id": "cust_demo_001"})
    p = _payload(run(fn, GATEKEEPER_MCP_TOKEN="eyJhZ2VudF9pZCI6Im1hbGxvcnkifQ.AAAA"))
    assert p["status"] == "denied" and p["rule_id"] == "AUTH-001"


def test_server_refuses_to_start_on_live_razorpay_key():
    """The razorpay backend must never accept a live key, via MCP or otherwise."""
    import subprocess

    env = {**os.environ, **_params("unused.db").env, "GATEKEEPER_MCP_BACKEND": "razorpay",
           "RAZORPAY_KEY_ID": "rzp_" + "live_" + "x" * 14, "RAZORPAY_KEY_SECRET": "x"}
    p = subprocess.run([sys.executable, "-m", "gatekeeper.mcp_server"], cwd=str(ROOT), env=env,
                       input="", capture_output=True, text=True, timeout=60)
    assert p.returncode != 0
    assert "refusing to start" in p.stderr and "not a test key" in p.stderr


def test_streamable_http_transport_serves_the_same_tools():
    """The --http mode: a real HTTP MCP client lists tools and gets a denial."""
    import socket
    import subprocess
    import time as _t

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    db = str(Path(tempfile.mkdtemp(prefix="gk-mcp-http-")) / "mcp.db")
    env = {**os.environ, **_params(db).env}
    proc = subprocess.Popen([sys.executable, "-m", "gatekeeper.mcp_server", "--http",
                             "--port", str(port)], cwd=str(ROOT), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = _t.time() + 20
        while _t.time() < deadline:
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            _t.sleep(0.2)

        async def main():
            async with Client(f"http://127.0.0.1:{port}/mcp") as c:
                names = [t.name for t in (await c.list_tools()).tools]
                r = await c.call_tool("create_refund", {"payment_id": "p", "amount_paise": 250000,
                                                        "customer_id": "cust_demo_001"})
                return names, r
        names, r = anyio.run(main)
        assert "create_refund" in names
        assert _payload(r)["rule_id"] == "CAP-001"
    finally:
        proc.terminate()
        proc.wait(timeout=10)
