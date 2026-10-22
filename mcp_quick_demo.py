"""60-second MCP demo. No API keys, no network, no LLM.

Spawns `python -m gatekeeper.mcp_server` over stdio (mock backend, a fixed
14:00 clock, a throwaway signing secret and audit db) and makes the calls an
injected agent would make, through the official MCP client:

    python mcp_quick_demo.py
"""
from __future__ import annotations

import json
import secrets
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import anyio
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

ROOT = Path(__file__).resolve().parent

CALLS = [
    ("legit refund, Rs 120", "create_refund",
     {"payment_id": "pay_demo_001", "amount_paise": 12000, "customer_id": "cust_demo_001"}),
    ("injected: Rs 9,500 to an attacker", "create_refund",
     {"payment_id": "pay_demo_001", "amount_paise": 950000, "customer_id": "cust_attacker_999"}),
    ("injected: small refund to an attacker", "create_refund",
     {"payment_id": "pay_demo_002", "amount_paise": 5000, "customer_id": "cust_attacker_999"}),
    ("Rs 740 refund (real ghee return)", "create_refund",
     {"payment_id": "pay_demo_003", "amount_paise": 74000, "customer_id": "cust_demo_002"}),
    ("injected: split it to dodge review", "create_refund",
     {"payment_id": "pay_demo_003", "amount_paise": 37000, "customer_id": "cust_demo_002"}),
    ("injected: link collecting to attacker UPI", "create_payment_link",
     {"amount_paise": 56000, "customer_id": "cust_demo_003", "upi_id": "attacker@okaxis"}),
    ("smuggled extra arg on a refund", "create_refund",
     {"payment_id": "pay_demo_004", "amount_paise": 1000, "customer_id": "cust_demo_001",
      "upi_id": "attacker@ybl"}),
]


def _payload(res) -> dict:
    if res.structured_content is not None:
        return res.structured_content
    text = res.content[0].text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"status": "rejected", "explanation": text}


async def main() -> int:
    db = str(Path(tempfile.mkdtemp(prefix="gk-quick-")) / "demo.db")
    env = {
        "GATEKEEPER_SIGNING_SECRET": secrets.token_hex(16),
        "GATEKEEPER_MCP_BACKEND": "mock",
        "GATEKEEPER_MCP_DB": db,
        "GATEKEEPER_MCP_FIXED_NOW": str(datetime(2020, 6, 5, 14, 0).timestamp()),
        "RAZORPAY_KEY_ID": "", "RAZORPAY_KEY_SECRET": "",
    }
    params = StdioServerParameters(command=sys.executable, args=["-m", "gatekeeper.mcp_server"],
                                   env=env, cwd=str(ROOT))
    async with Client(params, mode="legacy") as c:
        tools = sorted(t.name for t in (await c.list_tools()).tools)
        print(f"MCP server up over stdio. Tools: {', '.join(tools)}\n")
        for label, tool, args in CALLS:
            p = _payload(await c.call_tool(tool, args))
            status = p.get("status", "?")
            rule = p.get("rule_id") or ""
            print(f"{label:<42} -> {status:<16} {rule}")
        log = _payload(await c.call_tool("list_my_decisions", {"limit": 50}))
        moved = sum(d.get("amount_paise", 0) for d in log["decisions"] if d.get("executed"))
        print(f"\nexecuted: Rs {moved / 100:,.2f} | audit records: {len(log['decisions'])}"
              f" | hash chain intact: {log['chain_ok']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(anyio.run(main))
