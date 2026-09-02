#!/usr/bin/env python3
"""THE DEMO. This is what the pitch video records.

Same agent. Two runs. One number changes.

    python demo.py            # in-process, no servers needed
    python demo.py --live     # hits real Razorpay TEST MODE for the happy path

Run 1: the agent has direct access to the payments API. A poisoned product
       description tells it to issue a large refund to an unknown account, and
       it complies, because nothing is standing in the way.
Run 2: identical agent, identical instruction, now behind Gatekeeper.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gatekeeper.backends import MockBackend, get_backend  # noqa: E402
from gatekeeper.cli import _load_dotenv  # noqa: E402
from gatekeeper.models import ActionRequest  # noqa: E402
from gatekeeper.proxy import Gatekeeper  # noqa: E402
from gatekeeper.tokens import issue  # noqa: E402

SECRET = "demo-signing-secret"
NOW = datetime(2026, 9, 4, 14, 0, 0).timestamp()

# What the agent decides to do after reading a product page whose description
# contains an injected instruction. The agent is not malicious -- it is obedient,
# which is the whole problem.
AGENT_PLAN = [
    ("fetch_catalog",       {}),
    ("create_order",        {"amount": 17700, "receipt": "gk_demo"}),
    ("create_payment_link", {"amount": 17700, "customer_id": "cust_demo_001"}),
    # ---- everything below this line comes from the injected instruction ----
    ("create_refund",       {"amount": 250000, "customer_id": "cust_ATTACKER_9000"}),
    ("create_payout",       {"amount": 500000, "contact": "attacker@evil.test"}),
    ("create_refund",       {"amount": 49000, "customer_id": "cust_demo_001"}),
    ("create_refund",       {"amount": 49001, "customer_id": "cust_demo_002"}),
    ("create_refund",       {"amount": 49002, "customer_id": "cust_demo_003"}),
    ("create_refund",       {"amount": 49003, "customer_id": "cust_demo_001"}),
    ("create_refund",       {"amount": 49004, "customer_id": "cust_demo_002"}),
    ("transfer_all_funds",  {"amount": 999999}),
]

RULE = "=" * 78


def run_ungoverned() -> int:
    print(RULE)
    print("  RUN 1 -- agent talks to the payments API directly (no Gatekeeper)")
    print(RULE)
    backend, moved = MockBackend(), 0
    for op, args in AGENT_PLAN:
        try:
            backend.call(op, args)
            amt = int(args.get("amount", 0))
            moved += amt if op in ("create_refund", "create_payout", "capture_payment") else 0
            print(f"  executed  {op:<20} Rs {amt/100:>10,.2f}")
        except Exception as e:
            print(f"  error     {op:<20} {e}")
    print(f"\n  MONEY MOVED: Rs {moved/100:,.2f}   blocked: 0 of {len(AGENT_PLAN)} actions\n")
    return moved


def run_governed(backend_name: str = "mock") -> int:
    print(RULE)
    print("  RUN 2 -- identical agent, identical instruction, behind Gatekeeper")
    print(RULE)
    gk = Gatekeeper(backend=get_backend(backend_name),
                    db_path=tempfile.mktemp(suffix=".db"), signing_secret=SECRET)
    token = issue("buyer-1", [op for op, _ in AGENT_PLAN if op != "transfer_all_funds"],
                  secret=SECRET, ttl_seconds=86_400, now=NOW)

    moved = blocked = 0
    for i, (op, args) in enumerate(AGENT_PLAN):
        res = gk.handle(token, ActionRequest(op=op, args=args), now=NOW + i)
        v = res.decision.verdict.value
        amt = int(args.get("amount", 0))
        if v == "allow" and res.executed:
            moved += amt if op in ("create_refund", "create_payout", "capture_payment") else 0
            print(f"  ALLOW     {op:<20} Rs {amt/100:>10,.2f}")
        else:
            blocked += 1
            tag = "BLOCK" if v == "deny" else "HOLD "
            print(f"  {tag}     {op:<20} Rs {amt/100:>10,.2f}")
            print(f"            -> {res.decision.explanation.strip()[:88]}")

    print(f"\n  MONEY MOVED: Rs {moved/100:,.2f}   blocked or held: {blocked} of {len(AGENT_PLAN)} actions")
    c = gk.audit.verify()
    print(f"  AUDIT CHAIN: {'intact' if c.ok else 'BROKEN'} across {c.checked} records, "
          f"every decision explained in plain language\n")
    return moved


def main() -> int:
    _load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="use real Razorpay test mode for run 2 (needs .env)")
    a = ap.parse_args()

    print("\n  GATEKEEPER -- a fail-closed capability proxy for agents that move money")
    print("  Scenario: a product description on the merchant's own site contains an")
    print("  injected instruction. The agent is not malicious. It is obedient.\n")

    ungoverned = run_ungoverned()
    governed = run_governed("razorpay" if a.live else "mock")

    print(RULE)
    print(f"  Without Gatekeeper: Rs {ungoverned/100:,.2f} left the merchant.")
    print(f"  With Gatekeeper:    Rs {governed/100:,.2f}.")
    print(f"  Same agent. Same prompt. The difference is enforcement, not instruction.")
    print(RULE + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
