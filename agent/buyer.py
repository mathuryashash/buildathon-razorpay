"""The AI buyer agent.

READ THIS BEFORE EDITING: this process must never hold a Razorpay credential.
It holds a capability token. tests/test_no_secrets_in_agent.py enforces that,
and if you 'just for now' put a key in here to debug something, the project's
central claim becomes false.

The agent is deliberately simple. It is not the contribution -- the enforcement
layer underneath it is. A more capable agent does not make the demo better; a
more capable agent that still cannot exceed its bounds is exactly the point.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class BuyerAgent:
    proxy_url: str
    token: str
    merchant_url: str = "http://127.0.0.1:8081"
    trace: list[dict[str, Any]] = field(default_factory=list)

    # -- tool calls all go through the proxy ------------------------------

    def _act(self, op: str, args: dict[str, Any], idem: str | None = None) -> dict[str, Any]:
        r = httpx.post(
            f"{self.proxy_url}/v1/act",
            json={"op": op, "args": args, "idempotency_key": idem},
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=20.0,
        )
        out = r.json()
        self.trace.append({"op": op, "args": args,
                           "verdict": out["decision"]["verdict"],
                           "explanation": out["decision"]["explanation"]})
        return out

    # -- the shopping flow ------------------------------------------------

    def catalog(self) -> list[dict[str, Any]]:
        return httpx.get(f"{self.merchant_url}/catalog", timeout=10.0).json()

    def resolve(self, intent: str, catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Turn 'two kilos of atta and some honey' into SKUs.

        Uses an LLM when OPENAI_API_KEY is present, otherwise a keyword match.
        Either way the model returns SKU REFERENCES ONLY -- never prices. The
        merchant prices the cart. That makes a hallucinated price structurally
        impossible rather than merely unlikely.
        """
        if os.environ.get("OPENAI_API_KEY"):
            try:
                return self._resolve_llm(intent, catalog)
            except Exception:
                pass  # fall through to deterministic path; never fail the demo on an API
        return self._resolve_keyword(intent, catalog)

    def _resolve_keyword(self, intent: str, catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
        words = {w.strip(".,") for w in intent.lower().split()}
        picks = []
        for p in catalog:
            hay = f"{p['title']} {p['sku']}".lower()
            if any(w in hay for w in words if len(w) > 3):
                picks.append({"sku": p["sku"], "qty": 1})
        return picks[:3]

    def _resolve_llm(self, intent: str, catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
        from openai import OpenAI

        listing = "\n".join(f"{p['sku']}: {p['title']}" for p in catalog)
        r = OpenAI().chat.completions.create(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content":
                 "Map the shopper's request to SKUs from the catalogue. Reply with JSON "
                 '{"cart":[{"sku":"...","qty":1}]}. Use only SKUs from the list. Never '
                 "state a price. If nothing matches, return an empty cart."},
                {"role": "user", "content": f"Catalogue:\n{listing}\n\nShopper: {intent}"},
            ],
            response_format={"type": "json_object"},
        )
        cart = json.loads(r.choices[0].message.content).get("cart", [])
        valid = {p["sku"] for p in catalog}
        return [c for c in cart if c.get("sku") in valid]

    def checkout(self, intent: str, customer_id: str = "cust_demo_001") -> dict[str, Any]:
        catalog = self.catalog()
        cart = self.resolve(intent, catalog)
        if not cart:
            return {"ok": False, "reason": "no catalogue match for that request"}

        quote = httpx.post(f"{self.merchant_url}/quote", json=cart, timeout=10.0).json()

        order = self._act("create_order", {"amount": quote["total_paise"],
                                           "receipt": f"gk_{customer_id}"})
        if order["decision"]["verdict"] != "allow":
            return {"ok": False, "stage": "create_order", "quote": quote,
                    "blocked_by": order["decision"]["explanation"]}

        link = self._act("create_payment_link", {
            "amount": quote["total_paise"],
            "description": f"Acme Organics -- {len(cart)} item(s)",
            "customer_id": customer_id,
        })
        if link["decision"]["verdict"] != "allow":
            return {"ok": False, "stage": "create_payment_link", "quote": quote,
                    "blocked_by": link["decision"]["explanation"]}

        return {"ok": True, "quote": quote, "order": order.get("result"),
                "payment_link": link.get("result")}
