"""The whole path, wired together: buyer agent -> proxy -> merchant.

This is the clause in the Track 01 brief that says "makes a merchant
transactable by an AI buyer end to end", and until this file existed the
README asserted it with nothing behind it. `BuyerAgent` was instantiated
nowhere in the repository -- no test, no make target, no CI step -- so the
one component that makes the project an *agentic commerce* entry rather than
a proxy in isolation was the only one never exercised.

No sockets. Starlette's TestClient speaks to both apps in-process, so this
runs in CI, offline, in milliseconds, and cannot flake on a port collision.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from agent.buyer import BuyerAgent
from merchant.app import app as merchant_app
from gatekeeper.proxy import create_app
from gatekeeper.tokens import issue

from .conftest import SECRET

SHOPPER_SCOPES = ["fetch_catalog", "fetch_payment", "create_order",
                  "create_payment_link", "capture_payment"]


@pytest.fixture
def wired(gk, monkeypatch):
    """A BuyerAgent whose HTTP calls reach the real apps, without a network."""
    proxy = TestClient(create_app(gk), base_url="http://proxy")
    shop = TestClient(merchant_app, base_url="http://merchant")

    # BuyerAgent calls httpx at module level. Point both verbs at whichever
    # app the URL names, so the agent's own code runs unmodified -- the point
    # is to test the agent, not a copy of it.
    def route(url: str) -> TestClient:
        return proxy if "proxy" in str(url) else shop

    monkeypatch.setattr(httpx, "post",
                        lambda url, **kw: route(url).post(str(url), **kw))
    monkeypatch.setattr(httpx, "get",
                        lambda url, **kw: route(url).get(str(url), **kw))

    # Wall-clock token on purpose. Every other test injects the suite's fixed
    # 2020 timestamp, but there is no way to inject a clock through an HTTP
    # request, so a 2020 token would arrive at the proxy long expired. Nothing
    # here is hour-sensitive: TIME-001 only governs irreversible money, and
    # checkout is an order plus a payment link.
    token = issue("buyer-1", SHOPPER_SCOPES, secret=SECRET, ttl_seconds=86_400)
    yield BuyerAgent(proxy_url="http://proxy", token=token,
                     merchant_url="http://merchant")
    proxy.close()
    shop.close()


def test_a_shopper_sentence_becomes_a_real_order_and_payment_link(wired):
    out = wired.checkout("two kilos of atta and some honey")

    assert out["ok"], out
    assert out["order"]["id"].startswith("order_")
    assert out["payment_link"]["id"].startswith("plink_")

    # The merchant priced it, and the order is for exactly that.
    assert out["quote"]["total_paise"] > 0
    assert out["order"]["amount"] == out["quote"]["total_paise"]
    assert out["payment_link"]["amount"] == out["quote"]["total_paise"]


def test_the_agent_never_names_a_price(wired):
    """The structural claim, not a stylistic one.

    The agent proposes SKUs; the merchant prices them. A hallucinated price is
    therefore impossible rather than merely unlikely -- there is no field on
    the wire for the agent to put one in.
    """
    out = wired.checkout("atta and ghee")
    proposed = {c["op"]: c["args"] for c in wired.trace}

    assert out["ok"]
    for op, args in proposed.items():
        # Every amount the agent sent came back from /quote, not from itself.
        if "amount" in args:
            assert args["amount"] == out["quote"]["total_paise"], op


def test_every_agent_action_went_through_the_proxy_and_was_audited(gk, wired):
    out = wired.checkout("two kilos of atta and some honey")
    assert out["ok"]

    rows = list(gk.audit.rows())
    assert [r["op"] for r in rows] == ["create_order", "create_payment_link"]
    assert all(r["verdict"] == "allow" and r["executed"] for r in rows)
    assert gk.audit.verify().ok


def test_the_proxy_stops_the_agent_mid_checkout_and_says_why(gk, monkeypatch, wired):
    """A basket over the approval threshold does not silently half-complete."""
    # Six is the whole shelf -- nine would be refused by the merchant for
    # stock before the proxy ever saw it, which would test the wrong thing.
    monkeypatch.setattr(BuyerAgent, "_resolve_keyword",
                        lambda self, intent, catalog: [{"sku": "GHE-500", "qty": 6},
                                                       {"sku": "TEA-250", "qty": 2}])
    out = wired.checkout("every jar of ghee you have, and two teas")

    # 6 x Rs 740 + 2 x Rs 450 = Rs 5,340, over the Rs 5,000 threshold at
    # which a reversible write needs a human.
    assert out["ok"] is False
    assert out["stage"] == "create_order"
    assert "approval" in out["blocked_by"].lower()
    # Held, not executed, and on the record either way.
    assert [r["verdict"] for r in gk.audit.rows()] == ["require_approval"]


def test_an_unpriceable_cart_is_a_clean_refusal_not_a_crash(wired, monkeypatch):
    """The merchant rejects an out-of-stock quantity with 409.

    Reading ["total_paise"] off that response turned a clear merchant error
    into a KeyError halfway through checkout.
    """
    monkeypatch.setattr(BuyerAgent, "_resolve_keyword",
                        lambda self, intent, catalog: [{"sku": "GHE-500", "qty": 999}])
    out = wired.checkout("all the ghee you have")

    assert out["ok"] is False
    assert out["stage"] == "quote"
    assert "409" in out["reason"]
