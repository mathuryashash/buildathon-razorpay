from gatekeeper.models import ActionRequest

from .conftest import BUSINESS_HOURS_TS as T


def test_retry_storm_executes_exactly_once(gk, token):
    req = lambda: ActionRequest(op="create_payment_link",
                                args={"amount": 12000, "customer_id": "cust_demo_001"})
    results = [gk.handle(token, req(), now=T) for _ in range(20)]
    executed = [r for r in results if r.executed]
    assert len(executed) == 1, "a retry storm must not create 20 payment links"
    assert all(r.replayed for r in results[1:])


def test_replay_returns_the_original_result(gk, token):
    a = gk.handle(token, ActionRequest(op="create_order", args={"amount": 5000}), now=T)
    b = gk.handle(token, ActionRequest(op="create_order", args={"amount": 5000}), now=T)
    assert b.replayed and b.result == a.result


def test_replay_does_not_consume_the_velocity_budget(gk, token):
    for _ in range(10):
        gk.handle(token, ActionRequest(op="create_refund",
                                       args={"amount": 40000, "customer_id": "cust_demo_001"}), now=T)
    total = gk.audit.window_sum_paise("test-agent", 600)
    assert total == 40000, f"replays double-counted spend: {total}"


def test_different_amounts_are_different_actions(gk, token):
    a = gk.handle(token, ActionRequest(op="create_order", args={"amount": 100}), now=T)
    b = gk.handle(token, ActionRequest(op="create_order", args={"amount": 101}), now=T)
    assert a.executed and b.executed and not b.replayed


def test_client_supplied_key_wins_over_content(gk, token):
    a = gk.handle(token, ActionRequest(op="create_order", args={"amount": 100},
                                       idempotency_key="k1"), now=T)
    b = gk.handle(token, ActionRequest(op="create_order", args={"amount": 999},
                                       idempotency_key="k1"), now=T)
    assert a.executed and b.replayed
