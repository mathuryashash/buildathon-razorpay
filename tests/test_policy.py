import pytest
from gatekeeper.models import ActionRequest


from .conftest import BUSINESS_HOURS_TS


def act(gk, token, op, _t=None, **args):
    return gk.handle(token, ActionRequest(op=op, args=args),
                     now=_t or BUSINESS_HOURS_TS).decision.verdict.value


def test_reads_are_allowed(gk, token):
    assert act(gk, token, "fetch_payment", payment_id="p") == "allow"


def test_per_action_cap_blocks_large_irreversible_money(gk, token):
    assert act(gk, token, "create_refund", amount=50001, customer_id="cust_demo_001") == "deny"


def test_per_action_cap_is_inclusive_at_the_boundary(gk, token):
    # Off-by-one here blocks a legitimate customer, so it gets its own test.
    assert act(gk, token, "create_refund", amount=50000, customer_id="cust_demo_001") == "allow"


def test_amount_as_string_is_not_a_bypass(gk, token):
    assert act(gk, token, "create_refund", amount="50001", customer_id="cust_demo_001") == "deny"


def test_refund_to_unknown_recipient_is_blocked(gk, token):
    assert act(gk, token, "create_refund", amount=100, customer_id="cust_ATTACKER") == "deny"


def test_payouts_always_need_a_human(gk, token):
    assert act(gk, token, "create_payout", amount=1, contact="x") == "require_approval"


def test_velocity_stops_a_salami_slice(gk, token):
    verdicts = [act(gk, token, "create_refund", _t=BUSINESS_HOURS_TS + i,
                    amount=49000 + i, customer_id="cust_demo_001")
                for i in range(6)]
    assert "deny" in verdicts, "many small legal actions must eventually be stopped"


def test_reversible_writes_do_not_consume_the_money_budget(gk, token):
    # Regression test for ADR-006: a big basket creates an order AND a link for
    # the same rupees. Counting both against the spend window double-charged it.
    assert act(gk, token, "create_order", amount=128000) == "allow"
    assert act(gk, token, "create_payment_link", amount=128000,
               customer_id="cust_demo_001") == "allow"
    assert act(gk, token, "create_payment_link", amount=500000,
               customer_id="cust_demo_002") == "allow"


def test_a_single_deny_beats_any_number_of_allows(gk, token):
    # amount is under the reversible cap (allow) but the op needs approval.
    v = act(gk, token, "create_payout", amount=100, contact="x")
    assert v != "allow"


def test_unknown_condition_in_a_rule_raises_rather_than_silently_passing(tmp_path):
    from gatekeeper.policy import PolicyEngine
    p = tmp_path / "bad.yaml"
    p.write_text("rules:\n  - {id: X, action: deny, when: {no_such_condition: 1}}\n")
    eng = PolicyEngine.load(p)
    from gatekeeper.policy import EvalFacts
    with pytest.raises(ValueError, match="unknown condition"):
        eng.rules[0].matches(EvalFacts("op", None, 0, None, "a", 0, 0, 0, 0, 12))


def test_payment_count_limit_counts_payments_not_every_action(gk, token):
    """Regression for ADR-007.

    An earlier version counted every executed action toward the 'five payments
    per ten minutes' rule, so browsing the catalogue and creating an order used
    up a customer's refund allowance -- and the denial message said
    '5 payments already' when there had been two. A rule whose explanation is
    false is a bug even when the verdict happens to be right.
    """
    for i in range(4):
        assert act(gk, token, "create_order", _t=BUSINESS_HOURS_TS + i, amount=1000) == "allow"
    for i in range(4):
        assert act(gk, token, "create_refund", _t=BUSINESS_HOURS_TS + 10 + i,
                   amount=1000 + i, customer_id="cust_demo_00%d" % (i % 3 + 1)) == "allow"
