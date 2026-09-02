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


def test_velocity_uses_the_injected_clock_not_the_wall_clock(gk):
    """Regression for ADR-012.

    PolicyEngine asked the audit log for window totals without passing the
    timestamp it was evaluating against, so the log fell back to
    time.time(). Window edges came from the wall clock while record
    timestamps came from the injected one. Whenever the injected clock was
    older than (wall clock - window), every record fell outside the window
    and velocity silently stopped applying -- the whole `velocity` attack
    family passed only because the eval's BASE_TS happened to be in the
    future. Pin it to a fixed past date so a passing wall clock cannot hide
    the regression again.
    """
    from datetime import datetime

    from gatekeeper.tokens import issue

    from .conftest import ALL_OPS, SECRET

    past = datetime(2020, 6, 1, 14, 0, 0).timestamp()
    tok = issue("test-agent", ALL_OPS, secret=SECRET, ttl_seconds=10**9, now=past)

    # Five refunds just under the per-action cap, spread across three
    # customers so only the rolling-value rule can fire. The running total
    # crosses the Rs 2,000 window ceiling on the fifth.
    verdicts = [
        act(gk, tok, "create_refund", _t=past + i * 5,
            amount=49000 + i, customer_id="cust_demo_00%d" % (i % 3 + 1))
        for i in range(5)
    ]
    assert verdicts == ["allow"] * 4 + ["deny"], verdicts


# ---- AMT-001: an unreadable amount is denied, not read as zero (ADR-013) --


@pytest.mark.parametrize("bad", [
    250000.0,            # a plain JSON float -- this is the one that worked
    -500000,             # negative
    "2.5e5",             # exponent notation: a number to json.loads, not a digit-string
    {"value": 250000},   # nested object where a scalar belongs
    None,
    [250000],
    True,                # bool is an int in Python. It is not an amount.
])
def test_an_unreadable_amount_is_denied_rather_than_treated_as_zero(gk, token, bad):
    res = gk.handle(token, ActionRequest(
        op="create_refund", args={"amount": bad, "customer_id": "cust_demo_001"}),
        now=BUSINESS_HOURS_TS)
    assert res.decision.verdict.value == "deny", f"{bad!r} was not denied"
    assert not res.executed, f"{bad!r} EXECUTED -- the per-action cap is bypassed"


@pytest.mark.parametrize("good,expected", [
    (8500, 8500), ("9200", 9200), (50000, 50000), (0, 0), ("0", 0),
])
def test_readable_amounts_are_untouched(good, expected):
    r = ActionRequest(op="create_refund", args={"amount": good})
    assert r.amount_is_valid
    assert r.amount_paise == expected


def test_an_absent_amount_is_valid_not_unreadable():
    """Reads carry no amount. If absent read as unreadable, AMT-001 would deny
    every fetch in the system -- the deny-all failure mode in miniature."""
    r = ActionRequest(op="fetch_catalog", args={})
    assert r.amount_is_valid and r.amount_paise == 0


def test_a_backend_that_raises_something_unexpected_is_still_audited(gk, token):
    """The proxy caught BackendError only.

    A malformed payload made MockBackend raise a bare ValueError out of
    int(), which escaped the handler, skipped the audit append, and left a
    permitted money call with no record at all -- the one outcome the audit
    trail exists to prevent.
    """
    class Exploding:
        name = "exploding"

        def call(self, op, args):
            raise ValueError("something the backend never promised to raise")

    gk.backend = Exploding()
    before = len(list(gk.audit.rows()))
    res = gk.handle(token, ActionRequest(
        op="create_refund", args={"amount": 8500, "customer_id": "cust_demo_001"}),
        now=BUSINESS_HOURS_TS)

    assert res.error is not None and not res.executed
    assert len(list(gk.audit.rows())) == before + 1, "the failed call left no audit record"
    assert gk.audit.verify().ok


# ---- ADR-016: the money window counts money, not every executed row --------


def test_reversible_writes_do_not_consume_the_money_budget_for_a_later_payment(gk, token):
    """The teeth ADR-006's original regression test was missing.

    That test asserted three reversible writes are allowed, which they were
    even with the bug. The bug is only visible when a MONEY action follows
    them: ADR-006 scoped VEL-001's trigger to irreversible_money and left the
    sum it compares against counting every executed row, so ADR-006's own
    worked example still failed. A Rs 1,280 basket -- an order plus a payment
    link, zero rupees moved -- put Rs 2,560 into "money moved in the last 10
    minutes" and denied the next refund with an explanation that was false.
    """
    assert act(gk, token, "create_order", amount=128_000) == "allow"
    assert act(gk, token, "create_payment_link", _t=BUSINESS_HOURS_TS + 1,
               amount=128_000, customer_id="cust_demo_001") == "allow"

    assert gk.audit.window_sum_paise("test-agent", 600, now=BUSINESS_HOURS_TS + 2,
                                     effect="irreversible_money") == 0

    res = gk.handle(token, ActionRequest(
        op="create_refund", args={"amount": 1, "customer_id": "cust_demo_001"}),
        now=BUSINESS_HOURS_TS + 2)
    assert res.decision.verdict.value == "allow", res.decision.explanation


# ---- ADR-017: the destination allowlist binds to every destination ---------


def test_a_refund_naming_no_destination_is_denied(gk, token):
    """Dropping the field used to execute the refund: `counterparty_not_in`
    could not match what was not there, so the rule silently did not apply."""
    res = gk.handle(token, ActionRequest(
        op="create_refund", args={"amount": 50_000, "payment_id": "pay_X"}),
        now=BUSINESS_HOURS_TS)
    assert res.decision.verdict.value == "deny"
    assert not res.executed
    assert "DEST-001" in [h.rule_id for h in res.decision.hits]


def test_an_allowlisted_decoy_does_not_hide_a_second_destination(gk, token):
    """Only the first destination field was read, and the agent chooses the
    order. An allowlisted customer_id beside an attacker's upi_id passed."""
    res = gk.handle(token, ActionRequest(op="create_refund", args={
        "amount": 50_000,
        "customer_id": "cust_demo_001",     # decoy, on the allowlist
        "upi_id": "attacker@ybl",           # where the money actually goes
    }), now=BUSINESS_HOURS_TS)
    assert res.decision.verdict.value == "deny"
    assert not res.executed
    assert "attacker@ybl" in res.decision.explanation


# ---- AMT-002: absent is not the same as zero -------------------------------


def test_a_money_action_with_no_amount_is_denied(gk, token):
    """Absent parsed to a valid 0, and 0 passes every cap -- each one asks
    whether a number is too big. Razorpay reads an omitted refund amount as
    the FULL payment, so the request no rule could bound was the largest."""
    for op in ("create_refund", "capture_payment"):
        res = gk.handle(token, ActionRequest(
            op=op, args={"customer_id": "cust_demo_001", "payment_id": "pay_X"}),
            now=BUSINESS_HOURS_TS)
        assert res.decision.verdict.value == "deny", op
        assert not res.executed, op


def test_a_read_with_no_amount_is_untouched(gk, token):
    assert act(gk, token, "fetch_payment", payment_id="pay_X") == "allow"


# ---- ADR-020: an internal error denies, and is audited ---------------------


def test_an_internal_error_denies_and_is_audited(gk, token):
    """`"²".isdigit()` is True and `int("²")` raises. That ValueError
    escaped `handle` entirely -- FastAPI returned a bare 500 and nothing was
    written to the audit log. Only step 7 was guarded; steps 1-6 were not."""
    res = gk.handle(token, ActionRequest(
        op="create_refund", args={"amount": "²", "customer_id": "cust_demo_001"}),
        now=BUSINESS_HOURS_TS)
    assert res.decision.verdict.value == "deny"
    assert not res.executed
    assert len(list(gk.audit.rows())) == 1
    assert gk.audit.verify().ok


def test_the_proxy_refuses_to_exist_without_a_signing_secret(monkeypatch):
    """The guard lived in cli.py only, so anything constructing Gatekeeper
    directly verified every token against "" -- and a token signed with "" is
    a token anyone can mint, with any scopes and any ceilings."""
    import tempfile

    from gatekeeper.backends import MockBackend
    from gatekeeper.proxy import Gatekeeper

    monkeypatch.delenv("GATEKEEPER_SIGNING_SECRET", raising=False)
    with pytest.raises(ValueError, match="signing secret"):
        Gatekeeper(backend=MockBackend(), db_path=tempfile.mktemp(suffix=".db"))
