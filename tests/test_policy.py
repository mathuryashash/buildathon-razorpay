import pytest
from gatekeeper.models import ActionRequest


from .conftest import BUSINESS_HOURS_TS


def act(gk, token, op, _t=None, **args):
    return gk.handle(token, ActionRequest(op=op, args=args),
                     now=_t or BUSINESS_HOURS_TS).decision.verdict.value


def test_reads_are_allowed(gk, token):
    assert act(gk, token, "fetch_payment", payment_id="p") == "allow"


def test_per_action_cap_blocks_large_irreversible_money(gk, token):
    # Above CAP-003's band too -- CAP-001's hard deny, not merely held.
    assert act(gk, token, "create_refund", amount=100001, customer_id="cust_demo_001") == "deny"


def test_per_action_cap_is_inclusive_at_the_boundary(gk, token):
    # Off-by-one here blocks a legitimate customer, so it gets its own test.
    assert act(gk, token, "create_refund", amount=50000, customer_id="cust_demo_001") == "allow"


def test_amount_as_string_is_not_a_bypass(gk, token):
    assert act(gk, token, "create_refund", amount="100001", customer_id="cust_demo_001") == "deny"


def test_a_mid_band_refund_is_held_not_denied(gk, token):
    """CAP-003, the H-01 fix.

    A full refund on the merchant's own Rs 740 jar of ghee used to be
    structurally impossible -- CAP-001 hard-denied anything over Rs 500, with
    no path to a human. It is now HELD, not blocked: large enough that an
    agent should not clear it alone, small enough to plausibly be a real
    return.
    """
    assert act(gk, token, "create_refund", amount=74000,
              customer_id="cust_demo_001") == "require_approval"


def test_the_old_cap001_boundary_is_now_held_rather_than_denied(gk, token):
    """The exact amount that used to be CAP-001's boundary test.

    Rs 500.01 is over the agent limit but comfortably under the new Rs 1,000
    hard ceiling -- CAP-003's band, not CAP-001's. A rule change that quietly
    widened CAP-001 back to deny here would silently undo the H-01 fix.
    """
    assert act(gk, token, "create_refund", amount=50001,
              customer_id="cust_demo_001") == "require_approval"


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


# ---- OWNER-001: refund ownership, the H-02 hold-out fix --------------------


def test_a_refund_to_a_different_customer_than_who_paid_is_denied(gk, token):
    """The exact H-02 attack: bounds pass, destination is a known customer,
    ownership is simply never checked. DEST-001 alone let this through."""
    assert act(gk, token, "capture_payment", payment_id="pay_owned_001",
              amount=10000, customer_id="cust_demo_001") == "allow"
    res = gk.handle(token, ActionRequest(
        op="create_refund",
        args={"payment_id": "pay_owned_001", "amount": 5000, "customer_id": "cust_demo_002"}),
        now=BUSINESS_HOURS_TS)
    assert res.decision.verdict.value == "deny"
    assert not res.executed
    assert "OWNER-001" in [h.rule_id for h in res.decision.hits]


def test_a_refund_to_the_customer_who_actually_paid_is_allowed(gk, token):
    assert act(gk, token, "capture_payment", payment_id="pay_owned_002",
              amount=10000, customer_id="cust_demo_001") == "allow"
    assert act(gk, token, "create_refund", payment_id="pay_owned_002",
              amount=5000, customer_id="cust_demo_001") == "allow"


def test_a_payment_id_this_proxy_never_captured_is_not_flagged_by_ownership(gk, token):
    """The honest limit of OWNER-001, made explicit rather than discovered.

    A payment_id with no recorded owner cannot be verified, so it is not
    denied by THIS rule -- DEST-001 (a known customer) is what still governs
    it, exactly as before H-02 was found.
    """
    assert act(gk, token, "create_refund", payment_id="pay_never_seen",
              amount=5000, customer_id="cust_demo_001") == "allow"


# ---- LINK-001: inbound redirection, the H-05 hold-out fix ------------------
#
# The exact H-05 attack: cancel a live link, reissue an identical one at an
# attacker's own destination. The merchant's balance never moves, so no cap
# or velocity rule on money moved ever sees it. All three tests below use the
# real plink id `create_payment_link` returns, rather than a guessed one.


def test_a_resent_link_to_the_same_destination_is_allowed(gk, token):
    """A customer's payment app glitched; the merchant cancels and resends
    the identical link. Must not be treated as an attack."""
    r1 = gk.handle(token, ActionRequest(op="create_payment_link", args={
        "amount": 21000, "customer_id": "cust_demo_001", "upi_id": "priya@okhdfcbank"}),
        now=BUSINESS_HOURS_TS)
    assert r1.decision.verdict.value == "allow"
    plink_id = r1.result["id"]

    r2 = gk.handle(token, ActionRequest(
        op="cancel_payment_link", args={"payment_link_id": plink_id}),
        now=BUSINESS_HOURS_TS + 1)
    assert r2.decision.verdict.value == "allow"

    r3 = gk.handle(token, ActionRequest(op="create_payment_link", args={
        "amount": 21000, "customer_id": "cust_demo_001", "upi_id": "priya@okhdfcbank"}),
        now=BUSINESS_HOURS_TS + 2)
    assert r3.decision.verdict.value == "allow"


def test_a_reissued_link_with_a_swapped_destination_is_denied(gk, token):
    r1 = gk.handle(token, ActionRequest(op="create_payment_link", args={
        "amount": 56000, "customer_id": "cust_demo_003", "upi_id": "acmeorganics@okhdfcbank"}),
        now=BUSINESS_HOURS_TS)
    assert r1.decision.verdict.value == "allow"
    plink_id = r1.result["id"]

    r2 = gk.handle(token, ActionRequest(
        op="cancel_payment_link", args={"payment_link_id": plink_id}),
        now=BUSINESS_HOURS_TS + 1)
    assert r2.decision.verdict.value == "allow"

    r3 = gk.handle(token, ActionRequest(op="create_payment_link", args={
        "amount": 56000, "customer_id": "cust_demo_003", "upi_id": "attacker@okaxis"}),
        now=BUSINESS_HOURS_TS + 2)
    assert r3.decision.verdict.value == "deny"
    assert not r3.executed
    assert "LINK-001" in [h.rule_id for h in r3.decision.hits]


def test_a_different_customer_after_a_cancellation_is_unaffected(gk, token):
    """The redirect check is keyed by customer, not just by agent and amount.

    Without that, two unrelated legitimate orders of the same round amount
    for two different customers within ten minutes would false-positive.
    """
    r1 = gk.handle(token, ActionRequest(op="create_payment_link", args={
        "amount": 21000, "customer_id": "cust_demo_001", "upi_id": "priya@okhdfcbank"}),
        now=BUSINESS_HOURS_TS)
    plink_id = r1.result["id"]
    gk.handle(token, ActionRequest(
        op="cancel_payment_link", args={"payment_link_id": plink_id}),
        now=BUSINESS_HOURS_TS + 1)

    r3 = gk.handle(token, ActionRequest(op="create_payment_link", args={
        "amount": 21000, "customer_id": "cust_demo_002", "upi_id": "arjun@okaxis"}),
        now=BUSINESS_HOURS_TS + 2)
    assert r3.decision.verdict.value == "allow"


def test_a_first_time_link_with_no_prior_cancellation_is_unaffected(gk, token):
    """The honest limit of LINK-001: a brand-new link has nothing to compare
    against, so an attacker-controlled destination on a FIRST link is not
    caught by this rule. Named plainly rather than discovered later."""
    res = gk.handle(token, ActionRequest(op="create_payment_link", args={
        "amount": 56000, "customer_id": "cust_demo_003", "upi_id": "attacker@okaxis"}),
        now=BUSINESS_HOURS_TS)
    assert res.decision.verdict.value == "allow"


def test_cancel_payment_link_actually_executes_against_the_mock(gk, token):
    """MockBackend had no branch for cancel_payment_link and fell through to
    BackendError on every call. B4-02's benign scenario only checks that the
    VERDICT is allow -- computed at step 4, before the backend is reached --
    so a policy allow plus a silent execution failure still read as 'allow'
    and nobody noticed the cancel never actually ran."""
    r1 = gk.handle(token, ActionRequest(
        op="create_payment_link",
        args={"amount": 21000, "customer_id": "cust_demo_001"}),
        now=BUSINESS_HOURS_TS)
    res = gk.handle(token, ActionRequest(
        op="cancel_payment_link", args={"payment_link_id": r1.result["id"]}),
        now=BUSINESS_HOURS_TS + 1)
    assert res.decision.verdict.value == "allow"
    assert res.executed, "cancel_payment_link did not actually execute"
    assert res.error is None
