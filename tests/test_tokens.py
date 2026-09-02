import pytest
from gatekeeper.models import ActionRequest
from gatekeeper.tokens import TokenError, issue, verify
from .conftest import BUSINESS_HOURS_TS, SECRET


def test_round_trip():
    assert verify(issue("a", ["create_order"], secret=SECRET), secret=SECRET).agent_id == "a"


def test_tampered_signature_is_rejected():
    t = issue("a", ["create_order"], secret=SECRET)
    with pytest.raises(TokenError, match="bad signature"):
        verify(t[:-4] + "AAAA", secret=SECRET)


def test_tampered_body_is_rejected():
    body, sig = issue("a", ["create_order"], secret=SECRET).split(".")
    with pytest.raises(TokenError):
        verify(body[:-4] + "AAAA" + "." + sig, secret=SECRET)


def test_expired_token_is_rejected():
    with pytest.raises(TokenError, match="expired"):
        verify(issue("a", [], secret=SECRET, ttl_seconds=-1), secret=SECRET)


def test_wrong_secret_is_rejected():
    with pytest.raises(TokenError):
        verify(issue("a", [], secret=SECRET), secret="different")


def test_scope_is_enforced_before_policy(gk):
    # fetch_payment is harmless, but this token never granted it.
    narrow = issue("test-agent", ["create_order"], secret=SECRET,
                   ttl_seconds=86_400, now=BUSINESS_HOURS_TS)
    res = gk.handle(narrow, ActionRequest(op="fetch_payment", args={}),
                    now=BUSINESS_HOURS_TS)
    assert res.decision.verdict.value == "deny"
    assert "was not granted" in res.decision.explanation


# ---- the grant's own ceilings (ADR-014) ---------------------------------
#
# max_action_paise and max_window_paise were carried in every capability and
# read by nothing. A token saying "this agent may move Rs 100" got the
# merchant-wide Rs 500 rule instead, so narrowing a grant did nothing at all.


def _narrow(**kw):
    from .conftest import ALL_OPS, BUSINESS_HOURS_TS
    return issue("test-agent", ALL_OPS, secret=SECRET, ttl_seconds=86_400,
                 now=BUSINESS_HOURS_TS, **kw)


def _act(gk, tok, op, offset=0, **args):
    from .conftest import BUSINESS_HOURS_TS
    return gk.handle(tok, ActionRequest(op=op, args=args),
                     now=BUSINESS_HOURS_TS + offset)


def test_grant_per_action_cap_binds_below_merchant_policy(gk):
    tok = _narrow(max_action_paise=10_000)
    # Rs 400: allowed by every policy rule, outside this agent's own grant.
    res = _act(gk, tok, "create_refund", amount=40_000, customer_id="cust_demo_001")
    assert res.decision.verdict.value == "deny"
    assert not res.executed
    assert "own capability" in res.decision.explanation


def test_grant_window_cap_binds_below_merchant_policy(gk):
    tok = _narrow(max_action_paise=10_000, max_window_paise=25_000)
    for i in range(2):
        assert _act(gk, tok, "create_refund", offset=i,
                    amount=9000 + i, customer_id="cust_demo_00%d" % (i + 1)
                    ).decision.verdict.value == "allow"
    res = _act(gk, tok, "create_refund", offset=2, amount=9002,
               customer_id="cust_demo_003")
    assert res.decision.verdict.value == "deny"
    assert not res.executed


def test_grant_caps_do_not_touch_reversible_writes(gk):
    """A Rs 5,000 payment link moves no money.

    The grant's ceilings are denominated in money moved. Applying
    max_action_paise to a reversible write would deny a legitimate large
    payment link -- the false block that makes narrow grants unusable.
    """
    tok = _narrow(max_action_paise=10_000, max_window_paise=25_000)
    assert _act(gk, tok, "create_payment_link", amount=500_000,
                customer_id="cust_demo_001").decision.verdict.value == "allow"
    assert _act(gk, tok, "fetch_payment", offset=1,
                payment_id="pay_X").decision.verdict.value == "allow"


def test_a_policy_denial_is_explained_by_policy_not_by_the_grant(gk):
    """Ordering regression.

    The default grant mirrors the default policy numbers exactly. With the
    grant checked first it shadowed CAP-001 completely and every large-amount
    denial read 'your capability caps this' instead of naming the rule and
    the threat behind it. Policy is the artifact a merchant reviews; when both
    bind, policy explains it.
    """
    tok = _narrow()  # defaults: same Rs 500 / Rs 2,000 as policy
    res = _act(gk, tok, "create_refund", amount=250_000, customer_id="cust_demo_001")
    assert res.decision.verdict.value == "deny"
    assert "CAP-001" in [h.rule_id for h in res.decision.hits]
    assert "own capability" not in res.decision.explanation
