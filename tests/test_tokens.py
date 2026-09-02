import pytest
from gatekeeper.models import ActionRequest
from gatekeeper.tokens import TokenError, issue, verify
from .conftest import SECRET


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
    narrow = issue("test-agent", ["create_order"], secret=SECRET)
    res = gk.handle(narrow, ActionRequest(op="fetch_payment", args={}))
    assert res.decision.verdict.value == "deny"
    assert "was not granted" in res.decision.explanation
