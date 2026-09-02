"""The HTTP surface. It had no tests, and three of its four endpoints were open.

`/v1/audit`, `/v1/audit/verify` and `/v1/approvals` returned every amount,
customer id, raw payload and hash the proxy had ever seen, to anything that
could reach the port. Reading the audit trail is an operator action, so it now
needs a capability that says so -- and a buyer agent's token does not carry it,
which is the whole point of a scoped grant.
"""
import pytest
from fastapi.testclient import TestClient

from gatekeeper.proxy import create_app
from gatekeeper.tokens import issue

from .conftest import ALL_OPS, BUSINESS_HOURS_TS, SECRET

READER = ["read_audit"]


def _client(gk):
    return TestClient(create_app(gk), raise_server_exceptions=False)


def _tok(scopes):
    return issue("test-agent", scopes, secret=SECRET,
                 ttl_seconds=10**9, now=BUSINESS_HOURS_TS)


def _auth(scopes):
    return {"Authorization": f"Bearer {_tok(scopes)}"}


# ---- the audit endpoints are not public ---------------------------------


def test_audit_endpoints_reject_an_anonymous_caller(gk):
    c = _client(gk)
    for path in ("/v1/audit", "/v1/audit/verify", "/v1/approvals"):
        assert c.get(path).status_code == 401, path


def test_an_agent_token_cannot_read_the_audit_trail(gk):
    """The buyer agent holds a capability for money operations. That is not a
    licence to read every other customer's transaction history."""
    c = _client(gk)
    for path in ("/v1/audit", "/v1/audit/verify", "/v1/approvals"):
        r = c.get(path, headers=_auth(ALL_OPS))
        assert r.status_code == 403, (path, r.status_code)


def test_an_operator_token_can(gk):
    c = _client(gk)
    for path in ("/v1/audit", "/v1/audit/verify", "/v1/approvals"):
        assert c.get(path, headers=_auth(READER)).status_code == 200, path


def test_limit_zero_does_not_return_the_entire_table(gk):
    """`rows[-0:]` is `rows[:]`, so limit=0 returned everything."""
    c = _client(gk)
    for i in range(5):
        c.post("/v1/act", json={"op": "create_order", "args": {"amount": 100 + i}},
               headers=_auth(ALL_OPS))
    body = c.get("/v1/audit?limit=0", headers=_auth(READER)).json()
    assert len(body["records"]) == 1, len(body["records"])


# ---- nothing reaches the money path unauthenticated ----------------------


def test_act_requires_a_bearer_token(gk):
    assert _client(gk).post("/v1/act", json={"op": "fetch_catalog"}).status_code == 401


def test_a_non_ascii_token_is_denied_not_a_crash(gk):
    """Starlette decodes headers as latin-1 and `hmac.compare_digest` raises
    TypeError on a non-ASCII str, so one high byte in an Authorization header
    produced an unauthenticated 500 out of the proxy's own identity check.

    Driven through `handle` rather than the test client: httpx refuses to
    encode the header at all, so only a raw socket reproduces it end to end.
    The defect lives in `tokens.verify`, and that is where it is pinned.
    """
    from gatekeeper.models import ActionRequest
    from gatekeeper.tokens import TokenError, verify

    for bad in ("x.é", "é", "\udce9", "x." + "₹"):
        with pytest.raises(TokenError):
            verify(bad, secret=SECRET, now=BUSINESS_HOURS_TS)

    res = gk.handle("x.é", ActionRequest(op="fetch_catalog", args={}),
                    now=BUSINESS_HOURS_TS)
    assert res.decision.verdict.value == "deny"
    assert len(list(gk.audit.rows())) == 1, "the rejection was not audited"


def test_a_garbage_amount_is_denied_not_a_500(gk):
    r = _client(gk).post("/v1/act", json={
        "op": "create_refund", "args": {"amount": "²", "customer_id": "cust_demo_001"}},
        headers=_auth(ALL_OPS))
    assert r.status_code == 200, r.status_code
    assert r.json()["decision"]["verdict"] == "deny"


def test_healthz_needs_no_token_and_leaks_nothing(gk):
    body = _client(gk).get("/healthz").json()
    assert body["ok"] is True
    assert set(body) == {"ok", "backend", "rules", "operations"}
