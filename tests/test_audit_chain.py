from gatekeeper.models import ActionRequest

from .conftest import BUSINESS_HOURS_TS as T


def test_chain_verifies_when_untouched(gk, token):
    for i in range(5):
        gk.handle(token, ActionRequest(op="create_order", args={"amount": 1000 + i}), now=T)
    c = gk.audit.verify()
    assert c.ok and c.checked == 5


def test_chain_detects_an_edited_record(gk, token):
    gk.handle(token, ActionRequest(op="create_order", args={"amount": 1000}), now=T)
    gk.handle(token, ActionRequest(op="create_order", args={"amount": 2000}), now=T)
    gk.audit._conn.execute("UPDATE audit SET amount_paise=999999 WHERE seq=1")
    gk.audit._conn.commit()
    c = gk.audit.verify()
    assert not c.ok and c.broken_at == 1


def test_chain_detects_a_deleted_record(gk, token):
    for i in range(3):
        gk.handle(token, ActionRequest(op="create_order", args={"amount": 100 + i}), now=T)
    gk.audit._conn.execute("DELETE FROM audit WHERE seq=2")
    gk.audit._conn.commit()
    assert not gk.audit.verify().ok


def test_denials_are_audited_too(gk, token):
    # A log that only records successes cannot tell you what was stopped.
    gk.handle(token, ActionRequest(op="create_refund",
                                   args={"amount": 900000, "customer_id": "cust_demo_001"}), now=T)
    rows = list(gk.audit.rows())
    assert len(rows) == 1 and rows[0]["verdict"] == "deny"
    assert rows[0]["explanation"]


def test_every_record_carries_a_human_readable_explanation(gk, token):
    gk.handle(token, ActionRequest(op="create_payout", args={"amount": 100, "contact": "x"}), now=T)
    for r in gk.audit.rows():
        assert len(r["explanation"]) > 20, "audit entries must explain themselves"
