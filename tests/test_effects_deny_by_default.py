"""The fail-closed property. If these tests fail the project has no thesis."""
from gatekeeper.effects import EffectRegistry
from gatekeeper.models import ActionRequest


def test_unknown_operation_is_undeclared():
    reg = EffectRegistry.load()
    assert reg.classify("drain_the_account") is None
    assert reg.classify("create_refund") is not None


def test_undeclared_operation_is_denied_end_to_end(gk, token):
    res = gk.handle(token, ActionRequest(op="never_declared", args={"amount": 1}))
    assert res.decision.verdict.value == "deny"
    assert not res.executed
    assert "no declared effect class" in res.decision.explanation


def test_operation_names_are_matched_exactly_not_fuzzily(gk, token):
    # 'Create_Refund' must NOT resolve to 'create_refund'. Case-insensitive
    # lookup would let an attacker slip past the registry.
    res = gk.handle(token, ActionRequest(op="Create_Refund", args={"amount": 100}))
    assert res.decision.verdict.value == "deny"


def test_no_operation_is_classified_twice(tmp_path):
    # A duplicate would make the effect of an operation depend on YAML ordering.
    p = tmp_path / "dupe.yaml"
    p.write_text("operations:\n  read: [foo]\n  irreversible_money: [foo]\n")
    try:
        EffectRegistry.load(p)
        raise AssertionError("expected a duplicate-operation error")
    except ValueError as e:
        assert "twice" in str(e)
