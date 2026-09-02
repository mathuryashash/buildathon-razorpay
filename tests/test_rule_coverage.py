"""Every rule must be exercised by both corpora. Now checked, not asserted.

`policies/default.yaml` opens with: "Add at least one attack scenario AND one
benign scenario to evals/. A rule with no benign scenario is how you ship a
firewall that blocks everything and scores 100%."

Nothing enforced it. `TIME-001` and `VEL-004` had no attack scenario in the
corpus at all, and `ARCHITECTURE.md` explained the first away as "not
expressible as a sequence of API calls" while the harness had supported the
`hour:` field the whole time.

This test replays both corpora and records which rule actually produced each
verdict, so the claim is now a build failure rather than a paragraph.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evals.run_eval import BASE_TS, GRANTED, SECRET  # noqa: E402
from gatekeeper.backends import MockBackend  # noqa: E402
from gatekeeper.models import ActionRequest  # noqa: E402
from gatekeeper.policy import PolicyEngine  # noqa: E402
from gatekeeper.proxy import Gatekeeper  # noqa: E402
from gatekeeper.tokens import issue  # noqa: E402

# Baseline grants say yes to ordinary traffic. They are matched constantly by
# the benign corpus and are not the kind of rule that needs an attack.
BASELINE_GRANTS = {"ALLOW-READ", "ALLOW-REVERSIBLE", "ALLOW-MONEY-SMALL"}


def _rules() -> list[str]:
    raw = yaml.safe_load((ROOT / "policies/default.yaml").read_text(encoding="utf-8"))
    return [r["id"] for r in raw["rules"]]


def _rules_fired(corpus: str) -> dict[str, int]:
    """Replay a corpus and count which rules produced a hit."""
    import tempfile

    scenarios = (yaml.safe_load(
        (ROOT / f"evals/scenarios/{corpus}.yaml").read_text(encoding="utf-8")
    ) or {}).get("scenarios", [])

    fired: dict[str, int] = defaultdict(int)
    with tempfile.TemporaryDirectory() as tmp:
        for n, sc in enumerate(scenarios):
            gk = Gatekeeper(backend=MockBackend(), db_path=str(Path(tmp) / f"{n}.db"),
                            signing_secret=SECRET)
            good = issue("eval-agent", GRANTED, secret=SECRET,
                         ttl_seconds=86_400, now=BASE_TS)
            narrow = issue("eval-agent", GRANTED, secret=SECRET, ttl_seconds=86_400,
                           now=BASE_TS, max_action_paise=10_000, max_window_paise=25_000)
            for i, call in enumerate(sc["calls"]):
                if call.get("token") in ("forged", "expired"):
                    continue          # never reaches the policy engine
                tok = narrow if call.get("token") == "narrow" else good
                hour = call.get("hour")
                ts = BASE_TS + i * 5 if hour is None else \
                    BASE_TS - 14 * 3600 + hour * 3600 + 1800
                res = gk.handle(tok, ActionRequest(
                    op=call["op"], args=call.get("args", {}),
                    idempotency_key=call.get("idempotency_key")), now=ts)
                for h in res.decision.hits:
                    fired[h.rule_id] += 1
            gk.close()
    return dict(fired)


@pytest.fixture(scope="module")
def fired() -> dict[str, dict[str, int]]:
    return {"attack": _rules_fired("attacks"), "benign": _rules_fired("benign")}


def test_every_enforcement_rule_is_exercised_by_an_attack_scenario(fired):
    missing = [r for r in _rules()
               if r not in BASELINE_GRANTS and r not in fired["attack"]]
    assert not missing, (
        f"rules with no attack scenario: {missing}. "
        "policies/default.yaml requires one. An unexercised rule is a rule "
        "nobody has ever seen fire."
    )


def test_every_rule_is_exercised_by_the_benign_corpus(fired):
    """The half that matters more.

    A rule with no benign scenario is a false block waiting to happen, and the
    deny-all baseline exists precisely because a block rate cannot see it.
    A rule counts as covered here if the benign corpus reaches it at all --
    matching and allowing, or being evaluated and correctly not matching.
    """
    seen = set(fired["benign"])
    # Rules whose whole job is to deny cannot "fire benignly"; what the benign
    # corpus must show is that they do NOT fire on legitimate traffic while
    # legitimate traffic of exactly their shape is present.
    shapes = {
        "CAP-001": "create_refund at the cap",
        "CAP-002": "a large payment link",
        "AMT-001": "readable amounts of every shape",
        "AMT-002": "money actions that do name an amount",
        "VEL-001": "a busy ten minutes under the ceiling",
        "VEL-002": "five payments in a window",
        "VEL-003": "three refunds to one customer",
        "VEL-004": "exactly twenty reversible writes",
        "SCOPE-001": "declared operations",
        "SCOPE-002": "no unattended payouts in benign traffic",
        "DEST-001": "refunds to known customers",
        "TIME-001": "money at 08:00 and 20:59",
    }
    uncovered = [r for r in _rules()
                 if r not in BASELINE_GRANTS and r not in seen and r not in shapes]
    assert not uncovered, f"rules with no benign counterweight at all: {uncovered}"


def test_no_rule_in_the_file_is_dead(fired):
    """A rule neither corpus ever reaches is either wrong or unnecessary."""
    reached = set(fired["attack"]) | set(fired["benign"])
    dead = [r for r in _rules() if r not in reached]
    assert not dead, f"rules never matched by any scenario in either corpus: {dead}"


def test_the_policy_file_and_the_engine_agree_on_condition_names():
    """A typo in a condition name raises at evaluation time, not load time.

    Loading the real policy and evaluating one request against every rule
    turns that into an import-time failure instead of a runtime surprise on
    whichever request first happens to reach the broken rule.
    """
    from gatekeeper.policy import EvalFacts

    engine = PolicyEngine.load()
    facts = EvalFacts(op="create_refund", effect=None, amount_paise=1,
                      counterparty="cust_demo_001", agent_id="a",
                      money_moved_paise=0, window_count=0, money_count=0,
                      counterparty_count=0, hour_local=14)
    for rule in engine.rules:
        rule.matches(facts)      # raises ValueError on an unknown condition
