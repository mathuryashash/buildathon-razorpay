import tempfile
from datetime import datetime

import pytest
from gatekeeper.backends import MockBackend
from gatekeeper.proxy import Gatekeeper
from gatekeeper.tokens import issue

SECRET = "test-secret"
ALL_OPS = ["fetch_payment", "fetch_order", "fetch_catalog", "create_order",
           "create_payment_link", "cancel_payment_link", "update_payment_notes",
           "capture_payment", "create_refund", "create_payout", "never_declared"]


@pytest.fixture
def gk():
    return Gatekeeper(backend=MockBackend(),
                      db_path=tempfile.mktemp(suffix=".db"),
                      signing_secret=SECRET)


BUSINESS_HOURS_TS = datetime(2026, 9, 4, 14, 0, 0).timestamp()


@pytest.fixture
def token():
    # Issued against the SAME simulated clock the tests evaluate against.
    # Mixing a wall-clock token with an injected evaluation time makes every
    # test fail with 'token expired', which is a confusing way to learn that
    # you injected time in one place and not the other.
    return issue("test-agent", ALL_OPS, secret=SECRET,
                 ttl_seconds=86_400, now=BUSINESS_HOURS_TS)

