import time

from gatekeeper.models import ActionRequest

from .conftest import BUSINESS_HOURS_TS as T


def test_retry_storm_executes_exactly_once(gk, token):
    req = lambda: ActionRequest(op="create_payment_link",
                                args={"amount": 12000, "customer_id": "cust_demo_001"})
    results = [gk.handle(token, req(), now=T) for _ in range(20)]
    executed = [r for r in results if r.executed]
    assert len(executed) == 1, "a retry storm must not create 20 payment links"
    assert all(r.replayed for r in results[1:])


def test_replay_returns_the_original_result(gk, token):
    a = gk.handle(token, ActionRequest(op="create_order", args={"amount": 5000}), now=T)
    b = gk.handle(token, ActionRequest(op="create_order", args={"amount": 5000}), now=T)
    assert b.replayed and b.result == a.result


def test_replay_does_not_consume_the_velocity_budget(gk, token):
    for _ in range(10):
        gk.handle(token, ActionRequest(op="create_refund",
                                       args={"amount": 40000, "customer_id": "cust_demo_001"}), now=T)
    total = gk.audit.window_sum_paise("test-agent", 600, now=T)
    assert total == 40000, f"replays double-counted spend: {total}"


def test_different_amounts_are_different_actions(gk, token):
    a = gk.handle(token, ActionRequest(op="create_order", args={"amount": 100}), now=T)
    b = gk.handle(token, ActionRequest(op="create_order", args={"amount": 101}), now=T)
    assert a.executed and b.executed and not b.replayed


def test_client_supplied_key_wins_over_content(gk, token):
    a = gk.handle(token, ActionRequest(op="create_order", args={"amount": 100},
                                       idempotency_key="k1"), now=T)
    b = gk.handle(token, ActionRequest(op="create_order", args={"amount": 999},
                                       idempotency_key="k1"), now=T)
    assert a.executed and b.replayed


def test_a_concurrent_retry_storm_executes_exactly_once(gk, token):
    """The retry storm test above fires sequentially. A real one does not.

    Twelve threads through the old code produced seven backend calls, six
    'executed' responses, zero replays, and Rs 2,800 moved through a Rs 2,000
    ceiling -- `idem.get -> backend.call -> idem.put` is an unguarded
    read-modify-write and FastAPI runs sync endpoints on a threadpool. Worse,
    the `commit()` that raised 'database is locked' runs AFTER the money has
    moved, so those calls left no audit record at all.

    README, ARCHITECTURE and THREAT_MODEL all claimed a retry storm could not
    get past idempotency. See ADR-019.
    """
    import threading

    class Slow:
        name = "slow"

        def __init__(self):
            self.calls = 0
            self._lock = threading.Lock()

        def call(self, op, args):
            with self._lock:
                self.calls += 1
            time.sleep(0.01)      # widen the race the old code lost
            return {"id": "rfnd_X", "amount": args.get("amount")}

    gk.backend = Slow()
    errors: list[str] = []

    def fire():
        try:
            gk.handle(token, ActionRequest(
                op="create_refund",
                args={"amount": 40000, "customer_id": "cust_demo_001"},
                idempotency_key="retry-storm"), now=T)
        except Exception as e:                      # noqa: BLE001
            errors.append(repr(e))

    threads = [threading.Thread(target=fire) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    assert gk.backend.calls == 1, f"backend called {gk.backend.calls} times, not once"
    assert len(list(gk.audit.rows())) == 12, "a concurrent call left no audit record"
    assert gk.audit.window_sum_paise("test-agent", 600, now=T,
                                     effect="irreversible_money") == 40000
    assert gk.audit.verify().ok
