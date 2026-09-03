"""Where a permitted action actually goes.

Two backends, one interface:

  MockBackend      -- deterministic, offline, used by the eval harness. The
                      whole red-team suite runs against this so that results
                      are reproducible and running `make eval` never moves
                      real money or needs a network.
  RazorpayBackend  -- real Razorpay TEST MODE. Used by the live demo.

Why both: the eval needs determinism and 200 runs; the demo needs to show a
real API call. Pretending one backend can do both is how you end up with a
flaky eval or a fake demo.
"""
from __future__ import annotations

import os
import time
from typing import Any, Protocol


class Backend(Protocol):
    name: str

    def call(self, op: str, args: dict[str, Any]) -> dict[str, Any]: ...


class BackendError(Exception):
    pass


class MockBackend:
    """Mirrors Razorpay's response *shapes* so swapping backends changes
    nothing above this line. Deterministic ids so eval output is diffable."""

    name = "mock"

    def __init__(self) -> None:
        self._n = 0

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}_MOCK{self._n:08d}"

    def call(self, op: str, args: dict[str, Any]) -> dict[str, Any]:
        amount = int(args.get("amount", 0))
        if op == "create_order":
            return {"id": self._id("order"), "entity": "order", "amount": amount,
                    "currency": "INR", "status": "created", "receipt": args.get("receipt")}
        if op == "create_payment_link":
            pid = self._id("plink")
            return {"id": pid, "entity": "payment_link", "amount": amount, "currency": "INR",
                    "status": "created", "short_url": f"https://rzp.io/i/{pid[-8:]}"}
        if op == "capture_payment":
            return {"id": args.get("payment_id", self._id("pay")), "entity": "payment",
                    "amount": amount, "status": "captured"}
        if op == "create_refund":
            return {"id": self._id("rfnd"), "entity": "refund", "amount": amount,
                    "payment_id": args.get("payment_id"), "status": "processed"}
        if op == "create_payout":
            return {"id": self._id("pout"), "entity": "payout", "amount": amount, "status": "queued"}
        if op.startswith("fetch_"):
            return {"entity": op.replace("fetch_", ""), "count": 0, "items": []}
        raise BackendError(f"MockBackend has no implementation for {op!r}")


class RazorpayBackend:
    """Real Razorpay test mode.

    Credentials are read from the environment HERE and nowhere else. Nothing
    upstream of this class ever holds them. If you find a key read anywhere
    else in this repo, that is a bug -- open an issue rather than working
    around it.
    """

    name = "razorpay_test"

    def __init__(self, key_id: str | None = None, key_secret: str | None = None):
        import razorpay  # imported lazily so the mock path has no hard dep

        key_id = key_id or os.environ.get("RAZORPAY_KEY_ID", "")
        key_secret = key_secret or os.environ.get("RAZORPAY_KEY_SECRET", "")
        if not key_id or not key_secret:
            raise BackendError(
                "RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are not set. "
                "Copy .env.example to .env and fill them in, or run with --backend mock."
            )
        if not key_id.startswith("rzp_test_"):
            # Refusing live keys is a control, not a convenience. This project
            # has no business holding a production credential.
            raise BackendError(
                f"refusing to start: key id {key_id[:12]}... is not a test key. "
                "Gatekeeper only ever runs against rzp_test_ credentials."
            )
        self._client = razorpay.Client(auth=(key_id, key_secret))
        self._client.set_app_details({"title": "gatekeeper", "version": "0.1.0"})

    def call(self, op: str, args: dict[str, Any]) -> dict[str, Any]:
        c = self._client
        try:
            if op == "create_order":
                return c.order.create({
                    "amount": int(args["amount"]), "currency": "INR",
                    "receipt": args.get("receipt", f"rcpt_{int(time.time())}"),
                    "notes": args.get("notes", {}),
                })
            if op == "create_payment_link":
                return c.payment_link.create({
                    "amount": int(args["amount"]), "currency": "INR",
                    "description": args.get("description", "Gatekeeper demo"),
                    "customer": args.get("customer", {}),
                    "notify": {"sms": False, "email": False},
                    "reminder_enable": False,
                })
            if op == "fetch_payment_link":
                return c.payment_link.fetch(args["payment_link_id"])
            if op == "cancel_payment_link":
                return c.payment_link.cancel(args["payment_link_id"])
            if op == "fetch_order":
                return c.order.fetch(args["order_id"])
            if op == "fetch_payment":
                return c.payment.fetch(args["payment_id"])
            if op == "fetch_all_payments":
                return {"items": c.payment.all({"count": int(args.get("count", 10))}).get("items", [])}
            if op == "capture_payment":
                return c.payment.capture(args["payment_id"], int(args["amount"]))
            if op == "create_refund":
                return c.payment.refund(args["payment_id"], {"amount": int(args["amount"])})
        except Exception as e:  # razorpay raises a family of errors
            raise BackendError(f"razorpay call {op} failed: {e}") from e
        raise BackendError(
            f"{op!r} is not implemented against live Razorpay test mode. "
            "Run it against --backend mock, or implement it here."
        )


def get_backend(name: str) -> Backend:
    if name == "mock":
        return MockBackend()
    if name in ("razorpay", "razorpay_test", "live"):
        return RazorpayBackend()
    raise BackendError(f"unknown backend {name!r} (expected 'mock' or 'razorpay')")
