"""Scoped capability tokens.

THE CENTRAL ARCHITECTURAL CLAIM OF THIS PROJECT LIVES HERE.

The agent never receives Razorpay credentials. It receives one of these: an
HMAC-signed grant naming the operations it may request, the caps it is subject
to, and an expiry. It presents the token to the proxy; the proxy holds the
real key and makes the real call.

Why this matters: a proxy the agent can bypass enforces nothing. If the agent
process has RAZORPAY_KEY_SECRET in its environment, every rule in
policies/default.yaml is a suggestion. tests/test_no_secrets_in_agent.py
asserts this boundary holds, and it is the first test to read.

This is intentionally NOT JWT. A JWT library brings algorithm-confusion
footguns (alg:none, RS/HS confusion) for zero benefit here, because there is
exactly one issuer, one verifier, and one algorithm. See docs/DO_NOT_BUILD.md.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from .models import Capability


class TokenError(Exception):
    pass


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(
    agent_id: str,
    scopes: list[str],
    *,
    secret: str,
    max_action_paise: int = 50_000,
    max_window_paise: int = 200_000,
    window_seconds: int = 600,
    ttl_seconds: int = 900,
    now: float | None = None,
) -> str:
    # `now` is injectable so the eval harness can issue tokens against its own
    # simulated clock. Never pass it from production code.
    cap = Capability(
        agent_id=agent_id,
        scopes=scopes,
        max_action_paise=max_action_paise,
        max_window_paise=max_window_paise,
        window_seconds=window_seconds,
        exp=int(now if now is not None else time.time()) + ttl_seconds,
        nonce=secrets.token_hex(8),
    )
    body = _b64e(cap.model_dump_json().encode())
    sig = _b64e(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify(token: str, *, secret: str, now: float | None = None) -> Capability:
    try:
        body, sig = token.split(".", 1)
    except ValueError as e:
        raise TokenError("malformed capability token") from e

    expected = _b64e(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    # Constant-time compare: a timing oracle on the signature would let an
    # attacker forge a capability byte by byte.
    if not hmac.compare_digest(sig, expected):
        raise TokenError("bad signature on capability token")

    cap = Capability(**json.loads(_b64d(body)))
    if cap.exp < (now if now is not None else time.time()):
        raise TokenError("capability token expired")
    return cap


def proxy_secret() -> str:
    """The signing secret. Distinct from the Razorpay key -- rotating one must
    not require rotating the other."""
    s = os.environ.get("GATEKEEPER_SIGNING_SECRET")
    if not s:
        raise TokenError(
            "GATEKEEPER_SIGNING_SECRET is not set. Copy .env.example to .env "
            "and fill it in. The proxy refuses to start without a signing secret "
            "rather than falling back to a default one."
        )
    return s
