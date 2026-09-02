"""The trust boundary.

READ THIS FIRST if you are reviewing the repo. The claim the whole project
rests on is that the agent cannot bypass the proxy, and it cannot bypass the
proxy because it has no credential to bypass it WITH.

These tests are a guard rail against the most likely way that claim quietly
becomes false: someone hard-codes a key 'just to debug something'.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# A real key, not the mere mention of one. Docstrings are allowed to explain
# what the agent must not do; code is not allowed to do it.
KEY_RE = re.compile(r"rzp_(?:test|live)_[A-Za-z0-9]{10,}")
ENV_READ_RE = re.compile(r"environ\s*(?:\.get\s*\(|\[)\s*[\"']RAZORPAY_KEY")


def test_agent_package_never_reads_or_embeds_razorpay_credentials():
    for py in (ROOT / "agent").rglob("*.py"):
        text = py.read_text()
        assert not ENV_READ_RE.search(text), (
            f"{py.relative_to(ROOT)} reads a Razorpay credential from the environment. "
            "The agent must never hold one -- that is the entire security claim. "
            "Route the call through the proxy instead."
        )
        assert not KEY_RE.search(text), f"{py.relative_to(ROOT)} embeds an API key."


def test_only_the_backend_module_reads_razorpay_credentials():
    offenders = []
    for py in (ROOT / "gatekeeper").rglob("*.py"):
        if py.name == "backends.py":
            continue
        if ENV_READ_RE.search(py.read_text()):
            offenders.append(py.relative_to(ROOT))
    assert not offenders, (
        f"Razorpay credentials are read outside gatekeeper/backends.py: {offenders}. "
        "Keep credential handling in exactly one place so it can be audited in "
        "one place."
    )


def test_no_live_key_is_committed_anywhere():
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts \
                or path.suffix in (".db", ".png", ".pyc"):
            continue
        if path.name in ("test_no_secrets_in_agent.py", ".env"):
            continue
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        # A test key is still a secret: it can create real orders on a real
        # (test-mode) account and it identifies the account. Never commit one.
        found = KEY_RE.search(text)
        assert not found, (
            f"{path.relative_to(ROOT)} contains what looks like a Razorpay key "
            f"({found.group()[:14]}...). Move it to .env, which is gitignored."
        )
