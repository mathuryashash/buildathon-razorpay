"""Command line entry points. `python -m gatekeeper --help`"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .audit import AuditLog
from .backends import get_backend
from .proxy import Gatekeeper, create_app
from .tokens import issue


def _load_dotenv() -> None:
    """Minimal .env loader. Avoids a dependency and, more importantly, makes it
    obvious that credentials come from a gitignored file and nowhere else."""
    from pathlib import Path
    p = Path(".env")
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def main(argv: list[str] | None = None) -> int:
    _load_dotenv()
    ap = argparse.ArgumentParser(prog="gatekeeper", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the proxy")
    s.add_argument("--backend", default="mock", choices=["mock", "razorpay"])
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--db", default="gatekeeper.db")
    s.add_argument("--dry-run", action="store_true",
                   help="evaluate policy and audit, but never call the backend")

    t = sub.add_parser("issue-token", help="mint a scoped capability for an agent")
    t.add_argument("--agent-id", default="buyer-1")
    t.add_argument("--scopes", default="fetch_catalog,fetch_payment,create_order,create_payment_link")
    t.add_argument("--ttl", type=int, default=900)

    v = sub.add_parser("verify", help="check the audit chain for tampering")
    v.add_argument("--db", default="gatekeeper.db")

    l = sub.add_parser("log", help="print the audit trail")
    l.add_argument("--db", default="gatekeeper.db")
    l.add_argument("--limit", type=int, default=30)
    l.add_argument("--json", action="store_true")

    a = ap.parse_args(argv)

    if a.cmd == "serve":
        secret = os.environ.get("GATEKEEPER_SIGNING_SECRET")
        if not secret:
            print("FATAL: GATEKEEPER_SIGNING_SECRET is not set.\n"
                  "       cp .env.example .env and fill it in.\n"
                  "       The proxy refuses to start rather than use a default secret.",
                  file=sys.stderr)
            return 2
        gk = Gatekeeper(backend=get_backend(a.backend), db_path=a.db,
                        signing_secret=secret, dry_run=a.dry_run)
        import uvicorn
        print(f"gatekeeper: backend={gk.backend.name} rules={len(gk.policy.rules)} "
              f"ops={len(gk.effects)} dry_run={a.dry_run}")
        uvicorn.run(create_app(gk), host=a.host, port=a.port, log_level="warning")
        return 0

    if a.cmd == "issue-token":
        secret = os.environ.get("GATEKEEPER_SIGNING_SECRET")
        if not secret:
            print("FATAL: GATEKEEPER_SIGNING_SECRET is not set.", file=sys.stderr)
            return 2
        print(issue(a.agent_id, [x.strip() for x in a.scopes.split(",") if x.strip()],
                    secret=secret, ttl_seconds=a.ttl))
        return 0

    if a.cmd == "verify":
        c = AuditLog(a.db).verify()
        if c.ok:
            print(f"OK  audit chain intact across {c.checked} record(s)")
            return 0
        print(f"FAIL  chain broken at seq {c.broken_at}: {c.reason}", file=sys.stderr)
        return 1

    if a.cmd == "log":
        rows = [dict(r) for r in AuditLog(a.db).rows()][-a.limit:]
        if a.json:
            print(json.dumps(rows, indent=2, default=str))
            return 0
        if not rows:
            print("(audit log is empty)")
            return 0
        print(f"{'seq':>4}  {'verdict':<17} {'op':<22} {'amount':>12}  explanation")
        print("-" * 118)
        for r in rows:
            amt = f"Rs {r['amount_paise']/100:,.2f}" if r["amount_paise"] else "-"
            mark = {"allow": " ", "deny": "x", "require_approval": "?"}.get(r["verdict"], " ")
            print(f"{r['seq']:>4} {mark}{r['verdict']:<17} {r['op']:<22} {amt:>12}  "
                  f"{r['explanation'][:60]}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
