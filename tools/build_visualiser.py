#!/usr/bin/env python3
"""Regenerate the data blocks inside visualiser.html and pitch.html.

The page is not a mockup. Every verdict, explanation, rule id, amount and
audit hash it displays comes from actually executing demo.py's agent plan
through the proxy, here, now. Run this and the page updates:

    make visualiser

This exists because of what went wrong everywhere else in this project: a
hand-written figure in a document drifts away from the code and nobody
notices for a week. The README's demo transcript was wrong twice. A page
whose numbers are typed in by hand would be wrong a third time, and it is
the artifact most likely to be looked at and least likely to be re-checked.

The generator writes ONLY the contents of <script id="trace"> in each page.
Everything else in both files is hand-authored and left alone.

pitch.html additionally carries the LIVE run, read out of gatekeeper-live.db
if `make live` has been run. That database is gitignored, so on a fresh clone
the run sheet says plainly that no live run is recorded rather than showing a
transcript nobody produced.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from demo import (ACT_TITLES, AGENT_PLAN, MOVES_MONEY, SECRET,  # noqa: E402
                  timestamp_for, tokens_for)
from gatekeeper.audit import AuditLog  # noqa: E402
from gatekeeper.backends import MockBackend  # noqa: E402
from gatekeeper.console import use_utf8_stdout  # noqa: E402
from gatekeeper.models import ActionRequest  # noqa: E402
from gatekeeper.proxy import Gatekeeper  # noqa: E402


# Which lifecycle stage actually decided. Derived from the rule ids the proxy
# records rather than from a new field, so the page cannot claim a stage the
# audit log does not support.
STAGE_BY_RULE = {
    "AUTH-001": 1,      # capability token failed to verify
    "SCOPE-000": 2,     # operation outside the grant
    "GRANT-001": 5,     # the grant's own ceilings
    "INTERNAL-001": 0,  # fail-closed on an internal error
}

STAGES = [
    {"n": 1, "name": "Verify token",
     "what": "Is this agent who it says it is?",
     "detail": "HMAC over the capability, compared in constant time, with a short "
               "expiry. Not a JWT: one issuer, one verifier, one algorithm, and no "
               "algorithm-confusion footguns to inherit."},
    {"n": 2, "name": "Check scope",
     "what": "Was it granted this operation at all?",
     "detail": "An exact-match test against the operation list inside the token. "
               "Cheap, and it keeps “you were never given this” a different "
               "sentence from “you were given this, but not right now”."},
    {"n": 3, "name": "Classify effect",
     "what": "How dangerous is this operation?",
     "detail": "read / reversible_write / irreversible_money, looked up in "
               "policies/effects.yaml. An operation that is not listed has no "
               "effect class, and the next stage denies it. Registering a new tool "
               "therefore cannot quietly widen what an agent can do."},
    {"n": 4, "name": "Evaluate policy",
     "what": "Caps, velocity, destination, hours.",
     # {rules} is filled in from the policy file at generation time. It said
     # "14" for as long as there have been 15, in the one hand-typed number
     # inside a generator whose whole reason for existing is that hand-typed
     # numbers drift. len() was eight lines away the entire time.
     "detail": "{rules} rules of YAML over a fixed vocabulary of typed conditions. "
               "Every rule cites a threat id. A single deny beats any number of "
               "allows, and a request no rule covers is denied rather than "
               "assumed safe."},
    {"n": 5, "name": "Apply the grant’s own ceilings",
     "what": "A capability may only ever narrow policy further.",
     "detail": "The token carries its own per-action and per-window limits. This "
               "runs after policy, not before: the default grant mirrors the "
               "default policy numbers, so checking it first would shadow every "
               "rule and every denial would read “your capability caps this” "
               "instead of naming the rule and the threat behind it."},
    {"n": 6, "name": "Idempotency",
     "what": "Have we already done exactly this?",
     "detail": "A key derived from the request content, checked BEFORE execution, "
               "under a lock. After execution, a retry storm has already charged "
               "the customer twenty times and the cache only stops the "
               "twenty-first."},
    {"n": 7, "name": "Execute",
     "what": "Only now does anything move.",
     "detail": "The proxy holds the payment credential. The agent never has one, "
               "which is the entire architecture in one sentence: a proxy the "
               "agent can bypass enforces nothing."},
    {"n": 8, "name": "Append to the audit chain",
     "what": "Always — including on a denial.",
     "detail": "Each record stores the hash of the one before it. A log that "
               "records only what it allowed cannot tell you what it stopped, "
               "which is the half a merchant actually wants to read."},
]


def _stage_of(res, audit_rules: list[str]) -> int:
    """Which stage produced this verdict.

    `audit_rules` comes from the audit row, not from `decision.hits`. The
    proxy's own rejections at stages 1, 2 and 5 never reach the policy
    engine, so they produce no hits at all -- reading only `hits` labelled
    every one of them "stage 4, policy", which is a stage the audit log does
    not support. The whole point of this page is that it cannot say things
    the log does not.
    """
    for r in audit_rules:
        if r in STAGE_BY_RULE:
            return STAGE_BY_RULE[r]
    if res.replayed:
        return 6
    if res.decision.verdict.value != "allow":
        # SCOPE-001 is a policy rule, but what it reacts to is stage 3 finding
        # no classification at all. Attribute it where the cause is.
        return 3 if "SCOPE-001" in audit_rules else 4
    return 7 if res.executed else 8


def live_run() -> list[dict] | None:
    """The last live run against real Razorpay, straight from its audit log.

    Not retyped into the page. The run sheet quotes real object ids in front
    of a judge, and a hand-copied transcript is one refactor away from quoting
    ids that never existed.
    """
    db = ROOT / "gatekeeper-live.db"
    if not db.exists():
        return None
    log = AuditLog(str(db))
    out = []
    for r in log.rows():
        payload = json.loads(r["payload"] or "{}")
        out.append({
            "op": r["op"],
            "verdict": r["verdict"],
            "amount_paise": r["amount_paise"],
            # The real Razorpay id, when the call actually executed.
            "ref": payload.get("result_id") or "",
            "explanation": " ".join((r["explanation"] or "").split()),
        })
    log.close()
    return out


def run() -> dict:
    use_utf8_stdout()

    # ---- run 1: nothing in the way -------------------------------------
    ungoverned, moved = [], 0
    backend = MockBackend()
    for a in AGENT_PLAN:
        try:
            result = backend.call(a.op, a.args)
            amt = int(result.get("amount") or 0)
            delta = amt if a.op in MOVES_MONEY else 0
            moved += delta
            ungoverned.append({"op": a.op, "amount_paise": amt, "executed": True,
                               "moved_paise": delta, "running_paise": moved,
                               "error": None})
        except Exception as e:                                    # noqa: BLE001
            ungoverned.append({"op": a.op, "amount_paise": 0, "executed": False,
                               "moved_paise": 0, "running_paise": moved,
                               "error": str(e)})

    # ---- run 2: the same agent, behind the proxy ------------------------
    db = tempfile.mktemp(suffix=".db")
    gk = Gatekeeper(backend=MockBackend(), db_path=db, signing_secret=SECRET)
    tokens = tokens_for(AGENT_PLAN)

    results, moved2 = [], 0
    for i, a in enumerate(AGENT_PLAN):
        req = ActionRequest(op=a.op, args=a.args)
        res = gk.handle(tokens[a.token], req, now=timestamp_for(i, a))
        amt = req.amount_paise
        delta = amt if (res.executed and a.op in MOVES_MONEY) else 0
        moved2 += delta
        results.append((a, req, res, amt, delta, moved2))

    rows = list(gk.audit.rows())
    by_seq = {r["seq"]: [x for x in (r["rule_ids"] or "").split(",") if x]
              for r in rows}
    expl_by_seq = {r["seq"]: " ".join((r["explanation"] or "").split()) for r in rows}

    _raw = yaml.safe_load((ROOT / "policies/default.yaml").read_text(encoding="utf-8"))
    RULE_THREAT = {r["id"]: str(r.get("threat", "")) for r in _raw["rules"]}
    RULE_THREAT["SCOPE-000"] = "T3"    # the proxy's own scope check
    RULE_THREAT["GRANT-001"] = "T3"    # the grant's own ceilings
    RULE_THREAT["AUTH-001"] = "T3"

    governed = []
    for a, req, res, amt, delta, running in results:
        audit_rules = by_seq.get(res.audit_seq, [])
        governed.append({
            "op": a.op,
            "amount_paise": amt,
            "counterparty": req.counterparty,
            "args": {k: str(v) for k, v in a.args.items() if k != "notes"},
            "thought": a.thought,
            "act": a.act,
            "act_title": ACT_TITLES[a.act],
            "token": a.token,
            "hour": a.hour,
            "verdict": res.decision.verdict.value,
            "executed": res.executed,
            "replayed": res.replayed,
            "stage": _stage_of(res, audit_rules),
            "rules": audit_rules,
            # From the rules map, not from decision.hits: a rejection at stage
            # 1, 2 or 5 never reaches the policy engine and so carries no hits,
            # which left the proxy's own controls looking threat-less.
            "threats": sorted({RULE_THREAT[r] for r in audit_rules
                               if RULE_THREAT.get(r, "").startswith("T")}),
            # On a replay, decision.explanation still holds the POLICY reason
            # ("allowed, within the per-action limit"), which reads as though
            # the money moved a second time. The audit row carries what
            # actually happened, so prefer it.
            "explanation": (expl_by_seq.get(res.audit_seq)
                            if res.replayed
                            else " ".join(res.decision.explanation.split())),
            "moved_paise": delta,
            "running_paise": running,
            "audit_seq": res.audit_seq,
        })

    audit = [{"seq": r["seq"], "op": r["op"], "verdict": r["verdict"],
              "effect": r["effect"], "amount_paise": r["amount_paise"],
              "rule_ids": r["rule_ids"], "executed": bool(r["executed"]),
              "hash": r["hash"][:12], "prev_hash": r["prev_hash"][:12],
              "explanation": " ".join((r["explanation"] or "").split())}
             for r in rows]
    chain = gk.audit.verify()
    held = gk.audit.pending_approvals()
    gk.close()

    # ---- the rules, so the page can explain whichever one fired ---------
    raw = yaml.safe_load((ROOT / "policies/default.yaml").read_text(encoding="utf-8"))
    n_policy_rules = len(raw["rules"])   # before the two synthetic entries below
    rules = {r["id"]: {"threat": str(r.get("threat", "")),
                       "description": " ".join(str(r.get("description", "")).split()),
                       "action": r["action"]}
             for r in raw["rules"]}
    rules["SCOPE-000"] = {
        "threat": "T3", "action": "deny",
        "description": "Not a policy rule. The proxy's own scope check at stage 2: "
                       "the capability token never listed this operation."}
    rules["GRANT-001"] = {
        "threat": "T3", "action": "deny",
        "description": "Not a policy rule. The grant's own ceilings at stage 5, "
                       "which may only ever be narrower than merchant policy."}

    # ---- the measured numbers, straight out of the eval -----------------
    ev = json.loads((ROOT / "eval_results.json").read_text(encoding="utf-8"))

    # len(rules), not len(policy rules): the map below is augmented with
    # SCOPE-000 and GRANT-001 so the page can explain the proxy's own checks,
    # and counting those as policy rules overstates the file by two.
    stages = [dict(st, detail=st["detail"].format(rules=n_policy_rules))
              for st in STAGES]

    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "stages": stages,
        "rules": rules,
        "ungoverned": ungoverned,
        "governed": governed,
        "audit": audit,
        "chain_ok": chain.ok,
        "chain_len": chain.checked,
        "held_count": len(held),
        "totals": {"ungoverned_paise": moved, "governed_paise": moved2},
        "live": live_run(),
        "eval": {
            "block_rate": ev["attack"]["block_rate"],
            "blocked": ev["attack"]["blocked"],
            "blocking_calls": ev["attack"]["blocking_calls"],
            "attack_total": ev["attack"]["total"],
            "false_block_rate": ev["benign"]["false_block_rate"],
            "benign_wrongly_blocked": ev["benign"]["total"] - ev["benign"]["correct"],
            "benign_total": ev["benign"]["total"],
            # Score only. The per-call miss detail is in the README prose;
            # nothing on this page renders it, and baking the sealed set's
            # internals into a shipped HTML file serves no one.
            "holdout": ({k: v for k, v in ev["holdout"].items() if k != "misses"}
                        if ev.get("holdout") else None),
            "p50": ev["latency_ms"]["p50"],
            "p95": ev["latency_ms"]["p95"],
            "baseline": ev["baseline_deny_all"],
        },
    }


def _inject(page: pathlib.Path, data: str) -> bool:
    if not page.exists():
        print(f"FATAL: {page} does not exist. This script fills in a data "
              f"block; it does not create the page.", file=sys.stderr)
        return False
    new, n = re.subn(
        r'(<script id="trace" type="application/json">).*?(</script>)',
        lambda m: m.group(1) + "\n" + data + "\n" + m.group(2),
        page.read_text(encoding="utf-8"), count=1, flags=re.S)
    if n != 1:
        print(f'FATAL: no <script id="trace"> in {page.name}', file=sys.stderr)
        return False
    page.write_text(new, encoding="utf-8")
    print(f"  {page.name:<18} {len(data):>7,} bytes")
    return True


def main() -> int:
    payload = run()
    full = json.dumps(payload, indent=1, ensure_ascii=False)

    # The run sheet needs the headline figures and the live transcript, not
    # the 22-action trace or the stage prose. Sending it everything would
    # double the page for nothing.
    slim = json.dumps({
        "generated": payload["generated"],
        "governed": [{"verdict": g["verdict"], "executed": g["executed"],
                      "replayed": g["replayed"]} for g in payload["governed"]],
        "totals": payload["totals"],
        "eval": payload["eval"],
        "live": payload["live"],
    }, indent=1, ensure_ascii=False)

    print("regenerated from a live run:")
    ok = _inject(ROOT / "visualiser.html", full)
    ok = _inject(ROOT / "pitch.html", slim) and ok
    n_live = len(payload["live"] or [])
    print(f"  live run           {n_live or 'none recorded'}"
          f"{' record(s) from gatekeeper-live.db' if n_live else ''}")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
