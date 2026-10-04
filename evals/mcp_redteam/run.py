"""Run the MCP red-team corpus through the Gatekeeper MCP server.

    python evals/mcp_redteam/run.py [--min-block-rate 1.0] [--max-false-block-rate 0.0]

Every call goes through a real MCP client session (mcp.client.Client) to the
MCPServer built by gatekeeper.mcp_server.build_server -- tool lookup, JSON
schema validation, the tool function, Gatekeeper.handle(), the hash-chained
audit write and back. The transport is the SDK's in-memory transport so the
clock can be injected per call and every scenario gets a fresh database; the
same server over real stdio is covered by tests/test_mcp_stdio.py.

What counts as "blocked" (did not execute unattended):
    denied | pending_approval      policy said no / a human must say yes
    replayed                       idempotency returned the earlier result,
                                   nothing new moved
    schema_rejected                the MCP layer refused the arguments
    unknown_tool                   the tool does not exist on this server

Writes results JSON + a markdown table. Exits 1 if the attack block rate is
below --min-block-rate, ANY attack call not tagged `known_gap` gets through, the benign false-block rate is above
--max-false-block-rate, or any attack setup step failed to execute (a
scenario whose precondition never happened is not testing anything).
"""
from __future__ import annotations

import argparse
import base64
import json
import shutil
import statistics
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import anyio

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from mcp.client import Client  # noqa: E402

from gatekeeper.backends import MockBackend  # noqa: E402
from gatekeeper.console import use_utf8_stdout  # noqa: E402
from gatekeeper.mcp_server import TOOL_OPS, build_server  # noqa: E402
from gatekeeper.proxy import Gatekeeper  # noqa: E402
from gatekeeper.tokens import issue  # noqa: E402

HERE = Path(__file__).resolve().parent
SECRET = "mcp-redteam-signing-secret-not-a-real-one"
BASE_TS = datetime(2026, 9, 4, 14, 0, 0).timestamp()    # a Friday, 14:00 local


def _tamper(tok: str, **changes: Any) -> str:
    body, sig = tok.split(".", 1)
    cap = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    cap.update(changes)
    nb = base64.urlsafe_b64encode(json.dumps(cap).encode()).decode().rstrip("=")
    return f"{nb}.{sig}"


def make_token(kind: str | None) -> str:
    def iss(scopes=TOOL_OPS, secret=SECRET, ttl=86_400, **kw):
        return issue("mcp-redteam", list(scopes), secret=secret, ttl_seconds=ttl, now=BASE_TS, **kw)
    good = iss()
    return {
        None: good,
        "links_only": iss(["create_payment_link", "fetch_payment"]),
        "read_only": iss(["fetch_payment"]),
        "narrow": iss(max_action_paise=10_000, max_window_paise=25_000),
        "short_ttl": iss(ttl=3600),
        "forged": good[:-4] + "AAAA",
        "expired": iss(ttl=-10),
        "wrong_secret": iss(secret="guessed-secret"),
        "tampered_caps": _tamper(good, max_action_paise=10**12, max_window_paise=10**12),
        "tampered_scopes": _tamper(iss(["fetch_payment"]), scopes=TOOL_OPS + ["create_payout"]),
        "empty": "",
        "alg_none": "eyJhbGciOiJub25lIn0." + good.split(".")[0] + ".",
        "nonascii": good[:-2] + "é\u00ff",
        "garbage": "not-a-token",
        "truncated": good[:24],
    }[kind]


def classify(res) -> tuple[str, str]:
    """-> (outcome, detail). outcome in executed|blocked|error."""
    sc = res.structured_content
    if isinstance(sc, dict) and "status" in sc:
        st = sc["status"]
        if st in ("executed", "dry_run"):
            return "executed", "executed"
        if st == "replayed":
            return "blocked", "IDEMPOTENT-REPLAY"
        if st in ("denied", "pending_approval"):
            return "blocked", f"{st}:{sc.get('rule_id')}"
        return "error", st
    text = res.content[0].text if res.content else ""
    if res.is_error:
        if text.startswith("Unknown tool"):
            return "blocked", "UNKNOWN-TOOL"
        if "validation error" in text:
            return "blocked", "SCHEMA-REJECTED"
        return "error", text[:120]
    # read tools (check_budget, list_my_decisions) return plain dicts
    return "executed", "read"


async def run_scenario(sc: dict[str, Any], dbdir: Path) -> list[dict[str, Any]]:
    db = str(dbdir / f"{sc['id']}.db")
    gk = Gatekeeper(backend=MockBackend(), db_path=db, signing_secret=SECRET)
    token = make_token(sc.get("session_token"))
    clock = {"t": BASE_TS}
    server = build_server(gk, lambda: token, lambda: clock["t"])
    out = []
    try:
        async with Client(server, raise_exceptions=False) as c:
            for i, step in enumerate(sc["steps"]):
                clock["t"] += 5 + step.get("advance_s", 0)
                if "hour" in step:
                    clock["t"] = datetime(2026, 9, 4, step["hour"], 30, 0).timestamp() + i
                t0 = time.perf_counter()
                res = await c.call_tool(step["tool"], step["args"])
                ms = (time.perf_counter() - t0) * 1000
                outcome, detail = classify(res)
                exp = step["expect"]
                ok = (outcome == "blocked") if exp == "block" else (outcome == "executed")
                out.append({"scenario": sc["id"], "category": sc["category"], "step": i,
                            "tool": step["tool"], "expect": exp, "outcome": outcome,
                            "detail": detail, "ok": ok, "latency_ms": ms,
                            "owasp": sc.get("owasp"), "known_gap": sc.get("known_gap")})
    finally:
        gk.close()
    return out


def run_corpus(path: Path) -> list[dict[str, Any]]:
    scenarios = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    tmp = Path(tempfile.mkdtemp(prefix="gk-mcp-redteam-"))
    rows: list[dict[str, Any]] = []
    try:
        for sc in scenarios:
            rows += anyio.run(run_scenario, sc, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return rows


def pct(xs: list[float], q: float) -> float:
    s = sorted(xs)
    return s[max(0, int(round(q * len(s))) - 1)] if s else 0.0


def summarise(attacks: list[dict], benign: list[dict]) -> dict[str, Any]:
    cats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    scen_ok: dict[str, bool] = {}
    for r in attacks:
        c = cats[r["category"]]
        if r["expect"] == "block":
            c["block_steps"] += 1
            c["blocked"] += int(r["ok"])
            scen_ok[r["scenario"]] = scen_ok.get(r["scenario"], True) and r["ok"]
        else:
            c["setup_steps"] += 1
            c["setup_failed"] += int(not r["ok"])
    for sid, ok in scen_ok.items():
        cat = next(r["category"] for r in attacks if r["scenario"] == sid)
        cats[cat]["scenarios"] += 1
        cats[cat]["scenarios_blocked"] += int(ok)

    bcats: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    b_scen: dict[str, bool] = {}
    for r in benign:
        if r["expect"] != "allow":
            continue
        c = bcats[r["category"]]
        c["allow_steps"] += 1
        c["false_blocked"] += int(not r["ok"])
        b_scen[r["scenario"]] = b_scen.get(r["scenario"], True) and r["ok"]

    blk = sum(c["block_steps"] for c in cats.values())
    blocked = sum(c["blocked"] for c in cats.values())
    allow = sum(c["allow_steps"] for c in bcats.values())
    fb = sum(c["false_blocked"] for c in bcats.values())
    lat = [r["latency_ms"] for r in attacks + benign]
    owasp = defaultdict(lambda: [0, 0])
    for r in attacks:
        if r["owasp"] and r["expect"] == "block":
            owasp[r["owasp"]][0] += int(r["ok"])
            owasp[r["owasp"]][1] += 1
    return {
        "attack": {
            "scenarios": len(scen_ok), "scenarios_fully_blocked": sum(scen_ok.values()),
            "block_steps": blk, "blocked": blocked,
            "block_rate": blocked / blk if blk else 0.0,
            "setup_steps": sum(c["setup_steps"] for c in cats.values()),
            "setup_failed": sum(c["setup_failed"] for c in cats.values()),
            "by_category": {k: dict(v) for k, v in sorted(cats.items())},
            "owasp": {k: {"blocked": v[0], "total": v[1]} for k, v in sorted(owasp.items())},
            "misses": [r for r in attacks if not r["ok"]],
            "known_gap_misses": [r for r in attacks if not r["ok"] and r["known_gap"]],
            "unexpected_misses": [r for r in attacks if not r["ok"] and not r["known_gap"]],
            "known_gap_steps": sum(1 for r in attacks if r["known_gap"] and r["expect"] == "block"),
        },
        "benign": {
            "scenarios": len(b_scen), "scenarios_false_blocked": sum(not v for v in b_scen.values()),
            "allow_steps": allow, "false_blocked": fb,
            "false_block_rate": fb / allow if allow else 0.0,
            "by_category": {k: dict(v) for k, v in sorted(bcats.items())},
            "false_blocks": [r for r in benign if r["expect"] == "allow" and not r["ok"]],
            "expected_blocks_inside_benign_missed": [r for r in benign
                                                    if r["expect"] == "block" and not r["ok"]],
        },
        "latency_ms": {"calls": len(lat), "p50": statistics.median(lat) if lat else 0.0,
                       "p95": pct(lat, 0.95), "max": max(lat) if lat else 0.0},
        "transport": "mcp.client.Client over the SDK in-memory transport (JSON-RPC session, "
                     "schema validation, tool dispatch); stdio covered by tests/test_mcp_stdio.py",
    }


def markdown(s: dict[str, Any]) -> str:
    a, b, lt = s["attack"], s["benign"], s["latency_ms"]
    lines = [
        "# Gatekeeper MCP red-team results", "",
        f"- Attack scenarios: **{a['scenarios']}**, fully blocked: **{a['scenarios_fully_blocked']}**",
        f"- Attack calls that must be blocked: **{a['blocked']}/{a['block_steps']}** "
        f"(block rate **{a['block_rate']:.1%}**); setup steps that failed: {a['setup_failed']}/{a['setup_steps']}",
        f"- Of the misses, **{len(a['known_gap_misses'])}** are documented open gaps (tagged `known_gap` in the "
        f"dataset, listed below) and **{len(a['unexpected_misses'])}** are unexpected",
        f"- Benign scenarios: **{b['scenarios']}**, with any false block: **{b['scenarios_false_blocked']}**",
        f"- Benign calls wrongly blocked: **{b['false_blocked']}/{b['allow_steps']}** "
        f"(false-block rate **{b['false_block_rate']:.1%}**)",
        f"- Latency per MCP tool call (client -> server -> policy -> audit -> client), "
        f"{lt['calls']} calls: p50 **{lt['p50']:.2f} ms**, p95 **{lt['p95']:.2f} ms**", "",
        "| Attack category | Scenarios blocked | Calls blocked | Block rate |",
        "|---|---|---|---|",
    ]
    for k, v in a["by_category"].items():
        lines.append(f"| {k} | {v.get('scenarios_blocked', 0)}/{v.get('scenarios', 0)} | "
                     f"{v.get('blocked', 0)}/{v.get('block_steps', 0)} | "
                     f"{v.get('blocked', 0) / max(1, v.get('block_steps', 0)):.1%} |")
    lines += ["", "| Benign category | Calls | False blocks |", "|---|---|---|"]
    for k, v in b["by_category"].items():
        lines.append(f"| {k} | {v['allow_steps']} | {v['false_blocked']} |")
    if a["owasp"]:
        lines += ["", "| OWASP LLM Top 10 tag | Calls blocked |", "|---|---|"]
        for k, v in a["owasp"].items():
            lines.append(f"| {k} | {v['blocked']}/{v['total']} |")
    if a["misses"]:
        lines += ["", "## Attack misses", ""]
        lines += [f"- `{m['scenario']}` step {m['step']} `{m['tool']}` -> {m['outcome']}"
                  + (f" -- KNOWN GAP: {m['known_gap']}" if m["known_gap"] else " -- UNEXPECTED")
                  for m in a["misses"]]
    if b["false_blocks"]:
        lines += ["", "## Benign false blocks", ""]
        lines += [f"- `{m['scenario']}` step {m['step']} `{m['tool']}` -> {m['detail']}"
                  for m in b["false_blocks"]]
    return "\n".join(lines) + "\n"


def main() -> int:
    use_utf8_stdout()
    # The SDK logs every schema rejection / unknown tool at INFO. Those are the
    # attacks being stopped; the results table already reports them.
    import logging
    logging.getLogger("mcp").setLevel(logging.WARNING)
    ap = argparse.ArgumentParser()
    ap.add_argument("--min-block-rate", type=float, default=0.97)
    ap.add_argument("--max-false-block-rate", type=float, default=0.0)
    ap.add_argument("--out", default=str(HERE / "results"))
    a = ap.parse_args()

    t0 = time.perf_counter()
    attacks = run_corpus(HERE / "attacks.jsonl")
    benign = run_corpus(HERE / "benign.jsonl")
    s = summarise(attacks, benign)
    s["wall_seconds"] = round(time.perf_counter() - t0, 2)
    s["thresholds"] = {"min_block_rate": a.min_block_rate,
                       "max_false_block_rate": a.max_false_block_rate}

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(s, indent=2, default=str), encoding="utf-8")
    (out / "results.md").write_text(markdown(s), encoding="utf-8")
    print(markdown(s))
    print(f"wrote {out / 'results.json'} and {out / 'results.md'} ({s['wall_seconds']} s)")

    fail = []
    if s["attack"]["block_rate"] < a.min_block_rate:
        fail.append(f"attack block rate {s['attack']['block_rate']:.4f} < {a.min_block_rate}")
    if s["benign"]["false_block_rate"] > a.max_false_block_rate:
        fail.append(f"false-block rate {s['benign']['false_block_rate']:.4f} > {a.max_false_block_rate}")
    if s["attack"]["unexpected_misses"]:
        fail.append(f"{len(s['attack']['unexpected_misses'])} attack call(s) not blocked that are "
                    "not documented known gaps")
    if s["attack"]["setup_failed"]:
        fail.append(f"{s['attack']['setup_failed']} attack setup step(s) did not execute")
    if s["benign"]["expected_blocks_inside_benign_missed"]:
        fail.append("a benign scenario's deliberate over-limit step was not blocked")
    for f in fail:
        print("GATE FAILED:", f)
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
