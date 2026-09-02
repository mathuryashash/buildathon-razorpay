"""Hash-chained, append-only audit log.

Each record stores the hash of the previous record, so any edit to history
breaks every hash after it. `gatekeeper verify` walks the chain and reports the
first sequence number where the chain breaks.

This is deliberately NOT a blockchain and makes no distributed-consensus
claim. It is a tamper-EVIDENT local log: it does not stop someone with write
access from rewriting the file, it makes the rewrite detectable.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    agent_id    TEXT    NOT NULL,
    op          TEXT    NOT NULL,
    effect      TEXT,
    verdict     TEXT    NOT NULL,
    amount_paise INTEGER NOT NULL DEFAULT 0,
    counterparty TEXT,
    rule_ids    TEXT    NOT NULL DEFAULT '',
    explanation TEXT    NOT NULL DEFAULT '',
    executed    INTEGER NOT NULL DEFAULT 0,
    payload     TEXT    NOT NULL DEFAULT '{}',
    prev_hash   TEXT    NOT NULL,
    hash        TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_agent_ts ON audit(agent_id, ts);
"""


def _canonical(d: dict[str, Any]) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), default=str)


def record_hash(fields: dict[str, Any], prev_hash: str) -> str:
    return hashlib.sha256((_canonical(fields) + prev_hash).encode()).hexdigest()


@dataclass
class ChainCheck:
    ok: bool
    checked: int
    broken_at: int | None = None
    reason: str | None = None


class AuditLog:
    def __init__(self, path: Path | str = "gatekeeper.db"):
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def _last_hash(self) -> str:
        row = self._conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hash"] if row else GENESIS

    def append(
        self,
        *,
        agent_id: str,
        op: str,
        effect: str | None,
        verdict: str,
        amount_paise: int = 0,
        counterparty: str | None = None,
        rule_ids: list[str] | None = None,
        explanation: str = "",
        executed: bool = False,
        payload: dict[str, Any] | None = None,
        ts: float | None = None,
    ) -> int:
        prev = self._last_hash()
        fields = {
            "ts": ts if ts is not None else time.time(),
            "agent_id": agent_id,
            "op": op,
            "effect": effect,
            "verdict": verdict,
            "amount_paise": int(amount_paise),
            "counterparty": counterparty,
            "rule_ids": ",".join(rule_ids or []),
            "explanation": explanation,
            "executed": int(executed),
            "payload": _canonical(payload or {}),
        }
        h = record_hash(fields, prev)
        cur = self._conn.execute(
            "INSERT INTO audit (ts,agent_id,op,effect,verdict,amount_paise,counterparty,"
            "rule_ids,explanation,executed,payload,prev_hash,hash) "
            "VALUES (:ts,:agent_id,:op,:effect,:verdict,:amount_paise,:counterparty,"
            ":rule_ids,:explanation,:executed,:payload,:prev,:hash)",
            {**fields, "prev": prev, "hash": h},
        )
        self._conn.commit()
        return int(cur.lastrowid)

    # -- read side -------------------------------------------------------

    def rows(self) -> Iterator[sqlite3.Row]:
        yield from self._conn.execute("SELECT * FROM audit ORDER BY seq ASC")

    def window_sum_paise(self, agent_id: str, seconds: int, *, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        row = self._conn.execute(
            "SELECT COALESCE(SUM(amount_paise),0) AS s FROM audit "
            "WHERE agent_id=? AND executed=1 AND ts >= ?",
            (agent_id, now - seconds),
        ).fetchone()
        return int(row["s"])

    def window_count(
        self,
        agent_id: str,
        seconds: int,
        *,
        counterparty: str | None = None,
        effect: str | None = None,
        now: float | None = None,
    ) -> int:
        """Count executed actions in the window.

        `effect` matters: a rule that says "5 payments in 10 minutes" must
        count payments, not every action the agent took. Counting reads and
        order creations toward a payment limit produces an explanation that is
        literally false, and a false explanation is worse than no explanation.
        """
        now = now if now is not None else time.time()
        q = "SELECT COUNT(*) AS c FROM audit WHERE agent_id=? AND executed=1 AND ts >= ?"
        params: list[Any] = [agent_id, now - seconds]
        if counterparty:
            q += " AND counterparty=?"
            params.append(counterparty)
        if effect:
            q += " AND effect=?"
            params.append(effect)
        return int(self._conn.execute(q, params).fetchone()["c"])

    def verify(self) -> ChainCheck:
        prev = GENESIS
        n = 0
        for r in self.rows():
            n += 1
            fields = {
                "ts": r["ts"],
                "agent_id": r["agent_id"],
                "op": r["op"],
                "effect": r["effect"],
                "verdict": r["verdict"],
                "amount_paise": r["amount_paise"],
                "counterparty": r["counterparty"],
                "rule_ids": r["rule_ids"],
                "explanation": r["explanation"],
                "executed": r["executed"],
                "payload": r["payload"],
            }
            if r["prev_hash"] != prev:
                return ChainCheck(False, n, r["seq"], "prev_hash does not match previous record")
            if record_hash(fields, prev) != r["hash"]:
                return ChainCheck(False, n, r["seq"], "record content does not match its hash")
            prev = r["hash"]
        return ChainCheck(True, n)
