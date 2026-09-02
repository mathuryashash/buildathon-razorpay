"""Content-addressed idempotency.

The failure this exists to prevent: an agent retries a network timeout and
charges the customer twice. The agent cannot be trusted to send a stable
idempotency key, so the proxy derives one from the request content when the
agent doesn't supply one.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS idem (
    key      TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    op       TEXT NOT NULL,
    ts       REAL NOT NULL,
    result   TEXT NOT NULL
);
"""


def derive_key(agent_id: str, op: str, args: dict[str, Any], client_key: str | None) -> str:
    if client_key:
        basis = f"{agent_id}|{op}|{client_key}"
    else:
        basis = f"{agent_id}|{op}|" + json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(basis.encode()).hexdigest()


class IdempotencyStore:
    def __init__(self, path: Path | str = "gatekeeper.db"):
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get(self, key: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT result FROM idem WHERE key=?", (key,)).fetchone()
        return json.loads(row["result"]) if row else None

    def put(self, key: str, agent_id: str, op: str, result: dict[str, Any]) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO idem (key,agent_id,op,ts,result) VALUES (?,?,?,?,?)",
            (key, agent_id, op, time.time(), json.dumps(result, default=str)),
        )
        self._conn.commit()
