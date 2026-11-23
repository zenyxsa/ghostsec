from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

DEFAULT_DB_PATH = Path(
    os.environ.get(
        "GHOSTSEC_DB_PATH",
        str(Path.home() / ".local" / "share" / "ghostsec" / "ghostsec.db"),
    )
).expanduser()

VALID_STATUSES = {
    "running",
    "completed",
    "no_new_actions",
    "cancelled",
    "failed",
    "max_rounds_reached",
}


def database_path() -> Path:
    return DEFAULT_DB_PATH


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _connect(db_path: str | Path | None = None) -> Iterator[sqlite3.Connection]:
    path = Path(db_path).expanduser() if db_path is not None else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Only enforce directory permissions on GhostSec default storage.
    # Explicit custom paths must not change an existing parent directory.
    if db_path is None:
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass

    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def initialize_database(db_path: str | Path | None = None) -> Path:
    schema = [
        """CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            objective TEXT NOT NULL,
            authorized_targets_json TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'running',
            risk_level TEXT,
            summary TEXT,
            report TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS tool_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            round_number INTEGER NOT NULL,
            tool_name TEXT NOT NULL,
            arguments_json TEXT NOT NULL,
            ok INTEGER NOT NULL CHECK(ok IN (0, 1)),
            result_json TEXT,
            error TEXT,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'unknown',
            port TEXT,
            service TEXT,
            description TEXT,
            evidence TEXT,
            created_at TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS fixes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
            remediation TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'ai',
            created_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_tool_results_session ON tool_results(session_id, round_number)",
        "CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_fixes_session ON fixes(session_id)",
    ]

    path = Path(db_path).expanduser() if db_path is not None else DEFAULT_DB_PATH
    with _connect(path) as conn:
        for statement in schema:
            conn.execute(statement)
    return path


def create_session(
    target: str,
    objective: str,
    authorized_targets: tuple[str, ...],
    db_path: str | Path | None = None,
) -> int:
    if not isinstance(target, str) or not target.strip():
        raise ValueError("A session target is required.")
    if not isinstance(objective, str) or not objective.strip():
        raise ValueError("An assessment objective is required.")
    if not isinstance(authorized_targets, tuple) or not authorized_targets:
        raise ValueError("Authorized targets must be a non-empty tuple.")
    if any(not isinstance(item, str) or not item.strip() for item in authorized_targets):
        raise ValueError("Every authorized target must be a non-empty string.")

    initialize_database(db_path)
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO sessions
               (target, objective, authorized_targets_json, started_at, status)
               VALUES (?, ?, ?, ?, ?)""",
            (target.strip(), objective.strip(), json.dumps(authorized_targets), _now(), "running"),
        )
        return int(cursor.lastrowid)


def record_tool_result(
    session_id: int,
    round_number: int,
    tool_name: str,
    arguments: dict[str, Any],
    ok: bool,
    result: Any = None,
    error: str | None = None,
    db_path: str | Path | None = None,
) -> int:
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be a dictionary.")
    if not isinstance(ok, bool):
        raise ValueError("Tool result status must be boolean.")
    if isinstance(round_number, bool) or not isinstance(round_number, int) or round_number < 1:
        raise ValueError("Round number must be a positive integer.")

    initialize_database(db_path)
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO tool_results
               (session_id, round_number, tool_name, arguments_json, ok,
                result_json, error, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                round_number,
                tool_name,
                json.dumps(arguments, ensure_ascii=False, default=str),
                int(ok),
                json.dumps(result, ensure_ascii=False, default=str) if result is not None else None,
                error,
                _now(),
            ),
        )
        return int(cursor.lastrowid)


def save_finding(
    session_id: int,
    name: str,
    severity: str = "unknown",
    port: str | None = None,
    service: str | None = None,
    description: str | None = None,
    evidence: str | None = None,
    db_path: str | Path | None = None,
) -> int:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Finding name is required.")

    initialize_database(db_path)
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """INSERT INTO findings
               (session_id, name, severity, port, service, description, evidence, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, name.strip(), str(severity or "unknown").lower(),
             port, service, description, evidence, _now()),
        )
        return int(cursor.lastrowid)


def save_fix(
    session_id: int,
    remediation: str,
    finding_id: int | None = None,
    source: str = "ai",
    db_path: str | Path | None = None,
) -> int:
    if not isinstance(remediation, str) or not remediation.strip():
        raise ValueError("Remediation text is required.")

    initialize_database(db_path)
    with _connect(db_path) as conn:
        if finding_id is not None:
            row = conn.execute(
                "SELECT id FROM findings WHERE id = ? AND session_id = ?",
                (finding_id, session_id),
            ).fetchone()
            if row is None:
                raise ValueError("Finding does not belong to this session.")

        cursor = conn.execute(
            """INSERT INTO fixes
               (session_id, finding_id, remediation, source, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (session_id, finding_id, remediation.strip(), source, _now()),
        )
        return int(cursor.lastrowid)


def complete_session(
    session_id: int,
    status: str,
    report: str,
    risk_level: str | None = None,
    summary: str | None = None,
    db_path: str | Path | None = None,
) -> None:
    if status not in VALID_STATUSES:
        raise ValueError("Invalid session status.")

    initialize_database(db_path)
    completed_at = None if status == "running" else _now()
    with _connect(db_path) as conn:
        cursor = conn.execute(
            """UPDATE sessions
               SET status = ?, completed_at = ?, report = ?, risk_level = ?, summary = ?
               WHERE id = ?""",
            (status, completed_at, report, risk_level, summary, session_id),
        )
        if cursor.rowcount != 1:
            raise ValueError("Session not found.")


def list_sessions(
    limit: int = 50,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("Session limit must be between 1 and 500.")

    initialize_database(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT id, target, objective, started_at, completed_at, status, risk_level
               FROM sessions ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]


def get_session(
    session_id: int,
    db_path: str | Path | None = None,
) -> dict[str, Any] | None:
    initialize_database(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM sessions WHERE id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            return None

        session = dict(row)
        session["authorized_targets"] = json.loads(session.pop("authorized_targets_json"))

        tool_rows = conn.execute(
            "SELECT * FROM tool_results WHERE session_id = ? ORDER BY id",
            (session_id,),
        ).fetchall()
        session["tool_results"] = []
        for item in tool_rows:
            record = dict(item)
            record["arguments"] = json.loads(record.pop("arguments_json"))
            raw_result = record.pop("result_json")
            record["result"] = json.loads(raw_result) if raw_result is not None else None
            session["tool_results"].append(record)

        for table in ("findings", "fixes"):
            session[table] = [
                dict(item)
                for item in conn.execute(
                    f"SELECT * FROM {table} WHERE session_id = ? ORDER BY id",
                    (session_id,),
                ).fetchall()
            ]

        return session


def delete_session(session_id: int, db_path: str | Path | None = None) -> None:
    initialize_database(db_path)
    with _connect(db_path) as conn:
        cursor = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        if cursor.rowcount != 1:
            raise ValueError("Session not found.")
