import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
DATABASE_PATH = os.path.join(INSTANCE_DIR, "scans.db")


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    final_url TEXT,
    status_code INTEGER,
    score INTEGER,
    rating TEXT,
    finding_count INTEGER,
    scan_date TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    category TEXT,
    severity TEXT,
    description TEXT,
    evidence TEXT,
    recommendation TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
"""


def _get_connection() -> sqlite3.Connection:
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    """Create the local database directory and tables if needed."""
    with _get_connection() as connection:
        connection.executescript(SCHEMA)


def save_scan(
    target_url: str,
    final_url: Optional[str] = None,
    status_code: Optional[int] = None,
    score: Optional[int] = None,
    rating: Optional[str] = None,
    finding_count: int = 0,
    scan_date: Optional[str] = None,
) -> int:
    scan_date = scan_date or datetime.now(timezone.utc).isoformat()

    with _get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                target_url, final_url, status_code, score, rating, finding_count, scan_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (target_url, final_url, status_code, score, rating, finding_count, scan_date),
        )
        return int(cursor.lastrowid)


def save_findings(scan_id: int, findings: Iterable[Dict[str, Any]]) -> None:
    finding_rows = [
        (
            scan_id,
            finding.get("title", ""),
            finding.get("category"),
            finding.get("severity"),
            finding.get("description"),
            finding.get("evidence"),
            finding.get("recommendation"),
        )
        for finding in findings
    ]

    if not finding_rows:
        return

    with _get_connection() as connection:
        connection.executemany(
            """
            INSERT INTO findings (
                scan_id, title, category, severity, description, evidence, recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            finding_rows,
        )


def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    limit = max(0, int(limit))
    if limit == 0:
        return []

    with _get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def get_dashboard_stats() -> Dict[str, Any]:
    with _get_connection() as connection:
        scan_stats = connection.execute(
            """
            SELECT COUNT(*) AS total_scans, AVG(score) AS average_score
            FROM scans
            """
        ).fetchone()
        finding_stats = connection.execute(
            """
            SELECT
                SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) AS high_findings,
                SUM(CASE WHEN LOWER(severity) = 'medium' THEN 1 ELSE 0 END) AS medium_findings
            FROM findings
            """
        ).fetchone()

        return {
            "total_scans": scan_stats["total_scans"] or 0,
            "average_score": round(scan_stats["average_score"], 1)
            if scan_stats["average_score"] is not None
            else None,
            "high_findings": finding_stats["high_findings"] or 0,
            "medium_findings": finding_stats["medium_findings"] or 0,
        }


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    with _get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None


def get_findings_by_scan_id(scan_id: int) -> List[Dict[str, Any]]:
    with _get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
        return [dict(row) for row in rows]


def delete_scan(scan_id: int) -> bool:
    with _get_connection() as connection:
        scan = connection.execute(
            "SELECT id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if not scan:
            return False

        connection.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return True


def clear_scan_history() -> int:
    with _get_connection() as connection:
        scan_count = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        connection.execute("DELETE FROM findings")
        connection.execute("DELETE FROM scans")
        return int(scan_count)


__all__ = [
    "DATABASE_PATH",
    "clear_scan_history",
    "delete_scan",
    "get_findings_by_scan_id",
    "get_dashboard_stats",
    "get_recent_scans",
    "get_scan_by_id",
    "init_db",
    "save_findings",
    "save_scan",
]
