import os
import json
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

CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT,
    path TEXT,
    query_string TEXT,
    http_version TEXT,
    headers_json TEXT NOT NULL,
    body TEXT,
    content_type TEXT,
    cookies_json TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    indicators_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    status_code INTEGER,
    http_version TEXT,
    headers_json TEXT NOT NULL,
    body TEXT,
    content_type TEXT,
    analysis_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS request_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    category TEXT,
    severity TEXT,
    description TEXT,
    evidence TEXT,
    recommendation TEXT,
    FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_requests_created_at ON requests(created_at);
CREATE INDEX IF NOT EXISTS idx_requests_host_path ON requests(host, path);
CREATE INDEX IF NOT EXISTS idx_responses_request_id ON responses(request_id);
CREATE INDEX IF NOT EXISTS idx_request_findings_request_id ON request_findings(request_id);
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


def save_imported_request(request_data: Dict[str, Any]) -> int:
    created_at = request_data.get("created_at") or datetime.now(timezone.utc).isoformat()
    with _get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO requests (
                scan_id, method, url, host, path, query_string, http_version,
                headers_json, body, content_type, cookies_json, parameters_json,
                indicators_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_data.get("scan_id"),
                request_data["method"],
                request_data["url"],
                request_data.get("host"),
                request_data.get("path"),
                request_data.get("query_string", ""),
                request_data.get("http_version"),
                json.dumps(request_data.get("headers", {})),
                request_data.get("body", ""),
                request_data.get("content_type", ""),
                json.dumps(request_data.get("cookies", {})),
                json.dumps(request_data.get("parameters", [])),
                json.dumps(request_data.get("indicators", [])),
                created_at,
            ),
        )
        return int(cursor.lastrowid)


def save_imported_response(request_id: int, response_data: Dict[str, Any]) -> int:
    with _get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO responses (
                request_id, status_code, http_version, headers_json, body,
                content_type, analysis_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request_id,
                response_data.get("status_code"),
                response_data.get("http_version"),
                json.dumps(response_data.get("headers", {})),
                response_data.get("body", ""),
                response_data.get("content_type", ""),
                json.dumps(response_data.get("analysis", {})),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return int(cursor.lastrowid)


def save_request_findings(request_id: int, findings: Iterable[Dict[str, Any]]) -> None:
    rows = [
        (
            request_id,
            finding.get("title", ""),
            finding.get("category"),
            finding.get("severity"),
            finding.get("description"),
            finding.get("evidence"),
            finding.get("recommendation"),
        )
        for finding in findings
    ]
    if not rows:
        return
    with _get_connection() as connection:
        connection.executemany(
            """
            INSERT INTO request_findings (
                request_id, title, category, severity, description, evidence, recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def _decode_request(row: sqlite3.Row) -> Dict[str, Any]:
    request_data = dict(row)
    for key in ("headers_json", "cookies_json", "parameters_json", "indicators_json"):
        source_key = key
        target_key = key.removesuffix("_json")
        request_data[target_key] = json.loads(request_data.pop(source_key) or "{}")
    return request_data


def get_request_by_id(request_id: int) -> Optional[Dict[str, Any]]:
    with _get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ).fetchone()
        return _decode_request(row) if row else None


def get_requests(limit: int = 50) -> List[Dict[str, Any]]:
    limit = max(0, int(limit))
    if limit == 0:
        return []
    with _get_connection() as connection:
        rows = connection.execute(
            """
            SELECT requests.*, responses.status_code AS response_status
            FROM requests
            LEFT JOIN responses ON responses.id = (
                SELECT MAX(id) FROM responses AS latest WHERE latest.request_id = requests.id
            )
            ORDER BY requests.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [_decode_request(row) for row in rows]


def get_response_by_request_id(request_id: int) -> Optional[Dict[str, Any]]:
    with _get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM responses WHERE request_id = ? ORDER BY id DESC LIMIT 1",
            (request_id,),
        ).fetchone()
        if not row:
            return None
        response = dict(row)
        response["headers"] = json.loads(response.pop("headers_json") or "{}")
        response["analysis"] = json.loads(response.pop("analysis_json") or "{}")
        return response


def get_request_findings(request_id: int) -> List[Dict[str, Any]]:
    with _get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM request_findings WHERE request_id = ? ORDER BY id",
            (request_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def delete_imported_request(request_id: int) -> bool:
    with _get_connection() as connection:
        exists = connection.execute(
            "SELECT id FROM requests WHERE id = ?", (request_id,)
        ).fetchone()
        if not exists:
            return False
        connection.execute("DELETE FROM requests WHERE id = ?", (request_id,))
        return True


def clear_imported_requests() -> int:
    with _get_connection() as connection:
        count = connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        connection.execute("DELETE FROM requests")
        return int(count)


def get_imported_request_count() -> int:
    with _get_connection() as connection:
        return int(connection.execute("SELECT COUNT(*) FROM requests").fetchone()[0])


__all__ = [
    "DATABASE_PATH",
    "clear_scan_history",
    "clear_imported_requests",
    "delete_scan",
    "delete_imported_request",
    "get_findings_by_scan_id",
    "get_dashboard_stats",
    "get_recent_scans",
    "get_imported_request_count",
    "get_request_by_id",
    "get_request_findings",
    "get_requests",
    "get_response_by_request_id",
    "get_scan_by_id",
    "init_db",
    "save_findings",
    "save_imported_request",
    "save_imported_response",
    "save_request_findings",
    "save_scan",
]
