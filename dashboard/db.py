"""
db.py  –  NetWatchman scan-history SQLite layer
Drop this file into dashboard/ alongside app.py.
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "netwatchman_history.db")


# ─────────────────────────────────────────────
#  Bootstrap
# ─────────────────────────────────────────────

def init_db():
    """Create tables if they don't exist yet. Call once at app startup."""
    with _conn() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at     TEXT    NOT NULL,
                source_name    TEXT    NOT NULL,
                mode           TEXT    NOT NULL,
                total_packets  INTEGER NOT NULL DEFAULT 0,
                total          INTEGER NOT NULL DEFAULT 0,
                critical       INTEGER NOT NULL DEFAULT 0,
                high           INTEGER NOT NULL DEFAULT 0,
                medium         INTEGER NOT NULL DEFAULT 0,
                low            INTEGER NOT NULL DEFAULT 0,
                info           INTEGER NOT NULL DEFAULT 0,
                results_json   TEXT    NOT NULL DEFAULT '[]'
            )
        """)
        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_created
            ON scans (created_at DESC)
        """)
        # Migrate existing DB: add total_packets column if missing
        try:
            con.execute("ALTER TABLE scans ADD COLUMN total_packets INTEGER NOT NULL DEFAULT 0")
        except Exception:
            pass  # column already exists


# ─────────────────────────────────────────────
#  Write
# ─────────────────────────────────────────────

def save_scan(source_name: str, mode: str, results: list, total_packets: int = 0) -> int:
    """
    Persist a completed scan.

    Parameters
    ----------
    source_name   : filename or interface name
    mode          : 'pcap' or 'live'
    results       : list of alert dicts
    total_packets : raw packet count from scapy

    Returns the new row id.
    """
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        sev = (r.get("severity") or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    with _conn() as con:
        cur = con.execute(
            """
            INSERT INTO scans
                (created_at, source_name, mode, total_packets, total,
                 critical, high, medium, low, info, results_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                source_name,
                mode,
                total_packets,
                len(results),
                severity_counts["critical"],
                severity_counts["high"],
                severity_counts["medium"],
                severity_counts["low"],
                severity_counts["info"],
                json.dumps(results),
            ),
        )
        return cur.lastrowid


# ─────────────────────────────────────────────
#  Read
# ─────────────────────────────────────────────

def list_scans(limit: int = 200) -> list:
    """Return scan summaries (no results_json) newest-first."""
    with _conn() as con:
        rows = con.execute(
            """
            SELECT id, created_at, source_name, mode,
                   total_packets, total, critical, high, medium, low, info
            FROM   scans
            ORDER  BY created_at DESC
            LIMIT  ?
            """,
            (limit,),
        ).fetchall()
    return [_row_to_summary(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    """Return a single scan including its full results list."""
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    data = _row_to_summary(row)
    data["results"] = json.loads(row["results_json"])
    return data


def delete_scan(scan_id: int) -> bool:
    with _conn() as con:
        con.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return True


def clear_all_scans() -> int:
    """Delete every row. Returns number of rows deleted."""
    with _conn() as con:
        cur = con.execute("DELETE FROM scans")
        return cur.rowcount


# ─────────────────────────────────────────────
#  Internals
# ─────────────────────────────────────────────

def _conn() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def _row_to_summary(row) -> dict:
    return {
        "id":            row["id"],
        "created_at":    row["created_at"],
        "source_name":   row["source_name"],
        "mode":          row["mode"],
        "total_packets": row["total_packets"],
        "total":         row["total"],
        "critical":      row["critical"],
        "high":          row["high"],
        "medium":        row["medium"],
        "low":           row["low"],
        "info":          row["info"],
    }