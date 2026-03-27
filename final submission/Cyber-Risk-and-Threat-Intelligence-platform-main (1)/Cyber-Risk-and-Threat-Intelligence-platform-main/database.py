# database.py
# Responsibility: all SQLite operations — no scanning, no scoring, no email.
# DB file is created in the project root alongside dashboard.py.

import sqlite3
import json
import pandas as pd
from datetime import datetime

DB_FILE = "cyberscan.db"


def init_db():
    """
    Create the scans table if it does not exist.
    Safe to call on every startup / import.
    Column names match dashboard.py's DataFrame columns exactly:
      target, composite_score, severity, portid, nmap_score, vt_score
    """
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time       TEXT    NOT NULL,
            targets         TEXT,
            total_hosts     INTEGER,
            total_ports     INTEGER,
            critical_count  INTEGER,
            high_count      INTEGER,
            max_risk_score  REAL,
            avg_risk_score  REAL,
            results_json    TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(df: pd.DataFrame, targets: list) -> int:
    """
    Persist a completed scan. Returns the new row ID.
    Expects df to be the port-level DataFrame produced by reports_to_df()
    in dashboard.py (columns: target, portid, composite_score, severity, …).
    """
    # Guard: must have data
    if df is None or df.empty:
        return -1

    conn = sqlite3.connect(DB_FILE)

    # Count unique hosts via 'target' column
    total_hosts     = int(df["target"].nunique()) if "target" in df.columns else 0
    total_ports     = len(df[df["portid"] != "N/A"]) if "portid" in df.columns else len(df)
    critical_count  = int((df["severity"] == "CRITICAL").sum()) if "severity" in df.columns else 0
    high_count      = int((df["severity"] == "HIGH").sum())     if "severity" in df.columns else 0
    max_risk_score  = float(df["composite_score"].max())        if "composite_score" in df.columns else 0.0
    avg_risk_score  = float(df["composite_score"].mean())       if "composite_score" in df.columns else 0.0

    # Serialise the full DataFrame — convert PortRisk objects if needed
    try:
        results_json = df.to_json(orient="records")
    except Exception:
        results_json = "[]"

    cur = conn.execute(
        """INSERT INTO scans
           (scan_time, targets, total_hosts, total_ports,
            critical_count, high_count, max_risk_score, avg_risk_score, results_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ", ".join(targets) if targets else "",
            total_hosts,
            total_ports,
            critical_count,
            high_count,
            round(max_risk_score, 2),
            round(avg_risk_score, 2),
            results_json,
        ),
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def load_history() -> pd.DataFrame:
    """
    Return scan summaries — one row per scan, newest first.
    Used by the History tab for the trend charts and summary table.
    """
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        """SELECT id, scan_time, targets, total_hosts, total_ports,
                  critical_count, high_count, max_risk_score, avg_risk_score
           FROM scans ORDER BY id DESC""",
        conn,
    )
    conn.close()
    return df


def load_scan_by_id(scan_id: int) -> pd.DataFrame:
    """
    Return the full port-level results for a specific past scan.
    Used when the user drills into a past scan in the History tab.
    """
    conn = sqlite3.connect(DB_FILE)
    row = conn.execute(
        "SELECT results_json FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    conn.close()
    if row and row[0]:
        try:
            return pd.read_json(row[0], orient="records")
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()


def delete_scan(scan_id: int) -> bool:
    """
    Delete a single scan row by ID. Returns True on success.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    return True


# ── Auto-initialise on import ─────────────────────────────────────────────────
init_db()
