"""SQLite storage module for NetShield incidents."""

import sqlite3
from pathlib import Path

# Resolve the database path relative to this file so it works regardless of
# the current working directory (Flask from backend/, sniffer from packet_capture/, etc.).
_DATA_DIR = Path(__file__).resolve().parent
DB_PATH = _DATA_DIR / "netshield.db"

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS incidents (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at         TEXT    NOT NULL,
    prediction         INTEGER NOT NULL,
    label              TEXT    NOT NULL,
    attack_probability REAL    NOT NULL,
    normal_probability REAL    NOT NULL,
    total_packets      INTEGER NOT NULL,
    window_start       REAL    NOT NULL,
    window_end         REAL    NOT NULL,
    feature_count      INTEGER NOT NULL,
    severity           TEXT    NOT NULL DEFAULT 'High',
    status             TEXT    NOT NULL DEFAULT 'New'
);
"""

_INSERT_INCIDENT_SQL = """
INSERT INTO incidents (
    created_at,
    prediction,
    label,
    attack_probability,
    normal_probability,
    total_packets,
    window_start,
    window_end,
    feature_count,
    severity,
    status
) VALUES (
    :created_at,
    :prediction,
    :label,
    :attack_probability,
    :normal_probability,
    :total_packets,
    :window_start,
    :window_end,
    :feature_count,
    :severity,
    :status
);
"""


def initialize_database() -> None:
    """Create the database file and the incidents table if they do not exist."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()


def create_incident(result: dict) -> int:
    """Insert one incident row from a completed ML inference result.

    Args:
        result: A dictionary produced by V3InferenceService.analyze_window().
                Must contain prediction == 1 (attack detected).

    Returns:
        The integer row ID of the newly inserted incident.

    Raises:
        ValueError: If result["prediction"] is not 1. Nothing is inserted.
    """
    if result.get("prediction") != 1:
        raise ValueError(
            f"create_incident() only stores attack detections (prediction == 1). "
            f"Got prediction={result.get('prediction')!r}."
        )

    import datetime

    row = {
        "created_at": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "prediction": int(result["prediction"]),
        "label": str(result["label"]),
        "attack_probability": float(result["attack_probability"]),
        "normal_probability": float(result["normal_probability"]),
        "total_packets": int(result["total_packets"]),
        "window_start": float(result["window_start"]),
        "window_end": float(result["window_end"]),
        "feature_count": int(result["feature_count"]),
        "severity": str(result.get("severity", "High")),
        "status": str(result.get("status", "New")),
    }

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(_INSERT_INCIDENT_SQL, row)
        conn.commit()
        return cursor.lastrowid


_SELECT_INCIDENTS_SQL = """
SELECT
    id,
    created_at,
    prediction,
    label,
    attack_probability,
    normal_probability,
    total_packets,
    window_start,
    window_end,
    feature_count,
    severity,
    status
FROM incidents
ORDER BY id DESC;
"""


def get_incidents() -> list[dict]:
    """Retrieve all incident records from the database, newest first.

    Returns:
        A list of incident dictionaries ordered by id DESC.
        Returns an empty list when there are no incident rows.
    """
    if not DB_PATH.exists():
        return []

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(_SELECT_INCIDENTS_SQL)
        return [dict(row) for row in cursor.fetchall()]

