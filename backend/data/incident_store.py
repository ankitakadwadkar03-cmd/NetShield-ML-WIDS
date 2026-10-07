"""SQLite storage module for NetShield incidents."""

import json
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

CREATE TABLE IF NOT EXISTS pcap_analyses (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    filename           TEXT    NOT NULL,
    file_size_bytes    INTEGER NOT NULL,
    created_at         TEXT    NOT NULL,
    duration_seconds   REAL    NOT NULL,
    total_packets      INTEGER NOT NULL,
    analyzed_windows   INTEGER NOT NULL,
    normal_windows     INTEGER NOT NULL,
    attack_windows     INTEGER NOT NULL,
    attacks_detected   INTEGER NOT NULL,
    attack_categories  TEXT    NOT NULL,
    window_results     TEXT    NOT NULL,
    features_matched   INTEGER NOT NULL DEFAULT 31,
    status             TEXT    NOT NULL DEFAULT 'completed'
);

CREATE TABLE IF NOT EXISTS ml_test_runs (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset_name            TEXT    NOT NULL,
    dataset_path            TEXT    NOT NULL,
    evaluated_at            TEXT    NOT NULL,
    total_samples           INTEGER NOT NULL,
    features_matched        INTEGER NOT NULL,
    total_features_required INTEGER NOT NULL,
    accuracy                REAL    NOT NULL,
    precision               REAL    NOT NULL,
    recall                  REAL    NOT NULL,
    f1_score                REAL    NOT NULL,
    confusion_matrix        TEXT    NOT NULL,
    per_class_metrics       TEXT    NOT NULL,
    classification_report   TEXT    NOT NULL,
    status                  TEXT    NOT NULL DEFAULT 'completed'
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
    """Create the database file and all required tables if they do not exist."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(_CREATE_TABLE_SQL)
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


def save_pcap_analysis(report: dict) -> int:
    """Store a completed PCAP analysis report in the database."""
    initialize_database()

    summary = report.get("summary", {})
    categories = report.get("attack_categories", {})
    windows = report.get("windows", [])

    row = {
        "filename": str(report.get("filename", "unknown.pcap")),
        "file_size_bytes": int(report.get("file_size_bytes", 0)),
        "created_at": str(report.get("analyzed_at", "")),
        "duration_seconds": float(summary.get("duration_seconds", 0.0)),
        "total_packets": int(summary.get("total_packets", 0)),
        "analyzed_windows": int(summary.get("analyzed_windows", 0)),
        "normal_windows": int(summary.get("normal_windows", 0)),
        "attack_windows": int(summary.get("attack_windows", 0)),
        "attacks_detected": int(summary.get("attack_windows", 0)),
        "attack_categories": json.dumps(categories),
        "window_results": json.dumps(windows),
        "features_matched": int(report.get("features_matched", 31)),
        "status": "completed",
    }

    sql = """
    INSERT INTO pcap_analyses (
        filename, file_size_bytes, created_at, duration_seconds,
        total_packets, analyzed_windows, normal_windows, attack_windows,
        attacks_detected, attack_categories, window_results,
        features_matched, status
    ) VALUES (
        :filename, :file_size_bytes, :created_at, :duration_seconds,
        :total_packets, :analyzed_windows, :normal_windows, :attack_windows,
        :attacks_detected, :attack_categories, :window_results,
        :features_matched, :status
    );
    """

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(sql, row)
        conn.commit()
        return cursor.lastrowid


def get_pcap_analyses() -> list[dict]:
    """Retrieve list of PCAP analyses without large window blobs."""
    if not DB_PATH.exists():
        return []

    sql = """
    SELECT
        id, filename, file_size_bytes, created_at, duration_seconds,
        total_packets, analyzed_windows, normal_windows, attack_windows,
        attacks_detected, attack_categories, features_matched, status
    FROM pcap_analyses
    ORDER BY id DESC;
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(sql)
        rows = []
        for r in cursor.fetchall():
            d = dict(r)
            try:
                d["attack_categories"] = json.loads(d.get("attack_categories") or "{}")
            except Exception:
                d["attack_categories"] = {}
            rows.append(d)
        return rows


def get_pcap_analysis_by_id(analysis_id: int) -> dict | None:
    """Retrieve full PCAP analysis including window results."""
    if not DB_PATH.exists():
        return None

    sql = """
    SELECT
        id, filename, file_size_bytes, created_at, duration_seconds,
        total_packets, analyzed_windows, normal_windows, attack_windows,
        attacks_detected, attack_categories, window_results,
        features_matched, status
    FROM pcap_analyses
    WHERE id = ?;
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(sql, (analysis_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["attack_categories"] = json.loads(d.get("attack_categories") or "{}")
        except Exception:
            d["attack_categories"] = {}
        try:
            d["window_results"] = json.loads(d.get("window_results") or "[]")
        except Exception:
            d["window_results"] = []
        return d


def save_ml_test_run(eval_report: dict) -> int:
    """Store an ML test evaluation report in the database."""
    initialize_database()

    summary = eval_report.get("metrics", {})
    cm = eval_report.get("confusion_matrix", {})
    per_class = eval_report.get("per_class_metrics", {})
    report = eval_report.get("classification_report", {})

    row = {
        "dataset_name": str(eval_report.get("dataset_name", "unknown.csv")),
        "dataset_path": str(eval_report.get("dataset_path", "")),
        "evaluated_at": str(eval_report.get("evaluated_at", "")),
        "total_samples": int(eval_report.get("total_samples", 0)),
        "features_matched": int(eval_report.get("features_matched", 31)),
        "total_features_required": int(eval_report.get("total_features_required", 31)),
        "accuracy": float(summary.get("accuracy", 0.0)),
        "precision": float(summary.get("precision", 0.0)),
        "recall": float(summary.get("recall", 0.0)),
        "f1_score": float(summary.get("f1_score", 0.0)),
        "confusion_matrix": json.dumps(cm),
        "per_class_metrics": json.dumps(per_class),
        "classification_report": json.dumps(report),
        "status": "completed",
    }

    sql = """
    INSERT INTO ml_test_runs (
        dataset_name, dataset_path, evaluated_at, total_samples,
        features_matched, total_features_required, accuracy, precision,
        recall, f1_score, confusion_matrix, per_class_metrics,
        classification_report, status
    ) VALUES (
        :dataset_name, :dataset_path, :evaluated_at, :total_samples,
        :features_matched, :total_features_required, :accuracy, :precision,
        :recall, :f1_score, :confusion_matrix, :per_class_metrics,
        :classification_report, :status
    );
    """

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(sql, row)
        conn.commit()
        return cursor.lastrowid


def get_ml_test_runs() -> list[dict]:
    """Retrieve list of past ML test runs."""
    if not DB_PATH.exists():
        return []

    sql = """
    SELECT
        id, dataset_name, dataset_path, evaluated_at, total_samples,
        features_matched, total_features_required, accuracy, precision,
        recall, f1_score, confusion_matrix, per_class_metrics,
        classification_report, status
    FROM ml_test_runs
    ORDER BY id DESC;
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(sql)
        rows = []
        for r in cursor.fetchall():
            d = dict(r)
            try:
                d["confusion_matrix"] = json.loads(d.get("confusion_matrix") or "{}")
            except Exception:
                d["confusion_matrix"] = {}
            try:
                d["per_class_metrics"] = json.loads(d.get("per_class_metrics") or "{}")
            except Exception:
                d["per_class_metrics"] = {}
            try:
                d["classification_report"] = json.loads(d.get("classification_report") or "{}")
            except Exception:
                d["classification_report"] = {}
            rows.append(d)
        return rows


def get_ml_test_run_by_id(run_id: int) -> dict | None:
    """Retrieve specific ML test run by ID."""
    if not DB_PATH.exists():
        return None

    sql = """
    SELECT
        id, dataset_name, dataset_path, evaluated_at, total_samples,
        features_matched, total_features_required, accuracy, precision,
        recall, f1_score, confusion_matrix, per_class_metrics,
        classification_report, status
    FROM ml_test_runs
    WHERE id = ?;
    """

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(sql, (run_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["confusion_matrix"] = json.loads(d.get("confusion_matrix") or "{}")
        except Exception:
            d["confusion_matrix"] = {}
        try:
            d["per_class_metrics"] = json.loads(d.get("per_class_metrics") or "{}")
        except Exception:
            d["per_class_metrics"] = {}
        try:
            d["classification_report"] = json.loads(d.get("classification_report") or "{}")
        except Exception:
            d["classification_report"] = {}
        return d


