"""ML Evaluation and Model Testing Module for NetShield ML WIDS.

Evaluates unseen test datasets against the frozen trained Random Forest model.
Validates the canonical 31-feature schema, generates comprehensive performance metrics,
confusion matrix, and per-class metrics without retraining or modifying the frozen model.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

try:
    from ml.feature_schema_validator import validate_feature_schema
    from ml.inference_service import PRODUCTION_MODEL_PATH
    from ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES
except ImportError:
    from backend.ml.feature_schema_validator import validate_feature_schema
    from backend.ml.inference_service import PRODUCTION_MODEL_PATH
    from backend.ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES


DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def list_available_test_datasets() -> list[dict[str, Any]]:
    """Scan backend/data for compatible CSV datasets and validate their schemas."""
    datasets = []
    if not DATA_DIR.exists():
        return []

    for csv_path in sorted(DATA_DIR.glob("*.csv")):
        try:
            df = pd.read_csv(csv_path, nrows=5)
            has_label = "label" in df.columns or "Label" in df.columns
            feature_cols = [c for c in df.columns if c.lower() != "label"]
            is_valid, status_msg, _ = validate_feature_schema(feature_cols)

            # Get row count
            full_df = pd.read_csv(csv_path)
            row_count = len(full_df)
            label_col = "label" if "label" in full_df.columns else "Label"
            class_counts = full_df[label_col].value_counts().to_dict() if has_label else {}

            datasets.append(
                {
                    "name": csv_path.name,
                    "filename": csv_path.name,
                    "filepath": str(csv_path),
                    "file_size_bytes": csv_path.stat().st_size,
                    "sample_count": row_count,
                    "has_label": has_label,
                    "feature_count": len(feature_cols),
                    "is_valid_schema": is_valid,
                    "schema_status": status_msg,
                    "normal_count": int(class_counts.get(0, 0)),
                    "attack_count": int(class_counts.get(1, 0)),
                }
            )
        except Exception:
            continue

    return datasets


def evaluate_test_dataset(
    dataset_path: str | Path,
    model_path: str | Path = PRODUCTION_MODEL_PATH,
) -> dict[str, Any]:
    """Evaluate an unseen test dataset against the trained model."""
    path = Path(dataset_path)
    if not path.is_absolute():
        path = DATA_DIR / path

    if not path.exists():
        raise FileNotFoundError(f"Test dataset not found: {path}")

    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"Test dataset is empty: {path.name}")

    label_col = None
    if "label" in df.columns:
        label_col = "label"
    elif "Label" in df.columns:
        label_col = "Label"

    if label_col is None:
        raise ValueError(
            f"Test dataset {path.name} is missing a ground-truth 'label' column."
        )

    feature_cols = [c for c in df.columns if c != label_col]
    is_valid, status_msg, schema_details = validate_feature_schema(feature_cols)

    if not is_valid:
        raise ValueError(
            f"Feature schema validation failed for {path.name}: {status_msg}. "
            f"Expected {V3_FEATURE_COUNT} features matching the authoritative training schema."
        )

    # Order features strictly by V3_FEATURE_NAMES
    X = df[V3_FEATURE_NAMES]
    y_raw = df[label_col].astype(int)

    # Load trained model
    m_path = Path(model_path)
    if not m_path.exists():
        raise FileNotFoundError(f"Production model file not found: {m_path}")

    model = joblib.load(m_path)

    # Model metadata
    model_name = m_path.name
    model_type = type(model).__name__
    n_estimators = getattr(model, "n_estimators", None)

    # Predictions
    y_pred = model.predict(X)
    y_proba = model.predict_proba(X) if hasattr(model, "predict_proba") else None

    # Calculate metrics
    accuracy = float(accuracy_score(y_raw, y_pred))
    precision = float(precision_score(y_raw, y_pred, average="binary", zero_division=0))
    recall = float(recall_score(y_raw, y_pred, average="binary", zero_division=0))
    f1 = float(f1_score(y_raw, y_pred, average="binary", zero_division=0))

    cm = confusion_matrix(y_raw, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    report_dict = classification_report(
        y_raw,
        y_pred,
        target_names=["Normal (0)", "Attack (1)"],
        output_dict=True,
        zero_division=0,
    )

    total_samples = len(y_raw)
    correct_samples = int((y_raw == y_pred).sum())
    incorrect_samples = int((y_raw != y_pred).sum())

    normal_support = int((y_raw == 0).sum())
    attack_support = int((y_raw == 1).sum())

    per_class_metrics = {
        "normal": {
            "label": "Normal (0)",
            "precision": round(float(report_dict["Normal (0)"]["precision"]), 4),
            "recall": round(float(report_dict["Normal (0)"]["recall"]), 4),
            "f1_score": round(float(report_dict["Normal (0)"]["f1-score"]), 4),
            "support": int(report_dict["Normal (0)"]["support"]),
        },
        "attack": {
            "label": "Attack (1)",
            "precision": round(float(report_dict["Attack (1)"]["precision"]), 4),
            "recall": round(float(report_dict["Attack (1)"]["recall"]), 4),
            "f1_score": round(float(report_dict["Attack (1)"]["f1-score"]), 4),
            "support": int(report_dict["Attack (1)"]["support"]),
        },
    }

    # Samples breakdown (first 25 samples for UI inspection)
    sample_preview = []
    for i in range(min(total_samples, 25)):
        sample_preview.append(
            {
                "index": i,
                "actual": int(y_raw.iloc[i]),
                "actual_label": "Attack" if y_raw.iloc[i] == 1 else "Normal",
                "predicted": int(y_pred[i]),
                "predicted_label": "Attack" if y_pred[i] == 1 else "Normal",
                "is_correct": bool(y_raw.iloc[i] == y_pred[i]),
                "attack_probability": round(float(y_proba[i][1]), 4) if y_proba is not None else None,
                "normal_probability": round(float(y_proba[i][0]), 4) if y_proba is not None else None,
            }
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    return {
        "status": "completed",
        "created_at": now_iso,
        "evaluated_at": now_iso,
        "dataset_name": path.name,
        "dataset_path": str(path),
        "model_name": model_name,
        "model_type": model_type,
        "n_estimators": n_estimators,
        "features_matched": V3_FEATURE_COUNT,
        "total_features_required": V3_FEATURE_COUNT,
        "schema_validation": {
            "status_text": "31 / 31 features matched",
            "matched": True,
            "feature_count": V3_FEATURE_COUNT,
            "features": V3_FEATURE_NAMES,
        },
        "total_samples": total_samples,
        "correct_samples": correct_samples,
        "incorrect_samples": incorrect_samples,
        "normal_support": normal_support,
        "attack_support": attack_support,
        "metrics": {
            "accuracy": round(accuracy * 100, 2),
            "precision": round(precision * 100, 2),
            "recall": round(recall * 100, 2),
            "f1_score": round(f1 * 100, 2),
        },
        "confusion_matrix": {
            "matrix": [[tn, fp], [fn, tp]],
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
        "per_class": per_class_metrics,
        "classification_report": report_dict,
        "sample_preview": sample_preview,
    }
