"""Training pipeline for the Wi-Fi Network Recommendation and Scan Classification model.

This script trains a dedicated Random Forest classifier on the 12 scan-level features,
computes comprehensive evaluation metrics (Accuracy, Precision, Recall, F1, Confusion Matrix,
Feature Importance), and serializes the model separately from the AWID3 intrusion model.
"""

from __future__ import annotations

import json
from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from .dataset_generator import OUTPUT_CSV, save_default_dataset
from .recommendation_schema import (
    CLASS_NAMES,
    RECOMMENDATION_FEATURE_COUNT,
    RECOMMENDATION_FEATURE_NAMES,
)

MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_FILE = MODELS_DIR / "wifi_network_recommendation.joblib"
METADATA_FILE = MODELS_DIR / "model_metadata.json"


def train_wifi_recommendation_model(
    dataset_path: Path | str | None = None,
    random_seed: int = 42,
) -> dict:
    """Train and evaluate the Wi-Fi recommendation Random Forest classifier."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    csv_path = Path(dataset_path) if dataset_path else OUTPUT_CSV
    if not csv_path.exists():
        csv_path = save_default_dataset()

    print(f"[Training] Loading dataset from: {csv_path}")
    df = pd.read_csv(csv_path)

    # Validate feature presence
    missing = [col for col in RECOMMENDATION_FEATURE_NAMES if col not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing required recommendation features: {missing}")

    X = df[RECOMMENDATION_FEATURE_NAMES]
    y = df["target_class"]

    # Stratified Train/Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=random_seed,
        stratify=y,
    )

    print(f"[Training] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

    # Instantiate transparent Random Forest classifier
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=random_seed,
    )

    model.fit(X_train, y_train)

    # Predictions on test set
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)

    # Compute Metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    rec_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))

    prec_weighted = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec_weighted = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    # Confusion Matrix (labels aligned with CLASS_NAMES)
    cm = confusion_matrix(y_test, y_pred, labels=CLASS_NAMES)
    report_dict = classification_report(
        y_test,
        y_pred,
        labels=CLASS_NAMES,
        output_dict=True,
        zero_division=0,
    )

    # Feature Importances for Explainability
    importances = model.feature_importances_
    feat_imp = {
        name: round(float(imp * 100), 2)
        for name, imp in sorted(
            zip(RECOMMENDATION_FEATURE_NAMES, importances),
            key=lambda x: x[1],
            reverse=True,
        )
    }

    # Save model artifact
    joblib.dump(model, MODEL_FILE)
    print(f"[Training] Saved model to: {MODEL_FILE}")

    # Build metadata payload
    metadata = {
        "model_name": "wifi_network_recommendation.joblib",
        "algorithm": "RandomForestClassifier",
        "n_estimators": 100,
        "max_depth": 12,
        "feature_count": RECOMMENDATION_FEATURE_COUNT,
        "features": RECOMMENDATION_FEATURE_NAMES,
        "classes": CLASS_NAMES,
        "dataset_type": "SYNTHETIC_DEMO (IEEE 802.11 QoS & Propagation Model)",
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "metrics": {
            "accuracy": round(acc * 100, 2),
            "macro_precision": round(prec_macro * 100, 2),
            "macro_recall": round(rec_macro * 100, 2),
            "macro_f1": round(f1_macro * 100, 2),
            "weighted_f1": round(f1_weighted * 100, 2),
        },
        "confusion_matrix": {
            "labels": CLASS_NAMES,
            "matrix": cm.tolist(),
        },
        "classification_report": report_dict,
        "feature_importances": feat_imp,
    }

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[Training] Saved metadata to: {METADATA_FILE}")

    print("\n=== Model Performance on Test Set ===")
    print(f"Accuracy:  {metadata['metrics']['accuracy']}%")
    print(f"Macro F1:  {metadata['metrics']['macro_f1']}%")
    print(f"Top 3 Features: {list(feat_imp.items())[:3]}")

    return metadata


if __name__ == "__main__":
    train_wifi_recommendation_model()
