"""Evaluation service for the Wi-Fi Network Recommendation model."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .train_recommendation_model import METADATA_FILE, MODEL_FILE, train_wifi_recommendation_model


def get_recommendation_model_metadata() -> dict[str, Any]:
    """Retrieve evaluation metrics and metadata for the recommendation model."""
    if not METADATA_FILE.exists() or not MODEL_FILE.exists():
        # Train model if not present yet
        return train_wifi_recommendation_model()

    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)
