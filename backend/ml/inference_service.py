"""Inference service for the frozen NetShield AWID3 v3 Random Forest model.

This module does not train, tune, or save models. It only converts an already
normalized packet window into the existing 31-feature v3 vector and asks the
frozen production model for a prediction.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from ml.burst_features_v3 import extract_burst_features
from ml.feature_extractor import extract_window_features
from ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES
from ml.v3_feature_vector import features_to_v3_vector


PRODUCTION_MODEL_PATH = (
    Path(__file__).resolve().parent
    / "models"
    / "random_forest_awid3_v3_expanded.joblib"
)

REQUIRED_PACKET_FIELDS = {
    "timestamp_epoch",
    "packet_type",
    "source_mac",
    "destination_mac",
    "bssid",
    "frame_type",
    "retry_flag",
}


class V3InferenceService:
    """Run inference with the frozen AWID3 v3 Random Forest model."""

    def __init__(self, model_path: str | Path = PRODUCTION_MODEL_PATH) -> None:
        self.model_path = Path(model_path)
        self.model = joblib.load(self.model_path)

    def analyze_window(
        self,
        packets: list[dict[str, Any]],
        window_seconds: float = 5.0,
    ) -> dict[str, Any]:
        """Classify one chronological 5-second packet window.

        The caller should pass normalized packet dictionaries. This method
        validates required fields, sorts packets by timestamp, reuses the
        existing feature extractors, converts to the v3 vector order, and then
        returns the Random Forest prediction and probabilities.
        """

        if not packets:
            return {
                "prediction": None,
                "label": "No Packets",
                "normal_probability": None,
                "attack_probability": None,
                "total_packets": 0,
                "window_start": None,
                "window_end": None,
                "feature_count": V3_FEATURE_COUNT,
                "error": "No packets provided for inference.",
            }

        normalized_packets = self._validate_and_sort_packets(packets)
        window_start = float(normalized_packets[0]["timestamp_epoch"])
        window_end = window_start + window_seconds

        base_features = extract_window_features(
            normalized_packets,
            window_seconds=window_seconds,
        )
        burst_features = extract_burst_features(
            normalized_packets,
            window_seconds=window_seconds,
        )
        features = {
            **base_features,
            **burst_features,
        }

        vector = features_to_v3_vector(features)

        if len(vector) != V3_FEATURE_COUNT:
            raise ValueError(
                f"Expected {V3_FEATURE_COUNT} v3 features, got {len(vector)}."
            )

        feature_df = pd.DataFrame([vector], columns=V3_FEATURE_NAMES)

        prediction = int(self.model.predict(feature_df)[0])
        probabilities = self.model.predict_proba(feature_df)[0]
        normal_probability = self._class_probability(probabilities, 0)
        attack_probability = self._class_probability(probabilities, 1)

        return {
            "prediction": prediction,
            "label": "Attack" if prediction == 1 else "Normal",
            "normal_probability": normal_probability,
            "attack_probability": attack_probability,
            "total_packets": int(features["total_packets"]),
            "window_start": window_start,
            "window_end": window_end,
            "feature_count": len(vector),
        }

    def _validate_and_sort_packets(
        self,
        packets: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        valid_packets: list[dict[str, Any]] = []

        for index, packet in enumerate(packets):
            missing_fields = REQUIRED_PACKET_FIELDS - packet.keys()

            if missing_fields:
                raise ValueError(
                    f"Packet {index} is missing required fields: "
                    f"{sorted(missing_fields)}"
                )

            timestamp = packet.get("timestamp_epoch")

            if timestamp is None:
                raise ValueError(
                    f"Packet {index} has missing timestamp_epoch."
                )

            try:
                float(timestamp)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Packet {index} has invalid timestamp_epoch: {timestamp!r}"
                ) from exc

            valid_packets.append(dict(packet))

        return sorted(
            valid_packets,
            key=lambda packet: float(packet["timestamp_epoch"]),
        )

    def _class_probability(
        self,
        probabilities: Any,
        class_label: int,
    ) -> float:
        class_positions = {
            int(label): index
            for index, label in enumerate(self.model.classes_)
        }

        return float(probabilities[class_positions[class_label]])


def create_v3_inference_service() -> V3InferenceService:
    """Create the reusable v3 inference service."""

    return V3InferenceService()
