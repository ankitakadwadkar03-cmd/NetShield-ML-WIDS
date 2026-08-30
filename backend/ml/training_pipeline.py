"""Training pipeline utilities for NetShield ML."""

from __future__ import annotations

from typing import Any

from ml.feature_schema import FEATURE_NAMES


def validate_feature_rows(
    feature_rows: list[dict[str, Any]],
) -> None:
    """Validate that feature rows follow the NetShield schema."""

    for index, row in enumerate(feature_rows):
        actual_names = list(row.keys())

        if actual_names != FEATURE_NAMES:
            raise ValueError(
                f"Feature row {index} does not match the "
                "authoritative feature schema."
            )


def prepare_training_data(
    feature_rows: list[dict[str, Any]],
    labels: list[str],
) -> tuple[list[list[float]], list[str]]:
    """Prepare feature matrix X and labels y.

    Dataset-specific loading and label mapping will be added
    after the AWID3 dataset has been inspected.
    """

    if len(feature_rows) != len(labels):
        raise ValueError(
            "Number of feature rows must match number of labels."
        )

    validate_feature_rows(feature_rows)

    x: list[list[float]] = []

    for row in feature_rows:
        vector: list[float] = []

        for feature_name in FEATURE_NAMES:
            value = row[feature_name]

            if value is None:
                value = 0.0

            vector.append(float(value))

        x.append(vector)

    return x, labels
