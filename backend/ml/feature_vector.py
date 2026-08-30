"""Convert NetShield feature dictionaries into ordered ML vectors."""

from __future__ import annotations

from typing import Mapping

from ml.feature_schema import FEATURE_NAMES


def features_to_vector(
    features: Mapping[str, int | float | None],
) -> list[float]:
    """Convert one feature dictionary into the authoritative ML vector."""

    vector: list[float] = []

    for feature_name in FEATURE_NAMES:
        value = features.get(feature_name)

        if value is None:
            value = 0.0

        vector.append(float(value))

    return vector


def vectors_from_feature_rows(
    feature_rows: list[Mapping[str, int | float | None]],
) -> list[list[float]]:
    """Convert multiple feature dictionaries into ML vectors."""

    return [
        features_to_vector(row)
        for row in feature_rows
    ]
