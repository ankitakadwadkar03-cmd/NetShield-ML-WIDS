"""Convert extracted NetShield features into first-model ML vectors."""

from __future__ import annotations

from collections.abc import Mapping

try:
    from .ml_feature_schema import ML_FEATURE_COUNT, ML_FEATURE_NAMES
except ImportError:  # pragma: no cover - supports direct script execution.
    from ml_feature_schema import ML_FEATURE_COUNT, ML_FEATURE_NAMES


if ML_FEATURE_COUNT != 17:
    raise ValueError("ML_FEATURE_COUNT must be 17 for the first AWID3 binary model.")


def features_to_ml_vector(
    features: Mapping[str, int | float | None],
) -> list[float]:
    """Convert one 20-feature extraction row into a 17-feature ML vector.

    Values are ordered by ``ML_FEATURE_NAMES``. Missing or ``None`` values are
    converted to ``0.0`` to match the existing NetShield vector behavior.
    """

    vector: list[float] = []

    for feature_name in ML_FEATURE_NAMES:
        value = features.get(feature_name)

        if value is None:
            value = 0.0

        vector.append(float(value))

    return vector


def vectors_from_feature_rows(
    feature_rows: list[Mapping[str, int | float | None]],
) -> list[list[float]]:
    """Convert multiple extracted feature dictionaries into ML vectors."""

    return [
        features_to_ml_vector(row)
        for row in feature_rows
    ]
