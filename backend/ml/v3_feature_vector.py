from __future__ import annotations

from typing import Any

from ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES


def features_to_v3_vector(
    features: dict[str, Any],
) -> list[float]:
    """Convert a v3 feature dictionary into the ordered 31-feature ML vector."""

    if V3_FEATURE_COUNT != 31:
        raise ValueError(
            f"V3_FEATURE_COUNT must be 31, got {V3_FEATURE_COUNT}."
        )

    vector: list[float] = []

    for feature_name in V3_FEATURE_NAMES:
        value = features.get(feature_name)

        if value is None:
            vector.append(0.0)
        else:
            vector.append(float(value))

    if len(vector) != V3_FEATURE_COUNT:
        raise ValueError(
            f"Expected {V3_FEATURE_COUNT} features, got {len(vector)}."
        )

    return vector
