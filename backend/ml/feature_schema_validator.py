"""Canonical 31-feature schema validator for NetShield ML WIDS.

Ensures that any dataset, PCAP analysis window, or evaluation input strictly adheres
to the 31-feature schema used during AWID3 v3 Random Forest model training.
"""

from __future__ import annotations

from typing import Any, Sequence
import pandas as pd

try:
    from ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES
except ImportError:
    from backend.ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES


def validate_feature_schema(
    input_data: Sequence[str] | dict[str, Any] | pd.DataFrame,
) -> tuple[bool, str, dict[str, Any]]:
    """Validate that features match the authoritative 31-feature schema.

    Checks:
    1. Expected feature count == 31.
    2. All 31 feature names exist.
    3. Exact feature ordering matches V3_FEATURE_NAMES.

    Returns:
        (is_valid, status_message, details_dict)
    """
    if isinstance(input_data, pd.DataFrame):
        actual_names = [col for col in input_data.columns if col.lower() != "label"]
    elif isinstance(input_data, dict):
        actual_names = [k for k in input_data.keys() if k.lower() != "label"]
    else:
        actual_names = [f for f in input_data if f.lower() != "label"]

    actual_count = len(actual_names)
    expected_set = set(V3_FEATURE_NAMES)
    actual_set = set(actual_names)

    missing = [f for f in V3_FEATURE_NAMES if f not in actual_set]
    extra = [f for f in actual_names if f not in expected_set]
    order_matches = actual_names == V3_FEATURE_NAMES

    if actual_count == V3_FEATURE_COUNT and not missing and not extra and order_matches:
        details = {
            "valid": True,
            "status_text": "31 / 31 features matched",
            "expected_count": V3_FEATURE_COUNT,
            "actual_count": actual_count,
            "missing_features": [],
            "extra_features": [],
            "order_matches": True,
            "feature_names": V3_FEATURE_NAMES,
        }
        return True, "31 / 31 features matched", details

    errors = []
    if actual_count != V3_FEATURE_COUNT:
        errors.append(f"Expected {V3_FEATURE_COUNT} features, got {actual_count}")
    if missing:
        errors.append(f"Missing required features ({len(missing)}): {', '.join(missing[:5])}")
    if extra:
        errors.append(f"Unexpected extra features ({len(extra)}): {', '.join(extra[:5])}")
    if not missing and not extra and not order_matches:
        errors.append("Feature ordering does not match authoritative training schema")

    error_message = "; ".join(errors)
    details = {
        "valid": False,
        "status_text": f"Schema mismatch ({actual_count}/{V3_FEATURE_COUNT})",
        "expected_count": V3_FEATURE_COUNT,
        "actual_count": actual_count,
        "missing_features": missing,
        "extra_features": extra,
        "order_matches": order_matches,
        "feature_names": V3_FEATURE_NAMES,
        "error_message": error_message,
    }
    return False, error_message, details
