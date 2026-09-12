"""Schema for all features extracted by the NetShield feature extractor."""

from __future__ import annotations

from .feature_schema import FEATURE_NAMES


DERIVED_FEATURE_NAMES = [
    "deauth_per_second",
    "disassociation_per_second",
    "reassociation_per_second",
    "beacon_per_second",
    "management_ratio",
    "control_ratio",
    "data_ratio",
    "clients_per_bssid",
]

EXTRACTED_FEATURE_NAMES = [
    *FEATURE_NAMES,
    *DERIVED_FEATURE_NAMES,
]

EXTRACTED_FEATURE_COUNT = len(EXTRACTED_FEATURE_NAMES)

if EXTRACTED_FEATURE_COUNT != 28:
    raise ValueError(
        "EXTRACTED_FEATURE_COUNT must be 28 for the NetShield extracted feature schema."
    )
