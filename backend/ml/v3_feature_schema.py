from __future__ import annotations

from ml.ml_feature_schema import ML_FEATURE_NAMES


BURST_FEATURE_NAMES = [
    "max_packets_1s",
    "max_deauth_1s",
    "max_disassoc_1s",
    "packet_burst_ratio",
    "deauth_burst_ratio",
    "disassoc_burst_ratio",
]


V3_FEATURE_NAMES = [
    *ML_FEATURE_NAMES,
    *BURST_FEATURE_NAMES,
]

V3_FEATURE_COUNT = len(V3_FEATURE_NAMES)

if V3_FEATURE_COUNT != 31:
    raise ValueError(
        f"V3_FEATURE_COUNT must be 31, got {V3_FEATURE_COUNT}."
    )
