from __future__ import annotations

from collections import defaultdict
from typing import Any


BURST_FEATURE_NAMES = [
    "max_packets_1s",
    "max_deauth_1s",
    "max_disassoc_1s",
    "packet_burst_ratio",
    "deauth_burst_ratio",
    "disassoc_burst_ratio",
]


def extract_burst_features(
    packets: list[dict[str, Any]],
    window_seconds: float = 5.0,
) -> dict[str, int | float]:
    """Extract 1-second burst features from one existing packet window."""

    if not packets:
        return {
            "max_packets_1s": 0,
            "max_deauth_1s": 0,
            "max_disassoc_1s": 0,
            "packet_burst_ratio": 0.0,
            "deauth_burst_ratio": 0.0,
            "disassoc_burst_ratio": 0.0,
        }

    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0.")

    start_timestamp = float(packets[0]["timestamp_epoch"])

    packets_per_second: dict[int, int] = defaultdict(int)
    deauth_per_second: dict[int, int] = defaultdict(int)
    disassoc_per_second: dict[int, int] = defaultdict(int)

    for packet in packets:
        timestamp = float(packet["timestamp_epoch"])

        second_index = int(timestamp - start_timestamp)

        if second_index < 0:
            second_index = 0

        if second_index >= int(window_seconds):
            second_index = int(window_seconds) - 1

        packets_per_second[second_index] += 1

        packet_type = packet.get("packet_type")

        if packet_type == "Deauthentication":
            deauth_per_second[second_index] += 1

        elif packet_type == "Disassociation":
            disassoc_per_second[second_index] += 1

    total_packets = len(packets)

    max_packets_1s = max(packets_per_second.values(), default=0)
    max_deauth_1s = max(deauth_per_second.values(), default=0)
    max_disassoc_1s = max(disassoc_per_second.values(), default=0)

    return {
        "max_packets_1s": max_packets_1s,
        "max_deauth_1s": max_deauth_1s,
        "max_disassoc_1s": max_disassoc_1s,
        "packet_burst_ratio": max_packets_1s / total_packets,
        "deauth_burst_ratio": max_deauth_1s / total_packets,
        "disassoc_burst_ratio": max_disassoc_1s / total_packets,
    }


def add_burst_features_to_window(
    features: dict[str, int | float | None],
    packets: list[dict[str, Any]],
    window_seconds: float = 5.0,
) -> dict[str, int | float | None]:
    """Return existing features plus v3 burst features."""
    burst_features = extract_burst_features(
        packets,
        window_seconds=window_seconds,
    )

    combined = dict(features)
    combined.update(burst_features)
    return combined
