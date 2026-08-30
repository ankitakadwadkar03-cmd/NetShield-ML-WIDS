"""Time-window feature extraction for NetShield ML."""

from __future__ import annotations

from .feature_schema import FEATURE_NAMES
from typing import Any


def group_packets_by_time_window(
    packet_records: list[dict[str, Any]],
    window_seconds: float = 5.0,
) -> list[list[dict[str, Any]]]:
    """Group normalized packet records into fixed time windows.

    Packets without a valid timestamp_epoch are ignored.
    """

    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0")

    valid_packets = [
        packet
        for packet in packet_records
        if packet.get("timestamp_epoch") is not None
    ]

    if not valid_packets:
        return []

    valid_packets.sort(
        key=lambda packet: float(packet["timestamp_epoch"])
    )

    windows: list[list[dict[str, Any]]] = []

    first_timestamp = float(
        valid_packets[0]["timestamp_epoch"]
    )

    current_window_start = first_timestamp
    current_window: list[dict[str, Any]] = []

    for packet in valid_packets:
        timestamp = float(packet["timestamp_epoch"])

        if timestamp >= current_window_start + window_seconds:
            if current_window:
                windows.append(current_window)

            window_offset = int(
                (timestamp - first_timestamp)
                // window_seconds
            )

            current_window_start = (
                first_timestamp
                + window_offset * window_seconds
            )

            current_window = []

        current_window.append(packet)

    if current_window:
        windows.append(current_window)

    return windows


def _count_packet_type(
    packets: list[dict[str, Any]],
    packet_type: str,
) -> int:
    """Count packets with a specific packet type."""

    return sum(
        1
        for packet in packets
        if packet.get("packet_type") == packet_type
    )


def _count_frame_type(
    packets: list[dict[str, Any]],
    frame_type: str,
) -> int:
    """Count packets with a specific 802.11 frame type."""

    return sum(
        1
        for packet in packets
        if packet.get("frame_type") == frame_type
    )


def _unique_values(
    packets: list[dict[str, Any]],
    field_name: str,
    ignored_values: set[str] | None = None,
) -> int:
    """Count unique meaningful values for a packet field."""

    ignored = ignored_values or set()

    values = {
        str(packet.get(field_name)).strip()
        for packet in packets
        if packet.get(field_name) is not None
    }

    values = {
        value
        for value in values
        if value and value not in ignored
    }

    return len(values)


def _signal_statistics(
    packets: list[dict[str, Any]],
) -> tuple[float | None, int | None, int | None]:
    """Return average, minimum, and maximum signal strength."""

    signals = [
        packet["signal_strength"]
        for packet in packets
        if packet.get("signal_strength") is not None
    ]

    if not signals:
        return None, None, None

    return (
        sum(signals) / len(signals),
        min(signals),
        max(signals),
    )


def extract_window_features(
    packets: list[dict[str, Any]],
    window_seconds: float = 5.0,
) -> dict[str, int | float | None]:
    """Extract ML features from one packet window.

    This function performs feature extraction only.
    It does not classify traffic as normal or malicious.
    """

    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0")

    total_packets = len(packets)

    average_signal, minimum_signal, maximum_signal = (
        _signal_statistics(packets)
    )

    retry_count = sum(
        1
        for packet in packets
        if packet.get("retry_flag") == 1
    )

    retry_ratio = (
        retry_count / total_packets
        if total_packets > 0
        else 0.0
    )

    return {
        "total_packets": total_packets,

        "packets_per_second": (
            total_packets / window_seconds
        ),

        "beacon_count": _count_packet_type(
            packets,
            "Beacon",
        ),

        "probe_request_count": _count_packet_type(
            packets,
            "Probe Request",
        ),

        "probe_response_count": _count_packet_type(
            packets,
            "Probe Response",
        ),

        "authentication_count": _count_packet_type(
            packets,
            "Authentication",
        ),

        "deauth_count": _count_packet_type(
            packets,
            "Deauthentication",
        ),

        "disassociation_count": _count_packet_type(
            packets,
            "Disassociation",
        ),

        "reassociation_count": (
            _count_packet_type(
                packets,
                "Reassociation Request",
            )
            + _count_packet_type(
                packets,
                "Reassociation Response",
            )
        ),

        "data_count": _count_frame_type(
            packets,
            "Data",
        ),

        "control_count": _count_frame_type(
            packets,
            "Control",
        ),

        "management_count": _count_frame_type(
            packets,
            "Management",
        ),

        "unique_source_macs": _unique_values(
            packets,
            "source_mac",
            {"Unknown", "Broadcast"},
        ),

        "unique_destination_macs": _unique_values(
            packets,
            "destination_mac",
            {"Unknown", "Broadcast"},
        ),

        "unique_bssids": _unique_values(
            packets,
            "bssid",
            {"Unknown", "Broadcast"},
        ),

        "retry_count": retry_count,

        "retry_ratio": retry_ratio,

        "average_signal": average_signal,

        "minimum_signal": minimum_signal,

        "maximum_signal": maximum_signal,
    }
