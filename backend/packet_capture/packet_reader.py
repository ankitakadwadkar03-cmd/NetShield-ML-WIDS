"""Read captured WiFi packet metadata for the NetShield API."""

from __future__ import annotations

import csv
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


PACKET_LOG_CSV = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "packet_logs"
    / "wifi_packets.csv"
)


def _safe_signal(value: str | None) -> int | None:
    return _safe_int(value)


def _clean_optional_text(value: str | None) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _clean_text(
    value: str | None,
    default: str,
) -> str:
    return _clean_optional_text(value) or default


def _safe_int(value: str | None) -> int | None:
    try:
        text = str(value).strip()
        return int(text) if text else None
    except (TypeError, ValueError):
        return None


def _safe_float(value: str | None) -> float | None:
    try:
        text = str(value).strip()
        return float(text) if text else None
    except (TypeError, ValueError):
        return None


def read_packets(
    limit: int = 50,
    session_start_row: int | None = None,
) -> list[dict]:
    """Return the most recent captured WiFi packets."""

    if not PACKET_LOG_CSV.exists():
        return []

    safe_limit = max(1, min(int(limit), 500))

    start_row = (
        max(0, int(session_start_row))
        if session_start_row is not None
        else 0
    )

    recent_rows = deque(maxlen=safe_limit)

    with PACKET_LOG_CSV.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as csv_file:

        reader = csv.DictReader(csv_file)

        for row_index, row in enumerate(reader):

            if row_index < start_row:
                continue

            recent_rows.append(
                {
                    "timestamp": _clean_text(
                        row.get("Timestamp"),
                        "",
                    ),

                    "timestamp_epoch": _safe_float(
                        row.get("Timestamp Epoch")
                    ),

                    "packet_type": _clean_text(
                        row.get("Packet Type"),
                        "Unknown",
                    ),

                    "source_mac": _clean_text(
                        row.get("Source MAC"),
                        "Unknown",
                    ),

                    "destination_mac": _clean_text(
                        row.get("Destination MAC"),
                        "Unknown",
                    ),

                    "bssid": _clean_text(
                        row.get("BSSID"),
                        "Unknown",
                    ),

                    "ssid": _clean_optional_text(
                        row.get("SSID")
                    ),

                    "frame_type": _clean_text(
                        row.get("Frame Type"),
                        "Unknown",
                    ),

                    "frame_type_id": _safe_int(
                        row.get("Frame Type ID")
                    ),

                    "frame_subtype_id": _safe_int(
                        row.get("Frame Subtype ID")
                    ),

                    "signal_strength": _safe_signal(
                        row.get("Signal Strength")
                    ),

                    "channel": _safe_int(
                        row.get("Channel")
                    ),

                    "sequence_number": _safe_int(
                        row.get("Sequence Number")
                    ),

                    "fragment_number": _safe_int(
                        row.get("Fragment Number")
                    ),

                    "retry_flag": _safe_int(
                        row.get("Retry Flag")
                    ),

                    "protected_flag": _safe_int(
                        row.get("Protected Flag")
                    ),

                    "to_ds": _safe_int(
                        row.get("To DS")
                    ),

                    "from_ds": _safe_int(
                        row.get("From DS")
                    ),

                    "duration": _safe_int(
                        row.get("Duration")
                    ),

                    "frame_length": _safe_int(
                        row.get("Frame Length")
                    ),

                    "reason_code": _safe_int(
                        row.get("Reason Code")
                    ),

                    "eapol_present": _safe_int(
                        row.get("EAPOL Present")
                    ),
                }
            )

    return list(reversed(recent_rows))


def read_packet_feed(limit: int = 50) -> dict:
    """Return packet rows plus CSV freshness metadata."""

    packets = read_packets(limit=limit)

    updated_at = None
    age_seconds = None

    if PACKET_LOG_CSV.exists():

        modified_time = datetime.fromtimestamp(
            PACKET_LOG_CSV.stat().st_mtime,
            tz=timezone.utc,
        )

        updated_at = modified_time.isoformat()

        age_seconds = max(
            0,
            round(
                (
                    datetime.now(timezone.utc)
                    - modified_time
                ).total_seconds(),
                1,
            ),
        )

    return {
        "count": len(packets),
        "source": "wifi_packets.csv",
        "updated_at": updated_at,
        "age_seconds": age_seconds,
        "packets": packets,
    }
