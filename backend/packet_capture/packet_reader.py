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
    try:
        text = str(value).strip()
        return int(text) if text else None
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
                    "timestamp": (
                        row.get("Timestamp") or ""
                    ).strip(),

                    "packet_type": (
                        row.get("Packet Type")
                        or "Unknown"
                    ).strip(),

                    "source_mac": (
                        row.get("Source MAC")
                        or "Unknown"
                    ).strip(),

                    "destination_mac": (
                        row.get("Destination MAC")
                        or "Unknown"
                    ).strip(),

                    "bssid": (
                        row.get("BSSID")
                        or "Unknown"
                    ).strip(),

                    "frame_type": (
                        row.get("Frame Type")
                        or "Unknown"
                    ).strip(),

                    "signal_strength": _safe_signal(
                        row.get("Signal Strength")
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
