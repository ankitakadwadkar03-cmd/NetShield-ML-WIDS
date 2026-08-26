"""Read WiFi scanner results for the NetShield API."""

from __future__ import annotations

import csv
from pathlib import Path

from vendor_lookup.vendor_lookup import (
    load_oui_database,
    lookup_vendor,
)


NETWORK_CSV = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "scan_results"
    / "wifi_scan_results.csv"
)

VENDORS = load_oui_database()


def read_networks() -> list[dict]:
    """Return scanned WiFi networks with vendor information."""

    if not NETWORK_CSV.exists():
        return []

    networks = []

    with NETWORK_CSV.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as csv_file:

        reader = csv.DictReader(csv_file)

        for row in reader:
            ssid = (row.get("SSID") or "").strip()
            bssid = (row.get("BSSID") or "").strip().upper()

            if not ssid and not bssid:
                continue

            networks.append(
                {
                    "ssid": ssid or "Hidden Network",
                    "bssid": bssid,
                    "channel": (
                        row.get("Channel") or ""
                    ).strip(),
                    "frequency": (
                        row.get("Frequency") or ""
                    ).strip(),
                    "signal": (
                        row.get("Signal") or ""
                    ).strip(),
                    "encryption": (
                        row.get("Encryption")
                        or "Unknown"
                    ).strip(),

                    # Vendor Lookup is now really integrated.
                    "vendor": lookup_vendor(
                        bssid,
                        VENDORS,
                    ),

                    # ML has not analyzed this network yet.
                    "analysis_status": "NOT_ANALYZED",
                }
            )

    return networks
