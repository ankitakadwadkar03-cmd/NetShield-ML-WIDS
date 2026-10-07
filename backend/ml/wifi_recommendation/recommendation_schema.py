"""Feature schema and extraction for Wi-Fi network recommendation and scan classification.

This module defines the 12 scan-level features extracted directly from scanner outputs
(SSID, BSSID, Signal, Channel, Frequency, Encryption, Vendor, and session context).
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence
import pandas as pd

RECOMMENDATION_FEATURE_NAMES = [
    "signal_strength_dbm",
    "signal_quality_pct",
    "channel_number",
    "band_is_5ghz",
    "security_level_rank",
    "is_open_network",
    "is_hidden_ssid",
    "channel_congestion_count",
    "co_channel_interference_risk",
    "nearby_ap_density",
    "has_known_vendor",
    "estimated_snr_proxy",
]

RECOMMENDATION_FEATURE_COUNT = len(RECOMMENDATION_FEATURE_NAMES)

# Target Classes for Network Assessment
CLASS_NAMES = ["POOR", "FAIR", "GOOD", "EXCELLENT"]
CLASS_TO_INT = {name: idx for idx, name in enumerate(CLASS_NAMES)}
INT_TO_CLASS = {idx: name for idx, name in enumerate(CLASS_NAMES)}


def parse_signal_dbm(raw_signal: Any) -> float:
    """Parse RSSI in dBm from raw signal string or number.
    
    Examples:
        -45 -> -45.0
        "-68 dBm" -> -68.0
        "85%" -> -57.5 (converted from percentage)
        None/empty -> -90.0 (default weak fallback)
    """
    if raw_signal is None:
        return -90.0
    if isinstance(raw_signal, (int, float)):
        val = float(raw_signal)
        # If passed as positive percentage (e.g. 80)
        if 0 < val <= 100 and val != 0:
            return round((val / 2.0) - 100.0, 1)
        return val

    s = str(raw_signal).strip().lower()
    if not s or s == "unknown":
        return -90.0

    # Percentage format (e.g. "80%")
    pct_match = re.search(r"(\d+)\s*%", s)
    if pct_match:
        pct = float(pct_match.group(1))
        return round((pct / 2.0) - 100.0, 1)

    # dBm format (e.g. "-65 dBm" or "-65")
    dbm_match = re.search(r"(-?\d+(?:\.\d+)?)", s)
    if dbm_match:
        val = float(dbm_match.group(1))
        # If it's a positive number like "80 dBm" or "80", interpret as quality %
        if val > 0 and val <= 100:
            return round((val / 2.0) - 100.0, 1)
        return val

    return -90.0


def compute_signal_quality(signal_dbm: float) -> float:
    """Convert RSSI dBm into standard 0-100% signal quality."""
    # Standard formula: <= -100 dBm is 0%, >= -50 dBm is 100%
    if signal_dbm <= -100.0:
        return 0.0
    if signal_dbm >= -50.0:
        return 100.0
    return round(2.0 * (signal_dbm + 100.0), 1)


def parse_channel(raw_channel: Any, raw_frequency: Any = None) -> int:
    """Parse Wi-Fi channel integer from channel or frequency string."""
    if raw_channel is not None:
        try:
            ch = int(str(raw_channel).strip())
            if 1 <= ch <= 196:
                return ch
        except (ValueError, TypeError):
            pass

    # Try frequency fallback (e.g. "2412 MHz", "5180 MHz", 2437)
    if raw_frequency:
        f_str = str(raw_frequency).strip().lower()
        f_match = re.search(r"(\d+)", f_str)
        if f_match:
            freq = int(f_match.group(1))
            # 2.4 GHz
            if 2412 <= freq <= 2472:
                return int((freq - 2407) / 5)
            if freq == 2484:
                return 14
            # 5 GHz
            if 5000 <= freq <= 5900:
                return int((freq - 5000) / 5)

    return 6  # standard 2.4GHz default channel


def detect_is_5ghz(channel: int, raw_frequency: Any = None) -> int:
    """Return 1 if operating on 5 GHz (or 6 GHz) band, else 0."""
    if channel >= 32:
        return 1
    if raw_frequency:
        f_str = str(raw_frequency).strip().lower()
        if "5." in f_str or "51" in f_str or "52" in f_str or "53" in f_str or "55" in f_str or "57" in f_str or "58" in f_str:
            return 1
    return 0


def parse_security_rank(raw_encryption: Any) -> int:
    """Map security protocol to numerical security strength rank (0 to 4).
    
    0: Open / None (Unencrypted)
    1: WEP (Deprecated, Broken)
    2: WPA (Legacy TKIP)
    3: WPA2 (AES-CCMP, Industry Standard)
    4: WPA3 (SAE, Modern High Security)
    """
    if not raw_encryption:
        return 0
    enc = str(raw_encryption).strip().upper()
    if "WPA3" in enc:
        return 4
    if "WPA2" in enc:
        return 3
    if "WPA" in enc:
        return 2
    if "WEP" in enc:
        return 1
    if "OPEN" in enc or "NONE" in enc or enc == "":
        return 0
    return 2  # default unknown protected


def extract_features_for_network(
    network: Mapping[str, Any],
    all_networks: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, float]:
    """Extract the 12 canonical recommendation features for a single network."""
    all_nets = list(all_networks or [network])
    
    # 1. RSSI
    rssi = parse_signal_dbm(network.get("signal") or network.get("Signal"))
    # 2. Quality %
    quality = compute_signal_quality(rssi)
    
    # 3. Channel
    channel = parse_channel(
        network.get("channel") or network.get("Channel"),
        network.get("frequency") or network.get("Frequency"),
    )
    
    # 4. 5 GHz Band
    is_5g = detect_is_5ghz(
        channel,
        network.get("frequency") or network.get("Frequency"),
    )
    
    # 5. Security Rank
    sec_rank = parse_security_rank(
        network.get("encryption") or network.get("Encryption")
    )
    
    # 6. Is Open
    is_open = 1 if sec_rank == 0 else 0
    
    # 7. Is Hidden SSID
    raw_ssid = str(network.get("ssid") or network.get("SSID") or "").strip()
    is_hidden = 1 if not raw_ssid or raw_ssid.lower() in ("<hidden>", "hidden network", "unknown") else 0
    
    # 8. Channel Congestion (other APs on exact same channel in scan snapshot)
    my_bssid = str(network.get("bssid") or network.get("BSSID") or "").strip().upper()
    same_channel_count = 0
    overlap_risk = 0.0
    
    for other in all_nets:
        other_bssid = str(other.get("bssid") or other.get("BSSID") or "").strip().upper()
        if other_bssid and other_bssid == my_bssid:
            continue
        other_ch = parse_channel(
            other.get("channel") or other.get("Channel"),
            other.get("frequency") or other.get("Frequency"),
        )
        if other_ch == channel:
            same_channel_count += 1
        elif channel <= 14 and other_ch <= 14:
            # 2.4 GHz adjacent channel interference check
            dist = abs(other_ch - channel)
            if dist in (1, 2):
                overlap_risk += 1.0
            elif dist in (3, 4):
                overlap_risk += 0.5

    # 9. Co-channel / Adjacent channel interference
    # 10. Nearby AP density
    nearby_density = len(all_nets)
    
    # 11. Known vendor
    vendor = str(network.get("vendor") or network.get("Vendor") or "").strip()
    has_vendor = 1 if vendor and vendor.lower() not in ("unknown", "none", "") else 0
    
    # 12. SNR Proxy: Assuming -95 dBm noise floor
    snr_proxy = max(0.0, min(55.0, rssi - (-95.0)))
    
    return {
        "signal_strength_dbm": float(rssi),
        "signal_quality_pct": float(quality),
        "channel_number": float(channel),
        "band_is_5ghz": float(is_5g),
        "security_level_rank": float(sec_rank),
        "is_open_network": float(is_open),
        "is_hidden_ssid": float(is_hidden),
        "channel_congestion_count": float(same_channel_count),
        "co_channel_interference_risk": float(overlap_risk),
        "nearby_ap_density": float(nearby_density),
        "has_known_vendor": float(has_vendor),
        "estimated_snr_proxy": float(snr_proxy),
    }


def extract_features_dataframe(
    networks: Sequence[Mapping[str, Any]],
) -> pd.DataFrame:
    """Extract a DataFrame of canonical features for a list of scanned networks."""
    records = [
        extract_features_for_network(net, networks)
        for net in networks
    ]
    df = pd.DataFrame(records, columns=RECOMMENDATION_FEATURE_NAMES)
    return df
