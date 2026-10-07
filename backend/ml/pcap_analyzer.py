"""PCAP/PCAPNG Packet Analysis Module for NetShield ML WIDS.

Parses offline 802.11 wireless capture files (.pcap, .pcapng), slices them into
chronological 5-second windows, extracts the authoritative 31-feature v3 schema,
and executes inference using the frozen NetShield Random Forest model.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.layers.dot11 import Dot11
from scapy.utils import PcapReader

try:
    from ml.feature_extractor import (
        extract_window_features,
        group_packets_by_time_window,
    )
    from ml.burst_features_v3 import extract_burst_features
    from ml.inference_service import V3InferenceService, create_v3_inference_service
    from ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES
    from ml.v3_feature_vector import features_to_v3_vector
except ImportError:
    from backend.ml.feature_extractor import (
        extract_window_features,
        group_packets_by_time_window,
    )
    from backend.ml.burst_features_v3 import extract_burst_features
    from backend.ml.inference_service import (
        V3InferenceService,
        create_v3_inference_service,
    )
    from backend.ml.v3_feature_schema import V3_FEATURE_COUNT, V3_FEATURE_NAMES
    from backend.ml.v3_feature_vector import features_to_v3_vector


def _frame_type_name(frame_type_id: int | None) -> str:
    return {
        0: "Management",
        1: "Control",
        2: "Data",
        3: "Extension",
    }.get(frame_type_id, "Unknown")


def _packet_type_name(frame_type_id: int | None, frame_subtype_id: int | None) -> str:
    if frame_type_id == 0:
        return {
            0: "Association Request",
            1: "Association Response",
            2: "Reassociation Request",
            3: "Reassociation Response",
            4: "Probe Request",
            5: "Probe Response",
            8: "Beacon",
            10: "Disassociation",
            11: "Authentication",
            12: "Deauthentication",
            13: "Action",
        }.get(frame_subtype_id, "Management")

    if frame_type_id == 1:
        return "Control"

    if frame_type_id == 2:
        return "Data"

    return "Unknown"


def _clean_mac(addr: Any) -> str:
    if not addr:
        return "Unknown"
    text = str(addr).strip().upper()
    if text == "FF:FF:FF:FF:FF:FF":
        return "Broadcast"
    return text


def _determine_attack_category(features: dict[str, Any]) -> str:
    """Infer the attack category based on dominant signature features."""
    deauth_count = features.get("deauth_count", 0) or 0
    disas_count = features.get("disassociation_count", 0) or 0
    reassoc_count = features.get("reassociation_count", 0) or 0
    max_deauth = features.get("max_deauth_1s", 0) or 0
    max_disas = features.get("max_disassoc_1s", 0) or 0

    if deauth_count > 0 or max_deauth > 0:
        return "Deauth"
    if disas_count > 0 or max_disas > 0:
        return "Disas"
    if reassoc_count > 0:
        return "(Re)Assoc"

    clients_per_bssid = features.get("clients_per_bssid", 0) or 0
    if clients_per_bssid > 15:
        return "RogueAP"

    return "Wireless Attack"


def parse_pcap_packets(
    pcap_path: str | Path,
    max_packets: int = 500000,
) -> list[dict[str, Any]]:
    """Parse raw 802.11 packets from a PCAP file into normalized dictionary records."""
    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    packets: list[dict[str, Any]] = []

    try:
        with PcapReader(str(path)) as reader:
            for count, pkt in enumerate(reader):
                if count >= max_packets:
                    break

                if not pkt.haslayer(Dot11):
                    continue

                dot11 = pkt[Dot11]
                type_id = int(dot11.type) if hasattr(dot11, "type") else None
                subtype_id = int(dot11.subtype) if hasattr(dot11, "subtype") else None

                source_mac = _clean_mac(getattr(dot11, "addr2", None))
                destination_mac = _clean_mac(getattr(dot11, "addr1", None))
                bssid = _clean_mac(getattr(dot11, "addr3", None) or getattr(dot11, "addr2", None))

                fcfield = int(getattr(dot11, "FCfield", 0)) or 0
                retry_flag = 1 if (fcfield & 0x08) else 0

                signal_strength = None
                if hasattr(pkt, "dBm_AntSignal"):
                    try:
                        signal_strength = int(pkt.dBm_AntSignal)
                    except (ValueError, TypeError):
                        pass

                channel = None
                if hasattr(pkt, "Channel"):
                    try:
                        channel = int(pkt.Channel)
                    except (ValueError, TypeError):
                        pass

                packets.append(
                    {
                        "timestamp_epoch": float(pkt.time),
                        "packet_type": _packet_type_name(type_id, subtype_id),
                        "source_mac": source_mac,
                        "destination_mac": destination_mac,
                        "bssid": bssid,
                        "frame_type": _frame_type_name(type_id),
                        "frame_type_id": type_id,
                        "frame_subtype_id": subtype_id,
                        "signal_strength": signal_strength,
                        "channel": channel,
                        "retry_flag": retry_flag,
                    }
                )
    except Exception as exc:
        raise ValueError(f"Error parsing PCAP file {path.name}: {exc}") from exc

    return packets


def analyze_pcap_file(
    pcap_path: str | Path,
    window_seconds: float = 5.0,
    inference_service: V3InferenceService | None = None,
) -> dict[str, Any]:
    """Execute complete end-to-end ML analysis on a PCAP file."""
    path = Path(pcap_path)
    file_size = path.stat().st_size if path.exists() else 0
    service = inference_service or create_v3_inference_service()

    packets = parse_pcap_packets(path)

    if not packets:
        return {
            "filename": path.name,
            "file_size_bytes": file_size,
            "status": "completed",
            "message": "No valid 802.11 Wi-Fi frames found in PCAP file.",
            "total_packets": 0,
            "wifi_packets": 0,
            "total_windows": 0,
            "normal_windows": 0,
            "attack_windows": 0,
            "attack_percentage": 0.0,
            "attack_categories": {},
            "start_time": None,
            "end_time": None,
            "duration_seconds": 0.0,
            "windows": [],
            "attacks": [],
            "dominant_category": "None",
        }

    # Sort packets chronologically
    packets.sort(key=lambda p: float(p["timestamp_epoch"]))

    windows = group_packets_by_time_window(packets, window_seconds=window_seconds)

    total_windows = len(windows)
    normal_windows = 0
    attack_windows = 0
    attack_category_counts: dict[str, int] = defaultdict(int)
    window_summaries: list[dict[str, Any]] = []
    detected_attacks: list[dict[str, Any]] = []

    start_time_epoch = float(packets[0]["timestamp_epoch"])
    end_time_epoch = float(packets[-1]["timestamp_epoch"])
    duration_seconds = round(max(0.0, end_time_epoch - start_time_epoch), 2)

    for idx, window_packets in enumerate(windows):
        window_result = service.analyze_window(window_packets, window_seconds=window_seconds)

        pred = window_result.get("prediction")
        atk_prob = window_result.get("attack_probability") or 0.0
        norm_prob = window_result.get("normal_probability") or 0.0
        total_pkts = window_result.get("total_packets") or len(window_packets)
        w_start = window_result.get("window_start")
        w_end = window_result.get("window_end")

        base_features = extract_window_features(window_packets, window_seconds=window_seconds)
        burst_features = extract_burst_features(window_packets, window_seconds=window_seconds)
        combined_features = {**base_features, **burst_features}

        category = "Normal"
        if pred == 1:
            attack_windows += 1
            category = _determine_attack_category(combined_features)
            attack_category_counts[category] += 1
        else:
            normal_windows += 1

        window_data = {
            "window_index": idx,
            "window_start": w_start,
            "window_end": w_end,
            "total_packets": total_pkts,
            "prediction": pred,
            "label": "Attack" if pred == 1 else "Normal",
            "category": category,
            "attack_probability": round(atk_prob, 4),
            "normal_probability": round(norm_prob, 4),
            "deauth_count": int(combined_features.get("deauth_count") or 0),
            "disassoc_count": int(combined_features.get("disassociation_count") or 0),
            "retry_ratio": round(float(combined_features.get("retry_ratio") or 0.0), 4),
            "packet_burst_ratio": round(float(combined_features.get("packet_burst_ratio") or 0.0), 4),
        }
        window_summaries.append(window_data)

        if pred == 1:
            detected_attacks.append(
                {
                    **window_data,
                    "target_bssid": window_packets[0].get("bssid", "Unknown"),
                    "source_mac": window_packets[0].get("source_mac", "Unknown"),
                }
            )

    attack_percentage = (
        round((attack_windows / total_windows) * 100, 2)
        if total_windows > 0
        else 0.0
    )

    dominant_category = (
        max(attack_category_counts.items(), key=lambda item: item[1])[0]
        if attack_category_counts
        else "None"
    )

    summary = {
        "total_packets": len(packets),
        "analyzed_windows": total_windows,
        "normal_windows": normal_windows,
        "attack_windows": attack_windows,
        "attacks_detected": len(detected_attacks),
        "attack_percentage": attack_percentage,
        "duration_seconds": duration_seconds,
        "dominant_category": dominant_category,
    }

    return {
        "filename": path.name,
        "file_size_bytes": file_size,
        "status": "completed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "features_matched": 31,
        "summary": summary,
        "total_packets": len(packets),
        "wifi_packets": len(packets),
        "total_windows": total_windows,
        "normal_windows": normal_windows,
        "attack_windows": attack_windows,
        "attack_percentage": attack_percentage,
        "attack_categories": dict(attack_category_counts),
        "dominant_category": dominant_category,
        "start_time": datetime.fromtimestamp(start_time_epoch, timezone.utc).isoformat(),
        "end_time": datetime.fromtimestamp(end_time_epoch, timezone.utc).isoformat(),
        "duration_seconds": duration_seconds,
        "windows": window_summaries,
        "attacks": detected_attacks,
    }
