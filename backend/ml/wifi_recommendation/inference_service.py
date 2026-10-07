"""Inference service for Wi-Fi network recommendation and scan classification.

Takes scanned Wi-Fi network records, extracts the 12 canonical recommendation features,
runs model inference with the dedicated Random Forest classifier, computes recommendation
scores and confidence, generates explainable reasons, and ranks networks best-to-worst.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping, Sequence
import joblib
import numpy as np
import pandas as pd

from .recommendation_schema import (
    CLASS_NAMES,
    RECOMMENDATION_FEATURE_COUNT,
    RECOMMENDATION_FEATURE_NAMES,
    extract_features_dataframe,
    extract_features_for_network,
)
from .train_recommendation_model import MODEL_FILE, train_wifi_recommendation_model

_LOADED_MODEL = None


def get_recommendation_model():
    """Retrieve or load the trained Random Forest recommendation model."""
    global _LOADED_MODEL
    if _LOADED_MODEL is not None:
        return _LOADED_MODEL

    if not MODEL_FILE.exists():
        print("[InferenceService] Model not found on disk, training model now...")
        train_wifi_recommendation_model()

    _LOADED_MODEL = joblib.load(MODEL_FILE)
    return _LOADED_MODEL


def generate_network_explainability(
    features: dict[str, float],
    classification: str,
    network: Mapping[str, Any],
) -> dict[str, Any]:
    """Generate transparent, evidence-based explainability factors for a network."""
    positives: list[str] = []
    negatives: list[str] = []

    rssi = features.get("signal_strength_dbm", -90.0)
    sec_rank = int(features.get("security_level_rank", 0))
    congestion = int(features.get("channel_congestion_count", 0))
    is_5g = int(features.get("band_is_5ghz", 0))
    is_open = int(features.get("is_open_network", 0))
    is_hidden = int(features.get("is_hidden_ssid", 0))
    vendor = str(network.get("vendor") or "").strip()

    # 1. Signal factor
    if rssi >= -55.0:
        positives.append(f"Strong signal strength ({int(rssi)} dBm, excellent link budget)")
    elif rssi >= -68.0:
        positives.append(f"Adequate signal strength ({int(rssi)} dBm, suitable for high-throughput traffic)")
    elif rssi >= -78.0:
        negatives.append(f"Moderate to weak signal ({int(rssi)} dBm, potential packet retransmissions)")
    else:
        negatives.append(f"Very weak signal ({int(rssi)} dBm, high packet loss risk)")

    # 2. Security factor
    if sec_rank == 4:
        positives.append("State-of-the-art security (WPA3-SAE with forward secrecy)")
    elif sec_rank == 3:
        positives.append("Secure industry-standard encryption (WPA2-PSK/CCMP)")
    elif sec_rank == 2:
        negatives.append("Legacy security protocol (WPA-TKIP, vulnerable to cryptanalysis)")
    elif sec_rank == 1:
        negatives.append("Deprecated broken encryption (WEP, insecure)")
    elif is_open == 1:
        negatives.append("Unencrypted public network (Open Wi-Fi, risk of eavesdropping)")

    # 3. Channel congestion factor
    ch = int(features.get("channel_number", 6))
    if congestion == 0:
        positives.append(f"Clean dedicated channel {ch} (no co-channel interference detected)")
    elif congestion <= 1:
        positives.append(f"Low channel congestion (only 1 neighboring AP on channel {ch})")
    elif congestion <= 3:
        negatives.append(f"Moderate channel contention ({congestion} other APs sharing channel {ch})")
    else:
        negatives.append(f"High channel saturation ({congestion} competing APs on channel {ch})")

    # 4. Frequency band factor
    if is_5g == 1:
        positives.append("5 GHz high-capacity band (wider spectrum, lower airtime contention)")
    else:
        if ch in (1, 6, 11):
            positives.append(f"Standard non-overlapping 2.4 GHz channel {ch}")
        else:
            negatives.append(f"2.4 GHz channel {ch} suffers from adjacent channel bleed")

    # 5. Visibility and Vendor factors
    if is_hidden == 1:
        negatives.append("Hidden SSID requires manual configuration")
    if vendor and vendor.lower() not in ("unknown", "none", ""):
        positives.append(f"Verified hardware manufacturer ({vendor})")

    # Build concise reason sentence
    if classification == "EXCELLENT":
        summary_reason = f"Excellent choice: strong signal ({int(rssi)} dBm), robust security, and low channel congestion."
    elif classification == "GOOD":
        summary_reason = f"Good reliable network: adequate signal with secure encryption and acceptable channel conditions."
    elif classification == "FAIR":
        summary_reason = f"Sub-optimal network: degraded by {negatives[0].lower() if negatives else 'medium signal'}."
    else:  # POOR
        summary_reason = f"Not recommended: compromised by {negatives[0].lower() if negatives else 'weak security and signal'}."

    return {
        "summary": summary_reason,
        "positive_factors": positives,
        "negative_factors": negatives,
    }


def classify_and_recommend_networks(
    networks: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Classify a list of scanned networks and produce sorted recommendations."""
    if not networks:
        return {
            "status": "empty",
            "message": "No networks available for analysis",
            "scanned_count": 0,
            "processed_count": 0,
            "best_network": None,
            "networks": [],
        }

    model = get_recommendation_model()
    df_features = extract_features_dataframe(networks)

    # ML Inference
    preds = model.predict(df_features)
    probas = model.predict_proba(df_features)
    classes = list(model.classes_)

    # Base quality score mapping weights for probability expectation
    class_weights = {"POOR": 18.0, "FAIR": 50.0, "GOOD": 78.0, "EXCELLENT": 96.0}

    results = []

    for i, net in enumerate(networks):
        cls_name = str(preds[i])
        probs = probas[i]
        cls_idx = classes.index(cls_name) if cls_name in classes else int(np.argmax(probs))
        confidence = float(probs[cls_idx])

        # Compute probability-weighted expected score
        expected_score = sum(
            probs[c_i] * class_weights.get(c_name, 50.0)
            for c_i, c_name in enumerate(classes)
        )

        feat_row = df_features.iloc[i].to_dict()

        # Fine-grained adjustment (+/- 5 points based on raw SNR & clean channel)
        # to ensure networks with identical classes have a natural rank
        snr_adj = (feat_row["estimated_snr_proxy"] - 25.0) * 0.12
        cong_adj = -float(feat_row["channel_congestion_count"]) * 0.8
        score = max(5.0, min(100.0, expected_score + snr_adj + cong_adj))

        # Hard cap: unencrypted open networks cannot score above 60
        if feat_row["is_open_network"] == 1:
            score = min(score, 58.0)
        # Hard cap: WEP cannot score above 45
        if feat_row["security_level_rank"] == 1:
            score = min(score, 45.0)

        explainability = generate_network_explainability(feat_row, cls_name, net)

        band_label = "5 GHz" if feat_row["band_is_5ghz"] == 1 else "2.4 GHz"

        results.append({
            "ssid": str(net.get("ssid") or net.get("SSID") or "Hidden Network"),
            "bssid": str(net.get("bssid") or net.get("BSSID") or "").upper(),
            "channel": int(feat_row["channel_number"]),
            "frequency": str(net.get("frequency") or net.get("Frequency") or f"{int(feat_row['channel_number'])} ({band_label})"),
            "band": band_label,
            "signal": f"{int(feat_row['signal_strength_dbm'])} dBm",
            "signal_dbm": int(feat_row["signal_strength_dbm"]),
            "signal_quality_pct": int(feat_row["signal_quality_pct"]),
            "security": str(net.get("encryption") or net.get("Encryption") or "Unknown"),
            "security_rank": int(feat_row["security_level_rank"]),
            "vendor": str(net.get("vendor") or net.get("Vendor") or "Unknown"),
            "ml_classification": cls_name,
            "confidence_pct": round(confidence * 100, 1),
            "recommendation_score": round(score, 1),
            "recommendation_reason": explainability["summary"],
            "positive_factors": explainability["positive_factors"],
            "negative_factors": explainability["negative_factors"],
            "features": feat_row,
            "is_best_recommendation": False,
            "rank": 0,
        })

    # Sort descending by recommendation_score
    ranked_networks = sorted(
        results,
        key=lambda item: item["recommendation_score"],
        reverse=True,
    )

    for rank_idx, item in enumerate(ranked_networks, start=1):
        item["rank"] = rank_idx
        if rank_idx == 1:
            item["is_best_recommendation"] = True

    best_network = ranked_networks[0] if ranked_networks else None

    return {
        "status": "completed",
        "scanned_count": len(networks),
        "processed_count": len(ranked_networks),
        "best_network": best_network,
        "networks": ranked_networks,
        "model_info": {
            "model_name": "wifi_network_recommendation.joblib",
            "feature_count": RECOMMENDATION_FEATURE_COUNT,
            "features": RECOMMENDATION_FEATURE_NAMES,
            "classes": CLASS_NAMES,
            "is_separate_from_awid3": True,
        },
    }
