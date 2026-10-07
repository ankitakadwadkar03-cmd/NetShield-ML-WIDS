"""Synthetic dataset generator for Wi-Fi network recommendation model.

IMPORTANT TRANSPARENCY NOTICE:
This dataset is explicitly SYNTHETIC / DEMONSTRATION data generated from
IEEE 802.11 wireless networking domain principles and signal propagation models.
It is NOT real-world experimental capture data. It enables a fully reproducible,
trainable ML pipeline when real-world labeled scan surveys are unavailable.
"""

from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd

from .recommendation_schema import (
    RECOMMENDATION_FEATURE_NAMES,
    CLASS_NAMES,
    CLASS_TO_INT,
)

DATA_DIR = Path(__file__).resolve().parent / "data"
OUTPUT_CSV = DATA_DIR / "wifi_scan_recommendation_synthetic_train.csv"


def generate_synthetic_recommendation_dataset(
    n_samples: int = 1500,
    random_seed: int = 42,
) -> pd.DataFrame:
    """Generate a labeled synthetic dataset of Wi-Fi scan features and target classes."""
    np.random.seed(random_seed)

    # 1. Signal strength (RSSI) in dBm: typical distribution between -30 and -95 dBm
    rssi = np.random.normal(loc=-65.0, scale=14.0, size=n_samples)
    rssi = np.clip(rssi, -98.0, -32.0).round(1)

    # 2. Signal quality (0-100%)
    quality = np.clip(2.0 * (rssi + 100.0), 0.0, 100.0).round(1)

    # 3. Channels and Band: 70% 2.4 GHz (channels 1-13), 30% 5 GHz (channels 36, 40, 44, 48, 149, 153, 157, 161)
    is_5g = np.random.choice([0, 1], size=n_samples, p=[0.65, 0.35])
    ch_2g = np.random.choice([1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13], size=n_samples, p=[0.3, 0.3, 0.25, 0.02, 0.02, 0.02, 0.02, 0.01, 0.01, 0.01, 0.02, 0.01, 0.01])
    ch_5g = np.random.choice([36, 40, 44, 48, 149, 153, 157, 161], size=n_samples)
    channel = np.where(is_5g == 1, ch_5g, ch_2g)

    # 4. Security rank (0: Open, 1: WEP, 2: WPA, 3: WPA2, 4: WPA3)
    # Realistic distribution: WPA2 dominant (60%), WPA3 emerging (20%), Open (12%), WPA (6%), WEP (2%)
    security_rank = np.random.choice([0, 1, 2, 3, 4], size=n_samples, p=[0.12, 0.02, 0.06, 0.60, 0.20])
    is_open = np.where(security_rank == 0, 1, 0)

    # 5. Hidden SSID (approx 5% hidden)
    is_hidden = np.random.choice([0, 1], size=n_samples, p=[0.95, 0.05])

    # 6. Channel congestion (co-channel AP count: 0 to 8)
    # Higher in 2.4GHz than 5GHz
    congestion_2g = np.random.poisson(lam=3.0, size=n_samples)
    congestion_5g = np.random.poisson(lam=0.8, size=n_samples)
    channel_congestion = np.where(is_5g == 1, congestion_5g, congestion_2g)
    channel_congestion = np.clip(channel_congestion, 0, 12)

    # 7. Co-channel / adjacent channel interference risk
    overlap_risk = np.where(
        is_5g == 1,
        0.0,
        np.where(np.isin(channel, [1, 6, 11]), 0.0, np.random.uniform(1.0, 3.5, size=n_samples)),
    ).round(1)

    # 8. Nearby AP density (total APs in scan: 3 to 25)
    nearby_density = np.random.randint(3, 26, size=n_samples)

    # 9. Known hardware vendor (80% known)
    has_vendor = np.random.choice([1, 0], size=n_samples, p=[0.82, 0.18])

    # 10. Estimated SNR Proxy (-95 noise floor)
    snr_proxy = np.clip(rssi - (-95.0), 0.0, 55.0).round(1)

    # Multi-factor composite quality score calculation (0 - 100 scale)
    # Signal component (35%): RSSI -30=35, -50=30, -70=18, -85=6, -95=0
    signal_score = (quality / 100.0) * 35.0

    # Security component (30%): WPA3=30, WPA2=25, WPA=15, WEP=5, Open=0
    sec_scores = {4: 30.0, 3: 25.0, 2: 15.0, 1: 5.0, 0: 0.0}
    sec_score = np.array([sec_scores[s] for s in security_rank])

    # Congestion & interference component (20%): 0 congestion = 20, high = lower
    congestion_score = np.clip(20.0 - (channel_congestion * 2.2) - (overlap_risk * 1.5), 0.0, 20.0)

    # Band component (10%): 5 GHz = 10, 2.4 GHz = 5
    band_score = np.where(is_5g == 1, 10.0, 5.0)

    # Visibility & Vendor component (5%):
    visibility_score = np.where(is_hidden == 1, 0.0, 3.0) + np.where(has_vendor == 1, 2.0, 0.0)

    # Add realistic stochastic noise (Gaussian N(0, 3.0)) to simulate real-world environmental variance
    noise = np.random.normal(loc=0.0, scale=3.0, size=n_samples)
    composite_score = signal_score + sec_score + congestion_score + band_score + visibility_score + noise
    composite_score = np.clip(composite_score, 0.0, 100.0).round(1)

    # Target class derivation based on multi-factor score:
    # >= 78: EXCELLENT (3)
    # 62 - 77.9: GOOD (2)
    # 44 - 61.9: FAIR (1)
    # < 44: POOR (0)
    # Severe disqualifiers: Open networks or WEP cannot be EXCELLENT or GOOD regardless of signal!
    labels = []
    label_ints = []

    for i in range(n_samples):
        sc = composite_score[i]
        sec = security_rank[i]
        sig = rssi[i]

        # Insecure networks capped at FAIR or POOR
        if sec == 0:  # Open
            target = "FAIR" if sig >= -60 and channel_congestion[i] <= 2 else "POOR"
        elif sec == 1:  # WEP
            target = "POOR"
        elif sig < -82.0:  # unusable signal
            target = "POOR"
        elif sc >= 78.0 and sec >= 3:
            target = "EXCELLENT"
        elif sc >= 62.0 and sec >= 2:
            target = "GOOD"
        elif sc >= 44.0:
            target = "FAIR"
        else:
            target = "POOR"

        labels.append(target)
        label_ints.append(CLASS_TO_INT[target])

    df = pd.DataFrame({
        "signal_strength_dbm": rssi,
        "signal_quality_pct": quality,
        "channel_number": channel,
        "band_is_5ghz": is_5g,
        "security_level_rank": security_rank,
        "is_open_network": is_open,
        "is_hidden_ssid": is_hidden,
        "channel_congestion_count": channel_congestion,
        "co_channel_interference_risk": overlap_risk,
        "nearby_ap_density": nearby_density,
        "has_known_vendor": has_vendor,
        "estimated_snr_proxy": snr_proxy,
        "target_class": labels,
        "target_class_int": label_ints,
        "composite_score": composite_score,
        "dataset_type": "SYNTHETIC_DEMO",
    })

    return df


def save_default_dataset() -> Path:
    """Generate and save the synthetic training dataset if not already present."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    df = generate_synthetic_recommendation_dataset(n_samples=1600, random_seed=42)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Generated and saved synthetic recommendation dataset to {OUTPUT_CSV}")
    print(f"Total samples: {len(df)}")
    print(f"Class distribution:\n{df['target_class'].value_counts()}")
    return OUTPUT_CSV


if __name__ == "__main__":
    save_default_dataset()
