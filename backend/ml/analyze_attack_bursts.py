"""
Exploratory analysis of short attack bursts inside 5-second AWID3 windows.

This script is READ-ONLY:
- It does not modify existing datasets.
- It does not modify feature schemas.
- It does not train or modify any model.

It examines AWID3 capture CSV files and measures how attack packets
are concentrated inside 1-second intervals within 5-second windows.
"""

from __future__ import annotations

import csv
import sys
from collections import defaultdict
from pathlib import Path


ATTACK_CATEGORIES = {
    "Deauth": "Deauth",
    "Disas": "Disas",
    "(Re)Assoc": "(Re)Assoc",
    "RogueAP": "RogueAP",
    "Evil_Twin": "Evil_Twin",
}


def classify_attack(label: str) -> str | None:
    label = (label or "").strip()

    if not label or label.lower() == "normal":
        return None

    for category, keyword in ATTACK_CATEGORIES.items():
        if keyword.lower() in label.lower():
            return category

    return label


def analyze_file(path: Path) -> list[dict]:
    rows = []

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            timestamp = row.get("frame.time_epoch", "").strip()

            if not timestamp:
                continue

            try:
                timestamp_value = float(timestamp)
            except ValueError:
                continue

            row["_timestamp"] = timestamp_value
            rows.append(row)

    if not rows:
        return []

    rows.sort(key=lambda row: row["_timestamp"])

    first_timestamp = rows[0]["_timestamp"]

    windows: dict[int, list[dict]] = defaultdict(list)

    for row in rows:
        window = int((row["_timestamp"] - first_timestamp) // 5)
        windows[window].append(row)

    results = []

    for window_number, window_rows in windows.items():
        attack_rows = [
            row
            for row in window_rows
            if classify_attack(row.get("Label", "")) is not None
        ]

        if not attack_rows:
            continue

        attack_categories = sorted(
            {
                classify_attack(row.get("Label", ""))
                for row in attack_rows
                if classify_attack(row.get("Label", "")) is not None
            }
        )

        one_second_buckets: dict[int, int] = defaultdict(int)

        for row in attack_rows:
            second = int(row["_timestamp"] - first_timestamp)
            one_second_buckets[second] += 1

        max_attack_1s = max(one_second_buckets.values())

        attack_count = len(attack_rows)

        concentration = max_attack_1s / attack_count

        results.append(
            {
                "file": path.name,
                "window": window_number,
                "total_packets": len(window_rows),
                "attack_packets": attack_count,
                "max_attack_1s": max_attack_1s,
                "attack_concentration": concentration,
                "attack_categories": ",".join(attack_categories),
            }
        )

    return results


def main() -> None:
    if len(sys.argv) != 2:
        print(
            "Usage:\n"
            "  python -m backend.ml.analyze_attack_bursts "
            "<AWID3_category_folder>"
        )
        sys.exit(1)

    folder = Path(sys.argv[1])

    if not folder.exists():
        print(f"ERROR: Folder does not exist: {folder}")
        sys.exit(1)

    files = sorted(folder.glob("*.csv"))

    if not files:
        print(f"ERROR: No CSV files found in {folder}")
        sys.exit(1)

    all_results = []

    for index, path in enumerate(files, start=1):
        print(f"[{index}/{len(files)}] Scanning {path.name}...")
        all_results.extend(analyze_file(path))

    output_path = Path("backend/ml/attack_burst_analysis.csv")

    fieldnames = [
        "file",
        "window",
        "total_packets",
        "attack_packets",
        "max_attack_1s",
        "attack_concentration",
        "attack_categories",
    ]

    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_results)

    print()
    print("=" * 90)
    print("ATTACK BURST ANALYSIS")
    print("=" * 90)
    print(f"Attack-containing windows: {len(all_results)}")
    print(f"Results saved to: {output_path}")
    print()

    if not all_results:
        print("No attack-containing windows found.")
        return

    print(
        f"{'Category':<15}"
        f"{'Windows':>10}"
        f"{'Avg concentration':>20}"
        f"{'>=75% burst':>15}"
        f"{'>=90% burst':>15}"
    )

    print("-" * 75)

    categories = sorted(
        {
            category
            for result in all_results
            for category in result["attack_categories"].split(",")
            if category
        }
    )

    for category in categories:
        category_results = [
            result
            for result in all_results
            if category in result["attack_categories"].split(",")
        ]

        average_concentration = sum(
            result["attack_concentration"]
            for result in category_results
        ) / len(category_results)

        burst_75 = sum(
            result["attack_concentration"] >= 0.75
            for result in category_results
        )

        burst_90 = sum(
            result["attack_concentration"] >= 0.90
            for result in category_results
        )

        print(
            f"{category:<15}"
            f"{len(category_results):>10}"
            f"{average_concentration:>20.3f}"
            f"{burst_75:>15}"
            f"{burst_90:>15}"
        )

    print()
    print(
        "Interpretation: concentration measures the fraction of attack "
        "packets occurring in the busiest 1-second interval of each "
        "5-second window."
    )


if __name__ == "__main__":
    main()
