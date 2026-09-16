from __future__ import annotations

import argparse
import csv
import tempfile
from pathlib import Path

from backend.ml.awid3_preprocessor import process_awid3_csv_file
from backend.ml.extracted_feature_schema import EXTRACTED_FEATURE_NAMES
from backend.ml.ml_feature_schema import ML_FEATURE_NAMES
from backend.ml.ml_feature_vector import features_to_ml_vector


def load_manifest(manifest_path: Path) -> list[dict[str, str]]:
    with manifest_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    if not rows or not {"file", "split"}.issubset(rows[0]):
        raise ValueError("Manifest must contain 'file' and 'split' columns.")

    allowed_splits = {"train", "validation", "test"}

    for row in rows:
        if row["split"] not in allowed_splits:
            raise ValueError(f"Invalid split: {row['split']}")

    return rows


def process_capture(
    input_path: Path,
    output_writer: csv.writer,
    window_seconds: float,
) -> tuple[int, int, int]:
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".csv",
            delete=False,
            encoding="utf-8",
            newline="",
        ) as temp_file:
            temp_path = Path(temp_file.name)

            fieldnames = ML_FEATURE_NAMES + ["label"]
            writer = csv.DictWriter(
                temp_file,
                fieldnames=fieldnames,
                extrasaction="ignore",
            )
            writer.writeheader()

            windows = process_awid3_csv_file(
                input_path,
                writer,
                window_seconds=window_seconds,
            )

        normal_windows = 0
        attack_windows = 0

        with temp_path.open(
            "r",
            encoding="utf-8",
            newline="",
        ) as processed_file:
            reader = csv.DictReader(processed_file)

            for feature_row in reader:
                vector = features_to_ml_vector(feature_row)

                if len(vector) != len(ML_FEATURE_NAMES):
                    raise ValueError(
                        f"Expected {len(ML_FEATURE_NAMES)} ML features, "
                        f"got {len(vector)}."
                    )

                label = int(feature_row["label"])

                if label not in (0, 1):
                    raise ValueError(f"Invalid binary label: {label}")

                output_writer.writerow(vector + [label])

                if label == 0:
                    normal_windows += 1
                else:
                    attack_windows += 1

        return windows, normal_windows, attack_windows

    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def build_split(
    manifest_rows: list[dict[str, str]],
    split_name: str,
    awid3_root: Path,
    output_path: Path,
    window_seconds: float,
) -> None:
    rows_for_split = [
        row for row in manifest_rows
        if row["split"] == split_name
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ML_FEATURE_NAMES + ["label"]

    total_windows = 0
    normal_windows = 0
    attack_windows = 0

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as output_file:

        output_writer = csv.writer(output_file)
        output_writer.writerow(fieldnames)

        for index, manifest_row in enumerate(rows_for_split, start=1):
            input_path = awid3_root / Path(manifest_row["file"])

            if not input_path.exists():
                raise FileNotFoundError(
                    f"AWID3 file not found: {input_path}"
                )

            print(
                f"[{index}/{len(rows_for_split)}] "
                f"Processing {manifest_row['file']}"
            )

            windows, normal, attack = process_capture(
                input_path,
                output_writer,
                window_seconds,
            )

            total_windows += windows
            normal_windows += normal
            attack_windows += attack

            output_file.flush()

            print(
                f"    Windows: {windows} | "
                f"Normal: {normal} | Attack: {attack}"
            )

    print(
        f"{split_name}: {total_windows} windows | "
        f"Normal: {normal_windows} | "
        f"Attack: {attack_windows}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build capture-independent AWID3 ML datasets."
    )

    parser.add_argument(
        "manifest",
        type=Path,
        help="Path to awid3_split_manifest.csv",
    )

    parser.add_argument(
        "awid3_root",
        type=Path,
        help="AWID3 CSV root directory.",
    )

    parser.add_argument(
        "output_dir",
        type=Path,
        help="Output directory for train/validation/test CSV files.",
    )

    parser.add_argument(
        "--window-seconds",
        type=float,
        default=5.0,
    )

    args = parser.parse_args()

    manifest_rows = load_manifest(args.manifest)

    print(f"Manifest captures: {len(manifest_rows)}")

    for split_name in ("train", "validation", "test"):
        count = sum(
            1
            for row in manifest_rows
            if row["split"] == split_name
        )
        print(f"{split_name} captures: {count}")

    for split_name in ("train", "validation", "test"):
        build_split(
            manifest_rows,
            split_name,
            args.awid3_root,
            args.output_dir / f"{split_name}.csv",
            args.window_seconds,
        )


if __name__ == "__main__":
    main()
