"""Build the first NetShield AWID3 binary training dataset.

This script processes one or more AWID3 CSV files through the existing AWID3
preprocessor, converts each 20-feature extraction window into the authoritative
17-feature first-model vector, and writes one combined training CSV.
"""

from __future__ import annotations

import argparse
import csv
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from .awid3_preprocessor import (
        DEFAULT_CHUNK_ROWS,
        DEFAULT_WINDOW_SECONDS,
        OUTPUT_LABEL_COLUMN,
        process_awid3_csv_file,
    )
    from .feature_schema import FEATURE_NAMES
    from .ml_feature_schema import ML_FEATURE_COUNT, ML_FEATURE_NAMES
    from .ml_feature_vector import features_to_ml_vector
except ImportError:  # pragma: no cover - supports direct script execution.
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from backend.ml.awid3_preprocessor import (
        DEFAULT_CHUNK_ROWS,
        DEFAULT_WINDOW_SECONDS,
        OUTPUT_LABEL_COLUMN,
        process_awid3_csv_file,
    )
    from backend.ml.feature_schema import FEATURE_NAMES
    from backend.ml.ml_feature_schema import ML_FEATURE_COUNT, ML_FEATURE_NAMES
    from backend.ml.ml_feature_vector import features_to_ml_vector


OUTPUT_LABELS = {0, 1}


@dataclass(frozen=True)
class BuildSummary:
    """Summary counts for an AWID3 training dataset build."""

    input_file_count: int
    output_windows: int
    normal_windows: int
    attack_windows: int
    output_feature_count: int


def _parse_feature_value(value: str | None) -> float | None:
    text = str(value).strip() if value is not None else ""

    if not text:
        return None

    try:
        return float(text)
    except ValueError as exc:
        raise ValueError(f"Invalid numeric feature value: {value!r}") from exc


def _parse_label(value: str | None) -> int:
    text = str(value).strip() if value is not None else ""

    try:
        label = int(text)
    except ValueError as exc:
        raise ValueError(f"Invalid output label: {value!r}") from exc

    if label not in OUTPUT_LABELS:
        raise ValueError(f"Output label must be 0 or 1, got: {label}")

    return label


def _read_feature_row(row: dict[str, str]) -> tuple[dict[str, float | None], int]:
    features = {
        feature_name: _parse_feature_value(row.get(feature_name))
        for feature_name in FEATURE_NAMES
    }
    return features, _parse_label(row.get(OUTPUT_LABEL_COLUMN))


def _validate_ml_vector(vector: list[float]) -> None:
    if len(vector) != ML_FEATURE_COUNT:
        raise ValueError(
            "ML feature vector length mismatch: "
            f"expected {ML_FEATURE_COUNT}, got {len(vector)}"
        )


def _write_ml_row(
    writer: csv.writer,
    features: dict[str, float | None],
    label: int,
) -> None:
    vector = features_to_ml_vector(features)
    _validate_ml_vector(vector)
    writer.writerow([*vector, label])


def _convert_preprocessed_windows(
    preprocessed_csv_path: Path,
    output_writer: csv.writer,
) -> tuple[int, int, int]:
    output_windows = 0
    normal_windows = 0
    attack_windows = 0

    with preprocessed_csv_path.open("r", newline="", encoding="utf-8") as input_file:
        reader = csv.DictReader(input_file)

        for row in reader:
            features, label = _read_feature_row(row)
            _write_ml_row(output_writer, features, label)
            output_windows += 1

            if label == 0:
                normal_windows += 1
            else:
                attack_windows += 1

    return output_windows, normal_windows, attack_windows


def build_awid3_training_dataset(
    input_csv_paths: list[str | Path],
    output_csv_path: str | Path,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
) -> BuildSummary:
    """Build one combined 17-feature AWID3 training CSV.

    Input AWID3 files are processed one at a time. Each file is delegated to the
    existing chunked/external-sort AWID3 preprocessor, then streamed into the
    final first-model feature schema without retaining the whole dataset in RAM.
    """

    if ML_FEATURE_COUNT != 17:
        raise ValueError(f"Expected 17 ML features, got {ML_FEATURE_COUNT}")

    if not input_csv_paths:
        raise ValueError("At least one AWID3 CSV input path is required.")

    output_path = Path(output_csv_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    input_paths = [Path(path) for path in input_csv_paths]

    missing_paths = [str(path) for path in input_paths if not path.is_file()]

    if missing_paths:
        raise FileNotFoundError("AWID3 CSV input file not found: " + ", ".join(missing_paths))

    total_windows = 0
    normal_windows = 0
    attack_windows = 0

    with output_path.open("w", newline="", encoding="utf-8") as output_file:
        output_writer = csv.writer(output_file)
        output_writer.writerow([*ML_FEATURE_NAMES, "label"])

        with tempfile.TemporaryDirectory(prefix="netshield_awid3_windows_") as temp_dir_name:
            temp_dir = Path(temp_dir_name)

            for input_path in input_paths:
                preprocessed_path = temp_dir / f"{input_path.stem}_20_feature_windows.csv"

                with preprocessed_path.open("w", newline="", encoding="utf-8") as temp_file:
                    temp_writer = csv.DictWriter(
                        temp_file,
                        fieldnames=[*FEATURE_NAMES, OUTPUT_LABEL_COLUMN],
                    )
                    temp_writer.writeheader()
                    process_awid3_csv_file(
                        input_path,
                        temp_writer,
                        window_seconds=window_seconds,
                        chunk_rows=chunk_rows,
                    )

                file_windows, file_normal, file_attack = _convert_preprocessed_windows(
                    preprocessed_path,
                    output_writer,
                )
                total_windows += file_windows
                normal_windows += file_normal
                attack_windows += file_attack
                output_file.flush()

    return BuildSummary(
        input_file_count=len(input_paths),
        output_windows=total_windows,
        normal_windows=normal_windows,
        attack_windows=attack_windows,
        output_feature_count=ML_FEATURE_COUNT,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a 17-feature NetShield AWID3 binary training CSV."
    )
    parser.add_argument("output_csv", help="Destination combined training CSV path.")
    parser.add_argument("input_csv", nargs="+", help="One or more AWID3 CSV input files.")
    parser.add_argument("--window-seconds", type=float, default=DEFAULT_WINDOW_SECONDS)
    return parser.parse_args()


def _print_summary(summary: BuildSummary) -> None:
    print(f"Input files: {summary.input_file_count}")
    print(f"Output windows: {summary.output_windows}")
    print(f"Normal windows: {summary.normal_windows}")
    print(f"Attack windows: {summary.attack_windows}")
    print(f"Output features: {summary.output_feature_count}")


def main() -> int:
    args = _parse_args()
    summary = build_awid3_training_dataset(
        args.input_csv,
        args.output_csv,
        window_seconds=args.window_seconds,
    )
    _print_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
