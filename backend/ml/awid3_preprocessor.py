"""AWID3 CSV preprocessing for NetShield ML training data.

This module converts AWID3 packet rows into the same 5-second window
feature rows used by the live NetShield pipeline. It does not train a
model or make attack decisions.
"""

from __future__ import annotations

import argparse
import csv
import heapq
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Iterator

try:
    from .extracted_feature_schema import EXTRACTED_FEATURE_NAMES
    from .feature_extractor import extract_window_features
except ImportError:  # pragma: no cover - supports direct script execution.
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from backend.ml.extracted_feature_schema import EXTRACTED_FEATURE_NAMES
    from backend.ml.feature_extractor import extract_window_features


DEFAULT_WINDOW_SECONDS = 5.0
DEFAULT_CHUNK_ROWS = 50_000
LABEL_COLUMN = "Label"
OUTPUT_LABEL_COLUMN = "label"
SORT_FIELDNAMES = [
    "timestamp_epoch",
    "label",
    "packet_type",
    "source_mac",
    "destination_mac",
    "bssid",
    "ssid",
    "frame_type",
    "frame_type_id",
    "frame_subtype_id",
    "signal_strength",
    "channel",
    "retry_flag",
]
INTEGER_PACKET_FIELDS = {
    "label",
    "frame_type_id",
    "frame_subtype_id",
    "signal_strength",
    "channel",
    "retry_flag",
}


def _clean_text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _safe_float(value: Any) -> float | None:
    text = _clean_text(value)

    if not text:
        return None

    try:
        return float(text)
    except ValueError:
        return None


def _safe_int(value: Any) -> int | None:
    number = _safe_float(value)

    if number is None:
        return None

    return int(number)


def _safe_flag(value: Any) -> int:
    text = _clean_text(value).lower()

    if text in {"1", "true", "yes", "set"}:
        return 1

    if text in {"0", "false", "no", "not set", ""}:
        return 0

    return 1 if _safe_float(text) not in (None, 0.0) else 0


def _serialize_optional(value: Any) -> Any:
    return "" if value is None else value


def _normalize_mac(value: Any) -> str:
    text = _clean_text(value)

    if not text:
        return "Unknown"

    if text.lower() == "ff:ff:ff:ff:ff:ff":
        return "Broadcast"

    return text.upper()


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


def _frame_type_name(frame_type_id: int | None) -> str:
    return {
        0: "Management",
        1: "Control",
        2: "Data",
        3: "Extension",
    }.get(frame_type_id, "Unknown")


def awid3_row_to_packet(row: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize one AWID3 CSV row for NetShield feature extraction."""

    timestamp_epoch = _safe_float(row.get("frame.time_epoch"))

    if timestamp_epoch is None:
        return None

    frame_type_id = _safe_int(row.get("wlan.fc.type"))
    frame_subtype_id = _safe_int(row.get("wlan.fc.subtype"))

    return {
        "timestamp_epoch": timestamp_epoch,
        "packet_type": _packet_type_name(frame_type_id, frame_subtype_id),
        "source_mac": _normalize_mac(row.get("wlan.sa")),
        "destination_mac": _normalize_mac(row.get("wlan.da") or row.get("wlan.ra")),
        "bssid": _normalize_mac(row.get("wlan.bssid")),
        "ssid": _clean_text(row.get("wlan.ssid")) or None,
        "frame_type": _frame_type_name(frame_type_id),
        "frame_type_id": frame_type_id,
        "frame_subtype_id": frame_subtype_id,
        "signal_strength": _safe_int(row.get("radiotap.dbm_antsignal")),
        "channel": _safe_int(row.get("wlan_radio.channel") or row.get("radiotap.channel.freq")),
        "retry_flag": _safe_flag(row.get("wlan.fc.retry")),
    }


def awid3_label_to_binary(label: Any) -> int:
    """Map AWID3 packet labels to NetShield binary window labels."""

    text = _clean_text(label)

    if not text or text.lower() == "normal":
        return 0

    return 1


def _iter_csv_chunks(
    csv_path: Path,
    chunk_rows: int,
) -> Iterator[list[dict[str, str]]]:
    with csv_path.open("r", newline="", encoding="utf-8-sig") as csv_file:
        reader = csv.DictReader(csv_file)
        chunk: list[dict[str, str]] = []

        for row in reader:
            chunk.append(row)

            if len(chunk) >= chunk_rows:
                yield chunk
                chunk = []

        if chunk:
            yield chunk


def _serialize_sort_row(
    packet: dict[str, Any],
    label: int,
) -> dict[str, Any]:
    return {
        field_name: _serialize_optional(packet.get(field_name))
        for field_name in SORT_FIELDNAMES
        if field_name != "label"
    } | {"label": label}


def _deserialize_sort_row(row: dict[str, str]) -> tuple[float, int, dict[str, Any]]:
    timestamp_epoch = _safe_float(row.get("timestamp_epoch"))

    if timestamp_epoch is None:
        raise ValueError("sorted AWID3 run row is missing timestamp_epoch")

    label = _safe_int(row.get("label")) or 0

    packet = {
        field_name: (
            _safe_int(row.get(field_name))
            if field_name in INTEGER_PACKET_FIELDS
            else _clean_text(row.get(field_name)) or None
        )
        for field_name in SORT_FIELDNAMES
        if field_name != "label"
    }
    packet["timestamp_epoch"] = timestamp_epoch

    return timestamp_epoch, label, packet


def _write_sorted_run(
    rows: list[tuple[dict[str, Any], int]],
    temp_dir: Path,
    run_index: int,
) -> Path:
    rows.sort(key=lambda item: float(item[0]["timestamp_epoch"]))
    run_path = temp_dir / f"awid3_sorted_run_{run_index}.csv"

    with run_path.open("w", newline="", encoding="utf-8") as run_file:
        writer = csv.DictWriter(run_file, fieldnames=SORT_FIELDNAMES)
        writer.writeheader()

        for packet, label in rows:
            writer.writerow(_serialize_sort_row(packet, label))

    return run_path


def _build_sorted_runs(
    csv_path: Path,
    chunk_rows: int,
    temp_dir: Path,
) -> list[Path]:
    run_paths: list[Path] = []

    for chunk in _iter_csv_chunks(csv_path, chunk_rows):
        sortable_rows: list[tuple[dict[str, Any], int]] = []

        for row in chunk:
            packet = awid3_row_to_packet(row)

            if packet is None:
                continue

            sortable_rows.append((packet, awid3_label_to_binary(row.get(LABEL_COLUMN))))

        if sortable_rows:
            run_paths.append(_write_sorted_run(sortable_rows, temp_dir, len(run_paths)))

    return run_paths


def _iter_sorted_run(run_path: Path) -> Iterator[tuple[float, int, dict[str, Any]]]:
    with run_path.open("r", newline="", encoding="utf-8") as run_file:
        reader = csv.DictReader(run_file)

        for row in reader:
            yield _deserialize_sort_row(row)


def _iter_sorted_packets(
    csv_path: Path,
    chunk_rows: int,
    temp_dir: Path,
) -> Iterator[tuple[dict[str, Any], int]]:
    run_paths = _build_sorted_runs(csv_path, chunk_rows, temp_dir)
    run_iterators = [_iter_sorted_run(run_path) for run_path in run_paths]

    for _, label, packet in heapq.merge(*run_iterators, key=lambda item: item[0]):
        yield packet, label


def iter_awid3_csv_files(input_path: str | Path) -> Iterator[Path]:
    """Yield AWID3 CSV files from one file or directory tree."""

    path = Path(input_path)

    if path.is_file():
        if path.suffix.lower() == ".csv":
            yield path
        return

    yield from sorted(file_path for file_path in path.rglob("*.csv") if file_path.is_file())


class WindowAccumulator:
    """Collect packet records into fixed 5-second windows incrementally."""

    def __init__(self, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than 0")

        self.window_seconds = window_seconds
        self.first_timestamp: float | None = None
        self.window_start: float | None = None
        self.packets: list[dict[str, Any]] = []
        self.label = 0

    def add_packet(
        self,
        packet: dict[str, Any],
        label: int,
    ) -> list[tuple[list[dict[str, Any]], int]]:
        timestamp = float(packet["timestamp_epoch"])

        if self.first_timestamp is None:
            self.first_timestamp = timestamp
            self.window_start = timestamp

        completed_windows: list[tuple[list[dict[str, Any]], int]] = []

        while (
            self.window_start is not None
            and timestamp >= self.window_start + self.window_seconds
        ):
            completed_windows.extend(self.flush())
            window_offset = int((timestamp - self.first_timestamp) // self.window_seconds)
            self.window_start = self.first_timestamp + window_offset * self.window_seconds

        self.packets.append(packet)
        self.label = max(self.label, label)

        return completed_windows

    def flush(self) -> list[tuple[list[dict[str, Any]], int]]:
        if not self.packets:
            self.label = 0
            return []

        completed = [(self.packets, self.label)]
        self.packets = []
        self.label = 0
        return completed


def _feature_row_for_window(
    packets: list[dict[str, Any]],
    label: int,
    window_seconds: float,
) -> dict[str, int | float | None]:
    features = extract_window_features(packets, window_seconds=window_seconds)
    ordered_row = {
        feature_name: features[feature_name]
        for feature_name in EXTRACTED_FEATURE_NAMES
    }
    ordered_row[OUTPUT_LABEL_COLUMN] = label
    return ordered_row


def _write_windows(
    writer: csv.DictWriter,
    windows: Iterable[tuple[list[dict[str, Any]], int]],
    window_seconds: float,
) -> int:
    written_rows = 0

    for packets, label in windows:
        writer.writerow(_feature_row_for_window(packets, label, window_seconds))
        written_rows += 1

    return written_rows


def process_awid3_csv_file(
    csv_path: str | Path,
    writer: csv.DictWriter,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
) -> int:
    """Process one AWID3 CSV file and append window feature rows."""

    accumulator = WindowAccumulator(window_seconds=window_seconds)
    written_rows = 0

    with tempfile.TemporaryDirectory(prefix="netshield_awid3_sort_") as temp_dir_name:
        temp_dir = Path(temp_dir_name)

        for packet, label in _iter_sorted_packets(Path(csv_path), chunk_rows, temp_dir):
            completed_windows = accumulator.add_packet(packet, label)
            written_rows += _write_windows(writer, completed_windows, window_seconds)

    written_rows += _write_windows(writer, accumulator.flush(), window_seconds)
    return written_rows


def process_awid3_dataset(
    input_path: str | Path,
    output_csv_path: str | Path,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    chunk_rows: int = DEFAULT_CHUNK_ROWS,
) -> int:
    """Preprocess AWID3 CSV files into NetShield feature rows."""

    output_path = Path(output_csv_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [*EXTRACTED_FEATURE_NAMES, OUTPUT_LABEL_COLUMN]
    total_windows = 0

    with output_path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()

        for csv_path in iter_awid3_csv_files(input_path):
            total_windows += process_awid3_csv_file(
                csv_path,
                writer,
                window_seconds=window_seconds,
                chunk_rows=chunk_rows,
            )
            output_file.flush()

    return total_windows


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Preprocess AWID3 CSV files into NetShield feature windows."
    )
    parser.add_argument("input_path", help="AWID3 CSV file or extracted AWID3 CSV directory.")
    parser.add_argument("output_csv", help="Destination processed feature CSV.")
    parser.add_argument("--window-seconds", type=float, default=DEFAULT_WINDOW_SECONDS)
    parser.add_argument("--chunk-rows", type=int, default=DEFAULT_CHUNK_ROWS)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    total_windows = process_awid3_dataset(
        args.input_path,
        args.output_csv,
        window_seconds=args.window_seconds,
        chunk_rows=args.chunk_rows,
    )
    print(f"Wrote {total_windows} AWID3 feature windows to {args.output_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
