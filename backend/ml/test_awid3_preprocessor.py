"""Focused validation for AWID3 preprocessing."""

from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from .awid3_preprocessor import (
    OUTPUT_LABEL_COLUMN,
    awid3_row_to_packet,
    process_awid3_dataset,
)
from .feature_extractor import extract_window_features, group_packets_by_time_window
from .feature_schema import FEATURE_NAMES


AWID3_TEST_FIELDS = [
    "frame.time_epoch",
    "radiotap.dbm_antsignal",
    "wlan.bssid",
    "wlan.da",
    "wlan.ra",
    "wlan.sa",
    "wlan.fc.type",
    "wlan.fc.subtype",
    "wlan.fc.retry",
    "wlan.ssid",
    "Label",
]


def _row(
    timestamp: str,
    label: str,
    subtype: str = "8",
    retry: str = "0",
    signal: str = "-40",
) -> dict[str, str]:
    return {
        "frame.time_epoch": timestamp,
        "radiotap.dbm_antsignal": signal,
        "wlan.bssid": "00:11:22:33:44:55",
        "wlan.da": "ff:ff:ff:ff:ff:ff",
        "wlan.ra": "",
        "wlan.sa": "66:77:88:99:aa:bb",
        "wlan.fc.type": "0",
        "wlan.fc.subtype": subtype,
        "wlan.fc.retry": retry,
        "wlan.ssid": "TestNet",
        "Label": label,
    }


class AWID3PreprocessorTest(unittest.TestCase):
    def _write_rows_and_read_output(
        self,
        rows: list[dict[str, str]],
        chunk_rows: int = 2,
    ) -> tuple[int, list[dict[str, str]], list[str] | None]:
        with tempfile.TemporaryDirectory() as temp_dir:
            input_csv = Path(temp_dir) / "awid3.csv"
            output_csv = Path(temp_dir) / "features.csv"

            with input_csv.open("w", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=AWID3_TEST_FIELDS)
                writer.writeheader()
                writer.writerows(rows)

            window_count = process_awid3_dataset(
                input_csv,
                output_csv,
                chunk_rows=chunk_rows,
            )

            with output_csv.open("r", newline="", encoding="utf-8") as csv_file:
                reader = csv.DictReader(csv_file)
                output_rows = list(reader)
                fieldnames = reader.fieldnames

        return window_count, output_rows, fieldnames

    def test_processes_five_second_windows_and_binary_labels(self) -> None:
        rows = [
            _row("100.0", "Normal", subtype="8"),
            _row("101.0", "Normal", subtype="4"),
            _row("105.0", "Normal", subtype="5"),
            _row("106.0", "Deauth", subtype="12", retry="1"),
        ]

        window_count, output_rows, fieldnames = self._write_rows_and_read_output(rows)

        self.assertEqual(window_count, 2)
        self.assertEqual(fieldnames, [*FEATURE_NAMES, OUTPUT_LABEL_COLUMN])
        self.assertEqual(len(output_rows), 2)
        self.assertEqual(output_rows[0][OUTPUT_LABEL_COLUMN], "0")
        self.assertEqual(output_rows[1][OUTPUT_LABEL_COLUMN], "1")
        self.assertEqual(output_rows[0]["total_packets"], "2")
        self.assertEqual(output_rows[1]["total_packets"], "2")
        self.assertEqual(output_rows[0]["beacon_count"], "1")
        self.assertEqual(output_rows[1]["deauth_count"], "1")
        self.assertEqual(output_rows[1]["retry_count"], "1")

    def test_out_of_order_rows_match_live_window_semantics(self) -> None:
        rows = [
            _row("106.0", "Deauth", subtype="12"),
            _row("100.0", "Normal", subtype="8"),
            _row("105.0", "Normal", subtype="5"),
            _row("101.0", "Normal", subtype="4"),
        ]

        window_count, output_rows, fieldnames = self._write_rows_and_read_output(
            rows,
            chunk_rows=2,
        )
        packets = [
            packet
            for packet in (awid3_row_to_packet(row) for row in rows)
            if packet is not None
        ]
        expected_windows = group_packets_by_time_window(packets)
        expected_feature_rows = [
            extract_window_features(window)
            for window in expected_windows
        ]

        self.assertEqual(window_count, len(expected_windows))
        self.assertEqual(fieldnames, [*FEATURE_NAMES, OUTPUT_LABEL_COLUMN])
        self.assertEqual(output_rows[0][OUTPUT_LABEL_COLUMN], "0")
        self.assertEqual(output_rows[1][OUTPUT_LABEL_COLUMN], "1")

        for output_row, expected_row in zip(output_rows, expected_feature_rows):
            for feature_name in FEATURE_NAMES:
                self.assertEqual(
                    float(output_row[feature_name]),
                    float(expected_row[feature_name] or 0),
                )

    def test_missing_values_are_safe(self) -> None:
        packet = awid3_row_to_packet(
            {
                "frame.time_epoch": "200.25",
                "radiotap.dbm_antsignal": "",
                "wlan.bssid": "",
                "wlan.da": "",
                "wlan.ra": "",
                "wlan.sa": "",
                "wlan.fc.type": "",
                "wlan.fc.subtype": "",
                "wlan.fc.retry": "",
                "Label": "Normal",
            }
        )

        self.assertIsNotNone(packet)
        self.assertEqual(packet["timestamp_epoch"], 200.25)
        self.assertEqual(packet["packet_type"], "Unknown")
        self.assertEqual(packet["frame_type"], "Unknown")
        self.assertEqual(packet["source_mac"], "Unknown")
        self.assertEqual(packet["destination_mac"], "Unknown")
        self.assertEqual(packet["bssid"], "Unknown")
        self.assertIsNone(packet["signal_strength"])
        self.assertEqual(packet["retry_flag"], 0)


if __name__ == "__main__":
    unittest.main()
