"""802.11 packet parsing for NetShield ML WIDS.

This module extracts packet metadata only.
It does NOT decide whether traffic is malicious.
Attack detection will be handled by the ML pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from scapy.layers.dot11 import Dot11


@dataclass(frozen=True)
class PacketAnalysis:
    """Normalized metadata extracted from one WiFi frame."""

    timestamp: str
    packet_type: str
    source_mac: str
    destination_mac: str
    bssid: str
    frame_type: str
    signal_strength: int | None

    def as_csv_row(self) -> dict[str, str | int | None]:
        return {
            "Timestamp": self.timestamp,
            "Packet Type": self.packet_type,
            "Source MAC": self.source_mac,
            "Destination MAC": self.destination_mac,
            "BSSID": self.bssid,
            "Frame Type": self.frame_type,
            "Signal Strength": self.signal_strength,
        }


class PacketAnalyzer:
    """Parse useful 802.11 frames without attack classification."""

    def analyze_packet(
        self,
        packet: Any,
    ) -> PacketAnalysis | None:

        if not packet.haslayer(Dot11):
            return None

        dot11 = packet[Dot11]

        packet_type = self._classify_packet(dot11)

        if packet_type is None:
            return None

        source_mac = self._normalize_mac(
            dot11.addr2
        )

        destination_mac = self._normalize_mac(
            dot11.addr1
        )

        bssid = self._extract_bssid(dot11)

        frame_type = self._frame_type_name(
            dot11.type
        )

        signal_strength = getattr(
            packet,
            "dBm_AntSignal",
            None,
        )

        return PacketAnalysis(
            timestamp=datetime.now().strftime(
                "%H:%M:%S"
            ),
            packet_type=packet_type,
            source_mac=source_mac,
            destination_mac=destination_mac,
            bssid=bssid,
            frame_type=frame_type,
            signal_strength=(
                int(signal_strength)
                if signal_strength is not None
                else None
            ),
        )

    @staticmethod
    def _classify_packet(
        dot11: Dot11,
    ) -> str | None:

        # Management frames
        if dot11.type == 0:
            subtype_map = {
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
            }

            return subtype_map.get(
                dot11.subtype,
                "Management",
            )

        # Control frames
        if dot11.type == 1:
            return "Control"

        # Data frames
        if dot11.type == 2:
            return "Data"

        return None

    def _extract_bssid(
        self,
        dot11: Dot11,
    ) -> str:

        if dot11.type == 0:
            if dot11.subtype == 4:
                return "Broadcast"

            return self._normalize_mac(
                dot11.addr3 or dot11.addr2
            )

        if dot11.type == 2:
            return self._normalize_mac(
                dot11.addr3
            )

        return "Unknown"

    @staticmethod
    def _normalize_mac(
        mac_address: str | None,
    ) -> str:

        if not mac_address:
            return "Unknown"

        if mac_address.lower() == (
            "ff:ff:ff:ff:ff:ff"
        ):
            return "Broadcast"

        return mac_address.upper()

    @staticmethod
    def _frame_type_name(
        frame_type: int,
    ) -> str:

        return {
            0: "Management",
            1: "Control",
            2: "Data",
            3: "Extension",
        }.get(
            frame_type,
            "Unknown",
        )
