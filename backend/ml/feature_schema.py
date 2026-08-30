"""Authoritative ML feature schema for NetShield."""

from __future__ import annotations


FEATURE_NAMES = [
    "total_packets",
    "packets_per_second",
    "beacon_count",
    "probe_request_count",
    "probe_response_count",
    "authentication_count",
    "deauth_count",
    "disassociation_count",
    "reassociation_count",
    "data_count",
    "control_count",
    "management_count",
    "unique_source_macs",
    "unique_destination_macs",
    "unique_bssids",
    "retry_count",
    "retry_ratio",
    "average_signal",
    "minimum_signal",
    "maximum_signal",
]


FEATURE_COUNT = len(FEATURE_NAMES)
