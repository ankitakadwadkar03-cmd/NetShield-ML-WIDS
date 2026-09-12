"""Feature schema for the first AWID3 binary ML model.

This 17-feature model schema intentionally excludes the three signal-statistics
features because AWID3 validation showed signal is missing in all tested Normal
windows but present in tested Attack windows.
"""

from __future__ import annotations


ML_FEATURE_NAMES = [
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
    "deauth_per_second",
    "disassociation_per_second",
    "reassociation_per_second",
    "beacon_per_second",
    "management_ratio",
    "control_ratio",
    "data_ratio",
    "clients_per_bssid",
]


ML_FEATURE_COUNT = len(ML_FEATURE_NAMES)
