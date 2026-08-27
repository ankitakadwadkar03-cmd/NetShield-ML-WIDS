"""Protected packet-capture service control for NetShield ML WIDS."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from scanner.adapter_manager import read_adapter_status
from scanner.scanner_service import read_scanner_status


SERVICE_NAME = "netshield-ml-capture.service"
SERVICE_INTERFACE = "wlan0"

PACKET_LOG_CSV = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "packet_logs"
    / "wifi_packets.csv"
)

CAPTURE_STATUS_JSON = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "packet_logs"
    / "capture_status.json"
)


def _run_systemctl(
    arguments: list[str],
) -> subprocess.CompletedProcess[str]:

    return subprocess.run(
        ["sudo", "-n", "systemctl", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _service_exists() -> bool:

    if shutil.which("systemctl") is None:
        return False

    result = subprocess.run(
        [
            "systemctl",
            "show",
            SERVICE_NAME,
            "--property=LoadState",
            "--value",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    return (
        result.returncode == 0
        and result.stdout.strip().lower() == "loaded"
    )


def _read_service_pid() -> int | None:

    result = subprocess.run(
        [
            "systemctl",
            "show",
            SERVICE_NAME,
            "--property=MainPID",
            "--value",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    try:
        pid = int(result.stdout.strip())
    except (TypeError, ValueError):
        return None

    return pid if pid > 0 else None


def read_capture_progress() -> dict:

    empty = {
        "state": "idle",
        "interface": None,
        "last_error": "",
        "packet_count": 0,
        "session_start_row": 0,
        "packet_rate": 0.0,
        "elapsed_seconds": 0.0,
        "packet_type_counts": {},
        "started_at": None,
        "last_packet_at": None,
        "current_channel": None,
        "channel_index": 0,
        "total_channels": 0,
        "enabled_channels": [],
        "sweep_number": 0,
        "updated_at": None,
    }

    if not CAPTURE_STATUS_JSON.exists():
        return empty

    try:
        payload = json.loads(
            CAPTURE_STATUS_JSON.read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError):
        return empty

    if not isinstance(payload, dict):
        return empty

    return {
        **empty,
        **payload,
    }


def read_capture_status() -> dict:

    adapter = read_adapter_status()
    progress = read_capture_progress()

    if not _service_exists():

        return {
            "state": "not_configured",
            "running": False,
            "interface": None,
            "pid": None,
            "message": (
                "Packet-capture service has not been configured yet."
            ),
            "adapter": adapter,
            "packet_log_found": PACKET_LOG_CSV.exists(),
            "progress": progress,
        }

    result = subprocess.run(
        [
            "systemctl",
            "is-active",
            SERVICE_NAME,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    service_state = result.stdout.strip().lower()

    state = {
        "active": "running",
        "activating": "starting",
        "deactivating": "stopping",
        "inactive": "idle",
        "failed": "error",
    }.get(
        service_state,
        "idle",
    )

    running = state in {
        "starting",
        "running",
        "stopping",
    }

    if state == "idle":
        progress = {
            **progress,
            "state": "idle",
            "interface": None,
            "current_channel": None,
            "channel_index": 0,
            "packet_rate": 0.0,
        }

    interface = (
        progress.get("interface")
        if running
        else None
    )

    return {
        "state": state,
        "running": running,
        "interface": interface,
        "pid": _read_service_pid() if running else None,
        "message": {
            "starting": "Packet capture is starting.",
            "running": "Packet capture is running.",
            "stopping": "Packet capture is stopping.",
            "idle": "Packet capture is idle.",
            "error": "Packet capture encountered an error.",
        }.get(
            state,
            "Packet capture is idle.",
        ),
        "adapter": adapter,
        "packet_log_found": PACKET_LOG_CSV.exists(),
        "progress": progress,
    }


def start_capture(
    interface: str | None,
) -> tuple[dict, int]:

    scanner = read_scanner_status()

    if scanner["running"]:
        return {
            "ok": False,
            "state": "service_conflict",
            "message": (
                "Stop WiFi scanning before starting packet capture."
            ),
        }, 409

    adapter = read_adapter_status()

    if not adapter["available"]:
        return {
            "ok": False,
            "state": "not_detected",
            "message": adapter["message"],
        }, 409

    interfaces = [
        item["name"]
        for item in adapter["interfaces"]
    ]

    selected = interface or interfaces[0]

    if selected not in interfaces:
        return {
            "ok": False,
            "state": "invalid_interface",
            "message": (
                f"Wireless interface '{selected}' is unavailable."
            ),
        }, 400

    if selected != SERVICE_INTERFACE:
        return {
            "ok": False,
            "state": "interface_not_configured",
            "message": (
                "Packet-capture service is configured for "
                f"{SERVICE_INTERFACE}, not {selected}."
            ),
        }, 409

    if not _service_exists():
        return {
            "ok": False,
            "state": "not_configured",
            "message": (
                "Packet-capture service is not configured yet."
            ),
        }, 409

    current = read_capture_status()

    if current["running"]:
        return {
            "ok": False,
            "state": current["state"],
            "message": "Packet capture is already running.",
            "capture": current,
        }, 409

    result = _run_systemctl(
        ["start", SERVICE_NAME]
    )

    if result.returncode != 0:
        return {
            "ok": False,
            "state": "error",
            "message": (
                result.stderr.strip()
                or result.stdout.strip()
                or "Unable to start packet capture."
            ),
        }, 500

    return {
        "ok": True,
        "capture": read_capture_status(),
    }, 202


def stop_capture() -> tuple[dict, int]:

    if not _service_exists():
        return {
            "ok": True,
            "state": "not_configured",
            "message": (
                "Packet-capture service is not configured yet."
            ),
        }, 200

    current = read_capture_status()

    if not current["running"]:
        return {
            "ok": True,
            "capture": current,
            "message": "Packet capture is already stopped.",
        }, 200

    result = _run_systemctl(
        ["stop", SERVICE_NAME]
    )

    if result.returncode != 0:
        return {
            "ok": False,
            "state": "error",
            "message": (
                result.stderr.strip()
                or result.stdout.strip()
                or "Unable to stop packet capture."
            ),
        }, 500

    return {
        "ok": True,
        "capture": read_capture_status(),
    }, 200
