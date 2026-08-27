"""Control and report NetShield WiFi scanner service state."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from scanner.adapter_manager import read_adapter_status


SERVICE_NAME = "netshield-ml-scanner.service"

SCANNER_STATUS_JSON = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "scan_results"
    / "scanner_status.json"
)


def _run_systemctl(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a systemctl command without prompting for a password."""

    return subprocess.run(
        ["sudo", "-n", "systemctl", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _service_exists() -> bool:
    """Return True when the scanner systemd unit is installed."""

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


def read_scanner_progress() -> dict:
    """Read live progress written by wifi_scanner.py."""

    empty = {
        "state": "idle",
        "interface": None,
        "sweep_number": 0,
        "current_channel": None,
        "channels_completed": 0,
        "total_channels": 0,
        "enabled_channels": [],
        "session_network_count": 0,
        "last_sweep_completed_at": None,
        "updated_at": None,
    }

    if not SCANNER_STATUS_JSON.exists():
        return empty

    try:
        payload = json.loads(
            SCANNER_STATUS_JSON.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return empty

    if not isinstance(payload, dict):
        return empty

    return {
        **empty,
        **payload,
    }


def read_scanner_status() -> dict:
    """Return scanner, service and adapter status."""

    adapter = read_adapter_status()
    progress = read_scanner_progress()

    if not _service_exists():
        progress = {
            **progress,
            "state": "idle",
            "interface": None,
            "current_channel": None,
        }

        return {
            "state": "not_configured",
            "running": False,
            "interface": None,
            "message": (
                "Scanner service has not been configured yet."
            ),
            "adapter": adapter,
            "progress": progress,
        }

    result = subprocess.run(
        ["systemctl", "is-active", SERVICE_NAME],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    service_state = result.stdout.strip().lower()

    mapping = {
        "active": "running",
        "activating": "starting",
        "deactivating": "stopping",
        "inactive": "idle",
        "failed": "error",
    }

    state = mapping.get(service_state, "idle")

    running = state in {
        "starting",
        "running",
        "stopping",
    }

    # The scanner status JSON can contain the final state from the
    # previous run. Normalize it against the real systemd state.
    if state == "idle":
        progress = {
            **progress,
            "state": "idle",
            "interface": None,
            "current_channel": None,
            "channels_completed": 0,
        }

    elif state in {"starting", "running"} and progress.get(
        "state"
    ) in {"idle", "stopping"}:
        progress = {
            **progress,
            "state": "starting",
            "interface": None,
            "current_channel": None,
        }

    elif state == "error":
        progress = {
            **progress,
            "state": "error",
            "current_channel": None,
        }

    interface = progress.get("interface") if running else None

    return {
        "state": state,
        "running": running,
        "interface": interface,
        "message": {
            "starting": "WiFi scanner is starting.",
            "running": "WiFi scanner is running.",
            "stopping": "WiFi scanner is stopping.",
            "idle": "WiFi scanner is idle.",
            "error": "WiFi scanner encountered an error.",
        }.get(state, "WiFi scanner is idle."),
        "adapter": adapter,
        "progress": progress,
    }


def start_scanner(interface: str | None) -> tuple[dict, int]:
    """Start scanning when an adapter and service are available."""

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

    selected_interface = interface or interfaces[0]

    if selected_interface not in interfaces:
        return {
            "ok": False,
            "state": "invalid_interface",
            "message": (
                f"Wireless interface '{selected_interface}' "
                "is not available."
            ),
        }, 400

    if not _service_exists():
        return {
            "ok": False,
            "state": "not_configured",
            "message": (
                "Scanner service is not configured yet."
            ),
        }, 409

    current = read_scanner_status()

    if current["running"]:
        return {
            "ok": False,
            "state": current["state"],
            "message": "WiFi scanner is already running.",
            "scanner": current,
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
                or "Unable to start WiFi scanner."
            ),
        }, 500

    return {
        "ok": True,
        "scanner": read_scanner_status(),
    }, 202


def stop_scanner() -> tuple[dict, int]:
    """Stop the WiFi scanner safely."""

    if not _service_exists():
        return {
            "ok": True,
            "state": "not_configured",
            "message": (
                "Scanner service is not configured yet."
            ),
        }, 200

    current = read_scanner_status()

    if not current["running"]:
        return {
            "ok": True,
            "scanner": current,
            "message": "WiFi scanner is already stopped.",
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
                or "Unable to stop WiFi scanner."
            ),
        }, 500

    return {
        "ok": True,
        "scanner": read_scanner_status(),
    }, 200
