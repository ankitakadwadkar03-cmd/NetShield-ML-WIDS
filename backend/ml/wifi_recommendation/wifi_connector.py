"""Secure Wi-Fi connection service for NetShield.

Handles OS-level Wi-Fi connection requests via controlled network management tools
(NetworkManager / nmcli on Linux, netsh on Windows) without arbitrary shell execution.

SECURITY RULES:
- Never store or log Wi-Fi passwords.
- Never write passwords to database or persistent logs.
- Strictly use subprocess argument lists (shell=False) to prevent command injection.
- Validate SSID and credentials before attempting connection.
- Immediately overwrite password variables in memory after use.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def validate_connection_input(ssid: Any, password: Any) -> tuple[bool, str]:
    """Validate SSID and password inputs against 802.11 standards."""
    if not ssid or not isinstance(ssid, str):
        return False, "SSID is required and must be a valid string."

    clean_ssid = ssid.strip()
    if len(clean_ssid) < 1 or len(clean_ssid.encode("utf-8")) > 32:
        return False, "SSID length must be between 1 and 32 bytes."

    # Reject null bytes or control characters in SSID
    if any(ord(c) < 32 or ord(c) == 127 for c in clean_ssid):
        return False, "SSID contains invalid control characters."

    if password is not None:
        if not isinstance(password, str):
            return False, "Password must be a string."
        # WPA-PSK standard length is 8 to 63 ASCII characters (or empty for open)
        if len(password) > 0 and len(password) < 8:
            return False, "Wi-Fi password must be at least 8 characters long."
        if len(password) > 63:
            return False, "Wi-Fi password cannot exceed 63 characters."

    return True, "Valid"


def attempt_wifi_connection(ssid: str, password: str | None = None) -> dict[str, Any]:
    """Attempt connecting to the specified Wi-Fi network using the OS network manager."""
    is_valid, validation_msg = validate_connection_input(ssid, password)
    if not is_valid:
        return {
            "success": False,
            "connected": False,
            "ssid": ssid,
            "message": validation_msg,
            "os": sys.platform,
        }

    clean_ssid = ssid.strip()
    pwd = password.strip() if password else ""

    try:
        if sys.platform.startswith("linux"):
            return _connect_linux(clean_ssid, pwd)
        elif sys.platform == "win32":
            return _connect_windows(clean_ssid, pwd)
        else:
            return {
                "success": False,
                "connected": False,
                "ssid": clean_ssid,
                "message": f"Operating system '{sys.platform}' does not support automated Wi-Fi control.",
                "os": sys.platform,
            }
    finally:
        # Wipe sensitive credentials from local memory
        pwd = None
        del pwd
        password = None
        del password


def _connect_linux(ssid: str, password: str) -> dict[str, Any]:
    """Attempt connection on Linux using NetworkManager (nmcli)."""
    nmcli_path = shutil.which("nmcli")
    if not nmcli_path:
        return {
            "success": False,
            "connected": False,
            "ssid": ssid,
            "message": "NetworkManager ('nmcli') is not installed or available on this Linux host.",
            "os": "linux",
        }

    cmd = [nmcli_path, "dev", "wifi", "connect", ssid]
    if password:
        cmd.extend(["password", password])

    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=25,
            shell=False,
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        # Sanitize any accidental password echo in output
        sanitized_msg = (stdout or stderr).replace(password, "********") if password else (stdout or stderr)

        if result.returncode == 0:
            return {
                "success": True,
                "connected": True,
                "ssid": ssid,
                "message": f"Successfully connected to Wi-Fi network '{ssid}'.",
                "output": sanitized_msg,
                "os": "linux",
            }
        else:
            return {
                "success": False,
                "connected": False,
                "ssid": ssid,
                "message": f"Connection failed: {sanitized_msg or 'Access point rejected connection request.'}",
                "os": "linux",
            }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "connected": False,
            "ssid": ssid,
            "message": "Connection attempt timed out after 25 seconds. Verify access point is in range.",
            "os": "linux",
        }
    except Exception as exc:
        return {
            "success": False,
            "connected": False,
            "ssid": ssid,
            "message": f"Connection error: {str(exc)}",
            "os": "linux",
        }


def _connect_windows(ssid: str, password: str) -> dict[str, Any]:
    """Attempt connection on Windows using netsh wlan."""
    netsh_path = shutil.which("netsh")
    if not netsh_path:
        return {
            "success": False,
            "connected": False,
            "ssid": ssid,
            "message": "Windows 'netsh' tool is not accessible.",
            "os": "win32",
        }

    # First check wireless interface status
    try:
        if_check = subprocess.run(
            [netsh_path, "wlan", "show", "interfaces"],
            check=False,
            capture_output=True,
            text=True,
            timeout=6,
            shell=False,
        )
        if "There is no wireless interface on the system" in if_check.stdout:
            return {
                "success": False,
                "connected": False,
                "ssid": ssid,
                "message": "No active wireless Wi-Fi adapter found on this Windows machine.",
                "os": "win32",
            }
    except Exception:
        pass

    # Check if a profile already exists for this SSID
    has_profile = False
    try:
        prof_check = subprocess.run(
            [netsh_path, "wlan", "show", "profile", f"name={ssid}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=6,
            shell=False,
        )
        if prof_check.returncode == 0:
            has_profile = True
    except Exception:
        pass

    temp_xml_path = None
    try:
        # If no existing profile and password is provided, create a temporary XML profile
        if not has_profile and password:
            # Generate hex SSID representation
            ssid_hex = "".join(f"{ord(c):02X}" for c in ssid)
            auth_type = "WPA2PSK"
            cipher_type = "AES"

            xml_content = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <hex>{ssid_hex}</hex>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth_type}</authentication>
                <encryption>{cipher_type}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""

            # Save to temporary secure file
            with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as tmp_file:
                tmp_file.write(xml_content)
                temp_xml_path = tmp_file.name

            # Add profile to Windows WLAN service
            add_res = subprocess.run(
                [netsh_path, "wlan", "add", "profile", f"filename={temp_xml_path}", "user=current"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
            )

        # Connect command
        connect_res = subprocess.run(
            [netsh_path, "wlan", "connect", f"name={ssid}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            shell=False,
        )

        out = connect_res.stdout.strip()
        if "Connection request was completed successfully" in out:
            return {
                "success": True,
                "connected": True,
                "ssid": ssid,
                "message": f"Connection request for '{ssid}' completed successfully.",
                "os": "win32",
            }
        else:
            return {
                "success": False,
                "connected": False,
                "ssid": ssid,
                "message": out or f"Unable to connect to '{ssid}'. Verify password and adapter status.",
                "os": "win32",
            }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "connected": False,
            "ssid": ssid,
            "message": "Windows connection attempt timed out.",
            "os": "win32",
        }
    except Exception as exc:
        return {
            "success": False,
            "connected": False,
            "ssid": ssid,
            "message": f"Windows connection failed: {str(exc)}",
            "os": "win32",
        }
    finally:
        # Crucial security step: always delete the temporary XML profile file immediately
        if temp_xml_path and os.path.exists(temp_xml_path):
            try:
                os.remove(temp_xml_path)
            except OSError:
                pass
