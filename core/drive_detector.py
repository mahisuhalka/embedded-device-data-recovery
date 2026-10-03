"""
core/drive_detector.py
Detects all connected external storage devices.
Works on Windows, Mac, and Linux.
"""

import os
import sys
import platform


def get_external_drives():
    """
    Returns a list of dicts describing connected external drives.
    Each dict: { name, path, size_gb, fs_type, removable, status }
    """
    system = platform.system()
    if system == "Windows":
        return _windows_drives()
    elif system == "Darwin":
        return _mac_drives()
    else:
        return _linux_drives()


# ── Windows ───────────────────────────────────────────────────────────────────
def _windows_drives():
    drives = []
    try:
        import ctypes
        import string

        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                path = f"{letter}:\\"
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(path)
                # 2 = removable, 3 = fixed, 4 = network, 5 = cdrom, 6 = ramdisk
                if drive_type in (2, 3):
                    info = _get_windows_drive_info(path, drive_type)
                    if info:
                        drives.append(info)
            bitmask >>= 1
    except Exception as e:
        drives.append({
            "name": "Error detecting drives",
            "path": "",
            "size_gb": 0,
            "fs_type": "unknown",
            "removable": False,
            "status": f"error: {str(e)}"
        })
    return drives


def _get_windows_drive_info(path, drive_type):
    import ctypes
    try:
        # Get size
        free_bytes  = ctypes.c_ulonglong(0)
        total_bytes = ctypes.c_ulonglong(0)
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            path, None, ctypes.byref(total_bytes), ctypes.byref(free_bytes)
        )
        size_gb = round(total_bytes.value / (1024**3), 1)

        # Get volume label and FS type
        vol_name   = ctypes.create_unicode_buffer(261)
        fs_name    = ctypes.create_unicode_buffer(261)
        ctypes.windll.kernel32.GetVolumeInformationW(
            path, vol_name, 261, None, None, None, fs_name, 261
        )

        label   = vol_name.value or f"Drive {path[0]}"
        fs_type = fs_name.value or "Unknown"
        removable = (drive_type == 2)

        # Raw device path for sector reading
        raw_path = f"\\\\.\\{path[0]}:"

        return {
            "name":      f"{label} ({path[0]}:)",
            "path":      path,
            "raw_path":  raw_path,
            "size_gb":   size_gb,
            "fs_type":   fs_type,
            "removable": removable,
            "status":    "ready",
            "letter":    path[0]
        }
    except Exception:
        return None


# ── macOS ─────────────────────────────────────────────────────────────────────
def _mac_drives():
    drives = []
    try:
        import subprocess, json
        result = subprocess.run(
            ["diskutil", "list", "-plist", "external"],
            capture_output=True, text=True
        )
        import plistlib
        data = plistlib.loads(result.stdout.encode())
        disks = data.get("AllDisksAndPartitions", [])
        for disk in disks:
            disk_id = disk.get("DeviceIdentifier", "")
            info_result = subprocess.run(
                ["diskutil", "info", "-plist", disk_id],
                capture_output=True, text=True
            )
            info = plistlib.loads(info_result.stdout.encode())
            size_bytes = info.get("TotalSize", 0)
            drives.append({
                "name":      info.get("VolumeName") or info.get("MediaName", disk_id),
                "path":      info.get("MountPoint", f"/dev/{disk_id}"),
                "raw_path":  f"/dev/r{disk_id}",
                "size_gb":   round(size_bytes / (1024**3), 1),
                "fs_type":   info.get("FilesystemType", "unknown"),
                "removable": info.get("Removable", False),
                "status":    "ready"
            })
    except Exception as e:
        drives.append({"name": f"Error: {e}", "path": "", "size_gb": 0,
                       "fs_type": "unknown", "removable": False, "status": "error"})
    return drives


# ── Linux ─────────────────────────────────────────────────────────────────────
def _linux_drives():
    drives = []
    try:
        import subprocess, json
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,SIZE,FSTYPE,LABEL,MOUNTPOINT,RM,TYPE"],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        for device in data.get("blockdevices", []):
            if device.get("type") != "disk":
                continue
            removable = device.get("rm", "0") == "1"
            name = device.get("name", "")
            label = device.get("label") or name
            size_str = device.get("size", "0")
            size_gb = _parse_size(size_str)
            mount = device.get("mountpoint") or f"/dev/{name}"
            drives.append({
                "name":      f"{label} (/dev/{name})",
                "path":      mount,
                "raw_path":  f"/dev/{name}",
                "size_gb":   size_gb,
                "fs_type":   device.get("fstype") or "unknown",
                "removable": removable,
                "status":    "ready"
            })
    except Exception as e:
        drives.append({"name": f"Error: {e}", "path": "", "size_gb": 0,
                       "fs_type": "unknown", "removable": False, "status": "error"})
    return drives


def _parse_size(size_str):
    """Convert '16G', '500M' etc to GB float."""
    try:
        if size_str.endswith("G"):
            return float(size_str[:-1])
        elif size_str.endswith("T"):
            return float(size_str[:-1]) * 1024
        elif size_str.endswith("M"):
            return round(float(size_str[:-1]) / 1024, 2)
        return 0
    except Exception:
        return 0
