"""
core/device_manager.py
Windows-focused physical device detection for EDRT.

Detects ALL physical drives (PhysicalDriveX), not just mounted volumes.
Returns rich metadata: device ID, size, filesystem, mount status,
corruption flag, and whether raw-scan fallback is available.

Dependencies: psutil (always), wmi (Windows-only, optional but preferred)
"""

import os
import sys
import platform
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

SECTOR_SIZE = 512        # default sector size
MAX_PHYSICAL_DRIVES = 32 # scan PhysicalDrive0 … PhysicalDrive31


# ── Public API ─────────────────────────────────────────────────────────────────

def get_physical_devices() -> list[dict]:
    """
    Return a list of physical drive descriptors.

    Each dict contains:
        device_id     : str   – e.g. "PhysicalDrive0"
        raw_path      : str   – Windows raw device path
        size_bytes    : int
        size_gb       : float
        fs_type       : str   – e.g. "NTFS", "FAT32", "RAW", "Unknown"
        partitions    : list  – mounted partition letters / mount-points
        mounted       : bool  – True if at least one partition is accessible
        corrupted     : bool  – True if FS cannot be read
        raw_scan_ok   : bool  – True if raw sector access is possible
        model         : str   – disk model string (WMI) or ""
        serial        : str   – serial number (WMI) or ""
        interface     : str   – "USB", "SATA", "NVMe", … or "Unknown"
        status        : str   – "ready" | "corrupted" | "no_access" | "error"
        error         : str   – human-readable error detail (if any)
    """
    if platform.system() != "Windows":
        return _non_windows_fallback()
    return _windows_physical_devices()


def probe_device(raw_path: str) -> dict:
    """
    Quick probe of a single device.  Returns the same dict shape as
    get_physical_devices() but for one drive only.
    Raises PermissionError if we lack admin rights.
    """
    result = _probe_raw_access(raw_path)
    return result


# ── Windows implementation ─────────────────────────────────────────────────────

def _windows_physical_devices() -> list[dict]:
    devices = []

    # --- Step 1: enumerate physical drives via WMI (best info) ----------------
    wmi_disks = _wmi_disk_info()           # {index: {...}} or {}

    # --- Step 2: map drive letters → physical drive index via psutil ----------
    letter_map = _build_letter_map()        # {index: [letters]}

    # --- Step 3: scan PhysicalDrive0..N  --------------------------------------
    for idx in range(MAX_PHYSICAL_DRIVES):
        raw_path = rf"\\.\PhysicalDrive{idx}"

        # Skip if WMI gave us a list and this index isn't in it
        if wmi_disks and idx not in wmi_disks:
            continue

        dev = _build_device_entry(idx, raw_path, wmi_disks, letter_map)
        if dev is not None:
            devices.append(dev)

    # If WMI wasn't available and nothing was found via probing, try psutil-only
    if not devices:
        devices = _psutil_only_devices()

    return devices


def _build_device_entry(idx: int, raw_path: str,
                        wmi_disks: dict, letter_map: dict) -> Optional[dict]:
    """Build a single device dict from all available sources."""

    # --- WMI metadata ---------------------------------------------------------
    wmi = wmi_disks.get(idx, {})

    # --- psutil partition info ------------------------------------------------
    partitions = letter_map.get(idx, [])
    mounted    = len(partitions) > 0

    # --- Size (prefer WMI, fall back to raw read) -----------------------------
    size_bytes = int(wmi.get("size_bytes", 0))
    if size_bytes == 0:
        size_bytes = _get_size_via_ioctl(raw_path)
    if size_bytes == 0:
        # Drive probably doesn't exist at this index
        return None

    size_gb = round(size_bytes / (1024 ** 3), 2)

    # --- Filesystem type ------------------------------------------------------
    fs_type = wmi.get("fs_type", "")
    if not fs_type and partitions:
        fs_type = _fs_from_partitions(partitions)
    if not fs_type:
        fs_type = "RAW"

    # --- Corruption check -----------------------------------------------------
    corrupted  = _is_corrupted(raw_path, partitions, fs_type, mounted)

    # --- Raw access probe -----------------------------------------------------
    raw_scan_ok = _can_read_raw(raw_path)

    # --- Status string --------------------------------------------------------
    if corrupted:
        status = "corrupted"
    elif not raw_scan_ok:
        status = "no_access"
    else:
        status = "ready"

    return {
        "device_id":  f"PhysicalDrive{idx}",
        "raw_path":   raw_path,
        "size_bytes": size_bytes,
        "size_gb":    size_gb,
        "fs_type":    fs_type,
        "partitions": partitions,
        "mounted":    mounted,
        "corrupted":  corrupted,
        "raw_scan_ok": raw_scan_ok,
        "model":      wmi.get("model", ""),
        "serial":     wmi.get("serial", ""),
        "interface":  wmi.get("interface", "Unknown"),
        "status":     status,
        "error":      "",
    }


# ── WMI helpers ───────────────────────────────────────────────────────────────

def _wmi_disk_info() -> dict:
    """
    Query Win32_DiskDrive via the `wmi` package.
    Returns {index: {model, serial, size_bytes, interface}} or {} on failure.
    """
    try:
        import wmi  # type: ignore
        c = wmi.WMI()
        result = {}
        for disk in c.Win32_DiskDrive():
            idx = int(disk.Index)
            # MediaType → infer interface
            media = (disk.MediaType or "").lower()
            if "usb" in media or "removable" in media:
                iface = "USB"
            elif "nvme" in (disk.Model or "").lower():
                iface = "NVMe"
            elif "ssd" in media or "fixed" in media:
                iface = "SATA/SSD"
            else:
                iface = disk.InterfaceType or "Unknown"

            result[idx] = {
                "model":      (disk.Model or "").strip(),
                "serial":     (disk.SerialNumber or "").strip(),
                "size_bytes": int(disk.Size or 0),
                "interface":  iface,
                "fs_type":    "",   # filled later from partition info
            }
        return result
    except Exception as e:
        logger.debug("WMI not available: %s", e)
        return {}


# ── psutil helpers ─────────────────────────────────────────────────────────────

def _build_letter_map() -> dict:
    """
    Use psutil.disk_partitions() to map each physical drive index to its
    mounted partition letters (Windows only).

    Returns {physical_index: ["C:", "D:", …]}
    """
    try:
        import psutil
        letter_map: dict[int, list[str]] = {}

        for part in psutil.disk_partitions(all=True):
            # device looks like "C:\\"  on Windows
            letter = part.device.rstrip("\\")          # → "C:"
            phys_idx = _letter_to_physical_index(letter)
            if phys_idx is not None:
                letter_map.setdefault(phys_idx, []).append(letter)

        return letter_map
    except Exception as e:
        logger.debug("psutil partition map failed: %s", e)
        return {}


def _letter_to_physical_index(letter: str) -> Optional[int]:
    """
    Map a drive letter like 'C:' to its PhysicalDriveX index via
    Windows DeviceIoControl (IOCTL_STORAGE_GET_DEVICE_NUMBER).
    Returns None on failure.
    """
    try:
        import ctypes, ctypes.wintypes as wt

        GENERIC_READ             = 0x80000000
        FILE_SHARE_READ          = 0x00000001
        FILE_SHARE_WRITE         = 0x00000002
        OPEN_EXISTING            = 3
        IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x2D1080

        class STORAGE_DEVICE_NUMBER(ctypes.Structure):
            _fields_ = [("DeviceType", wt.DWORD),
                        ("DeviceNumber", wt.DWORD),
                        ("PartitionNumber", wt.DWORD)]

        handle = ctypes.windll.kernel32.CreateFileW(
            f"\\\\.\\{letter}",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None
        )
        if handle == ctypes.c_void_p(-1).value:
            return None

        try:
            sdn  = STORAGE_DEVICE_NUMBER()
            size = ctypes.c_ulong(0)
            ok   = ctypes.windll.kernel32.DeviceIoControl(
                handle, IOCTL_STORAGE_GET_DEVICE_NUMBER,
                None, 0,
                ctypes.byref(sdn), ctypes.sizeof(sdn),
                ctypes.byref(size), None
            )
            return int(sdn.DeviceNumber) if ok else None
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return None


def _fs_from_partitions(letters: list[str]) -> str:
    """Get filesystem type from the first mountable partition."""
    try:
        import psutil
        for part in psutil.disk_partitions(all=True):
            letter = part.device.rstrip("\\")
            if letter in letters:
                return part.fstype or "Unknown"
    except Exception:
        pass
    return "Unknown"


def _psutil_only_devices() -> list[dict]:
    """
    Fallback: build device list from psutil.disk_partitions() alone
    (no WMI, no PhysicalDrive probing).
    """
    try:
        import psutil
        seen: dict[str, dict] = {}
        for part in psutil.disk_partitions(all=True):
            letter = part.device.rstrip("\\")
            if letter in seen:
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                size_bytes = usage.total
            except Exception:
                size_bytes = 0

            idx = len(seen)
            raw_path = rf"\\.\{letter}"
            seen[letter] = {
                "device_id":   f"PhysicalDrive{idx}",
                "raw_path":    raw_path,
                "size_bytes":  size_bytes,
                "size_gb":     round(size_bytes / (1024 ** 3), 2),
                "fs_type":     part.fstype or "Unknown",
                "partitions":  [letter],
                "mounted":     True,
                "corrupted":   False,
                "raw_scan_ok": _can_read_raw(raw_path),
                "model":       "",
                "serial":      "",
                "interface":   "Unknown",
                "status":      "ready",
                "error":       "",
            }
        return list(seen.values())
    except Exception as e:
        return [_error_entry(str(e))]


# ── Raw access helpers ─────────────────────────────────────────────────────────

def _get_size_via_ioctl(raw_path: str) -> int:
    """
    Open the physical drive read-only and query its size via
    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX.
    Returns 0 if device doesn't exist or is not accessible.
    """
    try:
        import ctypes, ctypes.wintypes as wt

        GENERIC_READ   = 0x80000000
        FILE_SHARE_READ  = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING  = 3
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0

        class DISK_GEOMETRY(ctypes.Structure):
            _fields_ = [("Cylinders", ctypes.c_int64),
                        ("MediaType", wt.DWORD),
                        ("TracksPerCylinder", wt.DWORD),
                        ("SectorsPerTrack", wt.DWORD),
                        ("BytesPerSector", wt.DWORD)]

        class DISK_GEOMETRY_EX(ctypes.Structure):
            _fields_ = [("Geometry", DISK_GEOMETRY),
                        ("DiskSize", ctypes.c_int64),
                        ("Data", ctypes.c_byte * 1)]

        handle = ctypes.windll.kernel32.CreateFileW(
            raw_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None
        )
        INVALID = ctypes.c_void_p(-1).value
        if handle == INVALID:
            return 0

        try:
            geom = DISK_GEOMETRY_EX()
            size = ctypes.c_ulong(0)
            ok   = ctypes.windll.kernel32.DeviceIoControl(
                handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None, 0,
                ctypes.byref(geom), ctypes.sizeof(geom),
                ctypes.byref(size), None
            )
            return int(geom.DiskSize) if ok else 0
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return 0


def _can_read_raw(raw_path: str) -> bool:
    """Try to open the device and read the first sector. READ-ONLY."""
    try:
        with open(raw_path, "rb") as fh:
            data = fh.read(SECTOR_SIZE)
        return len(data) == SECTOR_SIZE
    except PermissionError:
        return False          # exists but needs elevation
    except (OSError, FileNotFoundError):
        return False          # device not present


def _probe_raw_access(raw_path: str) -> dict:
    """Return a minimal status dict for one device path."""
    base = {
        "raw_path":    raw_path,
        "raw_scan_ok": False,
        "corrupted":   False,
        "status":      "error",
        "error":       "",
    }
    try:
        with open(raw_path, "rb") as fh:
            sector = fh.read(SECTOR_SIZE)
        base["raw_scan_ok"] = len(sector) == SECTOR_SIZE
        base["status"]      = "ready"
    except PermissionError:
        base["error"]  = "Requires administrator privileges"
        base["status"] = "no_access"
    except OSError as e:
        base["error"]  = str(e)
        base["status"] = "error"
    return base


# ── Corruption detection ───────────────────────────────────────────────────────

def _is_corrupted(raw_path: str, partitions: list[str],
                  fs_type: str, mounted: bool) -> bool:
    """
    Mark a drive as corrupted when any of the following are true:
      - Filesystem reported as 'RAW' (Windows couldn't parse it)
      - All known partition letters fail a stat/usage call
      - Sector 0 is all-zeros or all-0xFF (blank / overwritten MBR)
      - MBR boot signature (0x55 0xAA at bytes 510-511) is absent on MBR disks
      - NTFS VBR OEM ID mismatch when fs_type is NTFS
      - First 4 sectors are identical (possible overwrite / stuck media)
    """
    # RAW filesystem → Windows couldn't mount it
    if fs_type.upper() == "RAW":
        return True

    # If we have partition letters, try to access each one
    if partitions:
        accessible = 0
        for letter in partitions:
            try:
                import psutil
                psutil.disk_usage(f"{letter}\\")
                accessible += 1
            except Exception:
                pass
        if accessible == 0:
            return True     # none of the partitions are readable

    # Deep sector-level sanity checks
    if _can_read_raw(raw_path):
        try:
            with open(raw_path, "rb") as fh:
                mbr = fh.read(SECTOR_SIZE * 4)   # read first 4 sectors at once

            if len(mbr) < SECTOR_SIZE:
                return True     # couldn't even read one sector

            sector0 = mbr[:SECTOR_SIZE]

            # All zeros or all 0xFF → blank/wiped/stuck media
            if sector0 == bytes(SECTOR_SIZE) or sector0 == bytes([0xFF] * SECTOR_SIZE):
                return True

            # MBR boot signature for MBR-partitioned disks
            # GPT disks have a protective MBR that may also carry 55 AA, so this
            # is only a hard corruption flag when the signature is completely absent
            # AND there is no GPT header in sector 1.
            mbr_sig = sector0[510:512]
            gpt_sig = mbr[SECTOR_SIZE:SECTOR_SIZE + 8]   # sector 1 magic
            if mbr_sig not in (b"\x55\xAA", b"\xAA\x55") and gpt_sig != b"EFI PART":
                return True

            # NTFS: verify OEM ID in VBR
            if fs_type.upper() == "NTFS":
                oem = sector0[3:11]
                if oem != b"NTFS    ":
                    return True

            # All-same-sector heuristic (stuck / looped read from broken media)
            if len(mbr) >= SECTOR_SIZE * 4:
                s1 = mbr[SECTOR_SIZE:SECTOR_SIZE * 2]
                s2 = mbr[SECTOR_SIZE * 2:SECTOR_SIZE * 3]
                s3 = mbr[SECTOR_SIZE * 3:SECTOR_SIZE * 4]
                if s1 == s2 == s3 and s1 != bytes(SECTOR_SIZE):
                    return True     # media returning identical sectors — likely faulty

        except PermissionError:
            pass    # can't read raw — not necessarily corrupt
        except Exception:
            pass

    return False


# ── Non-Windows stub ───────────────────────────────────────────────────────────

def _non_windows_fallback() -> list[dict]:
    """
    On Linux/macOS return a minimal entry so the Flask app doesn't crash.
    Real multi-OS support lives in drive_detector.py (existing module).
    """
    return [{
        "device_id":   "N/A",
        "raw_path":    "",
        "size_bytes":  0,
        "size_gb":     0.0,
        "fs_type":     "N/A",
        "partitions":  [],
        "mounted":     False,
        "corrupted":   False,
        "raw_scan_ok": False,
        "model":       "",
        "serial":      "",
        "interface":   "N/A",
        "status":      "error",
        "error":       "device_manager.py is Windows-only. Use drive_detector.py on this OS.",
    }]


def _error_entry(msg: str) -> dict:
    return {
        "device_id":   "Error",
        "raw_path":    "",
        "size_bytes":  0,
        "size_gb":     0.0,
        "fs_type":     "Unknown",
        "partitions":  [],
        "mounted":     False,
        "corrupted":   False,
        "raw_scan_ok": False,
        "model":       "",
        "serial":      "",
        "interface":   "Unknown",
        "status":      "error",
        "error":       msg,
    }
