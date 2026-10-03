"""Low-level block device metadata — cross-platform version for EDRT.

On Linux: uses ioctl for true block-device size/sector queries.
On Windows/macOS: falls back to file-stat or seek-to-end sizing.
"""

from __future__ import annotations

import os
import platform
import stat
import struct
from dataclasses import dataclass

_SYSTEM = platform.system()
_IS_LINUX = _SYSTEM == "Linux"

if _IS_LINUX:
    import fcntl
    BLKGETSIZE64 = 0x80081272
    BLKSSZGET    = 0x1268
    BLKPBSZGET   = 0x127B
    BLKROGET     = 0x125E

_DEFAULT_SECTOR_SIZE = 512


class DeviceIOError(Exception):
    def __init__(self, message: str, user_message: str):
        super().__init__(message)
        self.user_message = user_message


@dataclass
class DeviceInfo:
    size_bytes: int
    logical_sector_size: int
    physical_sector_size: int
    read_only: bool
    is_block_device: bool


def get_logical_block_size(path: str) -> int:
    return get_device_info(path).logical_sector_size


def get_device_info(path: str) -> DeviceInfo:
    fd = _open_read_only(path)
    try:
        if _IS_LINUX:
            file_stat = os.fstat(fd)
            if stat.S_ISBLK(file_stat.st_mode):
                return _get_block_device_info_linux(fd, path)
    finally:
        os.close(fd)
    return _get_file_fallback_info(path)


def _open_read_only(path: str) -> int:
    try:
        return os.open(path, os.O_RDONLY)
    except PermissionError as error:
        raise DeviceIOError(
            f"Cannot open {path}: {error}",
            f"Permission denied: cannot open {path} (run as root/Administrator).",
        ) from error
    except OSError as error:
        raise DeviceIOError(
            f"Cannot open {path}: {error}",
            f"Cannot access {path}.",
        ) from error


def _get_block_device_info_linux(fd: int, path: str) -> DeviceInfo:
    try:
        size_bytes          = _ioctl_get_u64(fd, BLKGETSIZE64)
        logical_sector_size = _ioctl_get_u32(fd, BLKSSZGET)
        read_only           = bool(_ioctl_get_u32(fd, BLKROGET))
    except PermissionError as error:
        raise DeviceIOError(
            f"Cannot read block metadata from {path}: {error}",
            f"Permission denied: cannot read {path} metadata (run as root).",
        ) from error
    except OSError as error:
        raise DeviceIOError(
            f"Cannot read block metadata from {path}: {error}",
            f"Cannot read device information from {path}.",
        ) from error

    try:
        physical_sector_size = _ioctl_get_u32(fd, BLKPBSZGET)
    except (PermissionError, OSError):
        physical_sector_size = logical_sector_size

    return DeviceInfo(
        size_bytes=size_bytes,
        logical_sector_size=logical_sector_size,
        physical_sector_size=physical_sector_size,
        read_only=read_only,
        is_block_device=True,
    )


def _get_file_fallback_info(path: str) -> DeviceInfo:
    """Works for image files and raw devices on Windows/macOS."""
    size_bytes = _probe_size(path)
    return DeviceInfo(
        size_bytes=size_bytes,
        logical_sector_size=_DEFAULT_SECTOR_SIZE,
        physical_sector_size=_DEFAULT_SECTOR_SIZE,
        read_only=not os.access(path, os.W_OK),
        is_block_device=False,
    )


def _probe_size(path: str) -> int:
    """Try multiple strategies to determine source size."""
    # 1. stat (works for regular files)
    try:
        sz = os.stat(path).st_size
        if sz > 0:
            return sz
    except OSError:
        pass

    # 2. Seek-to-end (works for block devices on Linux/macOS)
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            sz = os.lseek(fd, 0, os.SEEK_END)
            if sz > 0:
                return sz
        finally:
            os.close(fd)
    except OSError:
        pass

    # 3. Windows IOCTL
    if _SYSTEM == "Windows":
        try:
            import ctypes, ctypes.wintypes as wt
            GENERIC_READ     = 0x80000000
            FILE_SHARE_READ  = 0x00000001
            FILE_SHARE_WRITE = 0x00000002
            OPEN_EXISTING    = 3
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0

            class _DISK_GEOMETRY(ctypes.Structure):
                _fields_ = [
                    ("Cylinders", ctypes.c_int64),
                    ("MediaType", wt.DWORD),
                    ("TracksPerCylinder", wt.DWORD),
                    ("SectorsPerTrack", wt.DWORD),
                    ("BytesPerSector", wt.DWORD),
                ]

            class _DISK_GEOMETRY_EX(ctypes.Structure):
                _fields_ = [
                    ("Geometry", _DISK_GEOMETRY),
                    ("DiskSize", ctypes.c_int64),
                    ("Data", ctypes.c_byte * 1),
                ]

            handle = ctypes.windll.kernel32.CreateFileW(
                path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None
            )
            if handle != ctypes.c_void_p(-1).value:
                geom   = _DISK_GEOMETRY_EX()
                ret_sz = ctypes.c_ulong(0)
                ok     = ctypes.windll.kernel32.DeviceIoControl(
                    handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                    None, 0,
                    ctypes.byref(geom), ctypes.sizeof(geom),
                    ctypes.byref(ret_sz), None,
                )
                ctypes.windll.kernel32.CloseHandle(handle)
                if ok:
                    return int(geom.DiskSize)
        except Exception:
            pass

    return 0


# ── Linux ioctl helpers ────────────────────────────────────────────────────────

def _ioctl_get_u32(fd: int, request: int) -> int:
    data = bytearray(4)
    fcntl.ioctl(fd, request, data, True)
    return struct.unpack("<I", data)[0]


def _ioctl_get_u64(fd: int, request: int) -> int:
    data = bytearray(8)
    fcntl.ioctl(fd, request, data, True)
    return struct.unpack("<Q", data)[0]
