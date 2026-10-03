"""
core/disk_reader.py
READ-ONLY raw disk sector access for EDRT.

Provides:
  - read_sector(path, sector_number, sector_size=512) → bytes
  - read_sectors(path, start, count, sector_size=512)  → bytes
  - DiskReader class — context manager with buffered I/O for large scans

SAFETY CONTRACT
  • This module NEVER opens a file handle with write permission.
  • All opens are:  open(path, "rb")  or  CreateFile with GENERIC_READ only.
  • Any attempt to call write() will raise AttributeError (rb mode).
  • No ctypes WriteFile / DeviceIoControl calls that modify data.
"""

import os
import sys
import platform
import logging
import ctypes
import ctypes.wintypes as wt
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

# ── Defaults ───────────────────────────────────────────────────────────────────

DEFAULT_SECTOR_SIZE  = 512
DEFAULT_BUFFER_SECTS = 2048          # 1 MB buffer  (2048 × 512)
MAX_READ_SECTORS     = 128 * 1024    # 64 MB single read ceiling


# ── Simple functional API ──────────────────────────────────────────────────────

def read_sector(path: str, sector_number: int,
                sector_size: int = DEFAULT_SECTOR_SIZE) -> bytes:
    """
    Read exactly one sector from *path* at *sector_number*.

    Args:
        path          : raw device path, e.g. Windows raw device path
                        or any file / image path
        sector_number : 0-based sector index
        sector_size   : bytes per sector (default 512; use 4096 for 4Kn drives)

    Returns:
        bytes of length *sector_size*

    Raises:
        PermissionError  : elevated rights required
        OSError          : I/O error (bad sector, device gone, etc.)
        ValueError       : sector_number out of range
    """
    if sector_number < 0:
        raise ValueError(f"sector_number must be >= 0, got {sector_number}")
    offset = sector_number * sector_size
    return _safe_read(path, offset, sector_size)


def read_sectors(path: str, start_sector: int, count: int,
                 sector_size: int = DEFAULT_SECTOR_SIZE) -> bytes:
    """
    Read *count* contiguous sectors starting at *start_sector*.

    count is silently capped at MAX_READ_SECTORS to prevent accidental
    multi-GB reads.  The caller can loop with DiskReader for large scans.

    Returns:
        bytes of length (count × sector_size) — may be shorter at end-of-disk
    """
    if start_sector < 0:
        raise ValueError("start_sector must be >= 0")
    if count <= 0:
        return b""
    count   = min(count, MAX_READ_SECTORS)
    offset  = start_sector * sector_size
    length  = count * sector_size
    return _safe_read(path, offset, length)


# ── DiskReader class ───────────────────────────────────────────────────────────

class DiskReader:
    """
    Context-manager wrapper around a raw disk / image file.

    Provides:
      - read_sector(n)              → bytes
      - read_sectors(start, count)  → bytes
      - iter_chunks(chunk_sectors)  → Iterator[bytes]  (for full-disk scan)
      - total_sectors property

    Usage:
        with DiskReader(raw_device_path) as dr:  # e.g. Windows PhysicalDrive0
            mbr = dr.read_sector(0)
            for chunk in dr.iter_chunks():
                process(chunk)

    The internal buffer is *read-only*; the handle is always opened with
    'rb' / GENERIC_READ.
    """

    def __init__(self, path: str,
                 sector_size: int = DEFAULT_SECTOR_SIZE,
                 buffer_sectors: int = DEFAULT_BUFFER_SECTS):
        self.path           = path
        self.sector_size    = sector_size
        self.buffer_sectors = buffer_sectors
        self._fh            = None
        self._disk_size     = 0         # bytes; 0 = unknown

    # ── Context manager ────────────────────────────────────────────────────────

    def __enter__(self) -> "DiskReader":
        self._open()
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    # ── Properties ─────────────────────────────────────────────────────────────

    @property
    def total_sectors(self) -> int:
        """Total sector count (0 if size could not be determined)."""
        if self._disk_size:
            return self._disk_size // self.sector_size
        return 0

    @property
    def total_bytes(self) -> int:
        return self._disk_size

    # ── Read methods ───────────────────────────────────────────────────────────

    def read_sector(self, sector_number: int) -> bytes:
        """Read one sector.  Wraps global read_sector()."""
        if sector_number < 0:
            raise ValueError("sector_number must be >= 0")
        return self._read_at(sector_number * self.sector_size, self.sector_size)

    def read_sectors(self, start: int, count: int) -> bytes:
        """Read *count* sectors starting at *start*."""
        if start < 0:
            raise ValueError("start must be >= 0")
        count  = min(count, MAX_READ_SECTORS)
        offset = start * self.sector_size
        length = count * self.sector_size
        return self._read_at(offset, length)

    def iter_chunks(self, chunk_sectors: Optional[int] = None
                    ) -> Iterator[tuple[int, bytes]]:
        """
        Yield (sector_offset, data) tuples covering the entire disk in
        buffered chunks.

        chunk_sectors defaults to self.buffer_sectors (≈ 1 MB).
        Yields shorter data at the end of the disk (or on read error).

        Example:
            for sector_off, chunk in dr.iter_chunks():
                scan_for_signatures(chunk, base_offset=sector_off)
        """
        chunk = chunk_sectors or self.buffer_sectors
        offset = 0
        total  = self._disk_size or (2 ** 63)   # fallback: read until error

        while offset < total:
            read_len = min(chunk * self.sector_size, total - offset)
            try:
                data = self._read_at(offset, read_len)
            except OSError as e:
                # Bad sector — skip forward by one chunk and continue
                logger.warning("Read error at offset %d: %s — skipping chunk", offset, e)
                offset += chunk * self.sector_size
                continue

            if not data:
                break

            yield offset // self.sector_size, data
            offset += len(data)

            if len(data) < read_len:
                break   # end of device

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _open(self) -> None:
        """Open the device read-only, determine its size."""
        if self._fh is not None:
            return

        try:
            # Standard Python open — works for image files and logical drives
            self._fh = open(self.path, "rb")           # READ-ONLY enforced
        except PermissionError:
            raise PermissionError(
                f"Cannot open {self.path!r}: administrator rights required"
            )
        except FileNotFoundError:
            raise FileNotFoundError(f"Device not found: {self.path!r}")

        self._disk_size = self._detect_size()

    def _detect_size(self) -> int:
        """
        Determine device/file size in bytes.

        For regular files: os.path.getsize
        For raw devices: IOCTL on Windows, seek-to-end elsewhere.
        """
        # Regular file
        try:
            sz = os.path.getsize(self.path)
            if sz > 0:
                return sz
        except OSError:
            pass

        # Seek to end (works for block devices on Linux/macOS)
        try:
            self._fh.seek(0, 2)   # SEEK_END
            sz = self._fh.tell()
            self._fh.seek(0)
            if sz > 0:
                return sz
        except OSError:
            pass

        # Windows IOCTL
        if platform.system() == "Windows":
            sz = _win_disk_size(self.path)
            if sz:
                return sz

        return 0

    def _read_at(self, offset: int, length: int) -> bytes:
        """Low-level aligned read at *offset*."""
        if self._fh is None:
            raise RuntimeError("DiskReader is not open — use as context manager")

        # Align offset to sector boundary (required for raw devices)
        aligned_offset = (offset // self.sector_size) * self.sector_size
        prefix_skip    = offset - aligned_offset
        aligned_length = _align_up(prefix_skip + length, self.sector_size)

        try:
            self._fh.seek(aligned_offset)
            data = self._fh.read(aligned_length)
        except OSError as e:
            raise OSError(f"Read error at offset {offset}: {e}") from e

        # Trim to requested window
        result = data[prefix_skip : prefix_skip + length]
        return result


# ── Module-level helper that doesn't need a DiskReader instance ───────────────

def _safe_read(path: str, offset: int, length: int) -> bytes:
    """
    Open *path* read-only, seek to *offset*, read *length* bytes.
    Handles alignment for raw devices.
    """
    sector_size = DEFAULT_SECTOR_SIZE

    aligned_offset = (offset // sector_size) * sector_size
    prefix_skip    = offset - aligned_offset
    aligned_length = _align_up(prefix_skip + length, sector_size)

    try:
        with open(path, "rb") as fh:      # READ-ONLY
            fh.seek(aligned_offset)
            raw = fh.read(aligned_length)
    except PermissionError:
        raise PermissionError(
            f"Cannot read {path!r}: administrator rights required"
        )

    result = raw[prefix_skip : prefix_skip + length]
    return result


# ── Windows IOCTL size query ───────────────────────────────────────────────────

def _win_disk_size(path: str) -> int:
    """Query disk size via Windows IOCTL_DISK_GET_DRIVE_GEOMETRY_EX."""
    try:
        GENERIC_READ    = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE= 0x00000002
        OPEN_EXISTING   = 3
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
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None, OPEN_EXISTING, 0, None
        )
        if handle == ctypes.c_void_p(-1).value:
            return 0
        try:
            geom = DISK_GEOMETRY_EX()
            ret_sz = ctypes.c_ulong(0)
            ok = ctypes.windll.kernel32.DeviceIoControl(
                handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None, 0,
                ctypes.byref(geom), ctypes.sizeof(geom),
                ctypes.byref(ret_sz), None
            )
            return int(geom.DiskSize) if ok else 0
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return 0


# ── Utility ────────────────────────────────────────────────────────────────────

def _align_up(value: int, alignment: int) -> int:
    """Round *value* up to the next multiple of *alignment*."""
    return ((value + alignment - 1) // alignment) * alignment
