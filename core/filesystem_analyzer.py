"""
core/filesystem_analyzer.py
Filesystem analysis module for EDRT.

Supports:
  - FAT32   — full directory traversal, deleted file recovery via raw cluster scan
  - NTFS    — full MFT traversal, deleted file recovery via $MFT walk
  - exFAT   — detection + basic BPB metadata (full traversal via pytsk3)

Primary engine: pytsk3 (The Sleuth Kit Python bindings)
Fallback engine: pure-Python struct-based BPB/MFT reader
  (activates automatically when pytsk3 is not installed or FS is corrupted)

Output format per file entry:
  {
      "name":     str,         # actual file name (never raw 0x000 bytes)
      "path":     str,         # full path from FS root, e.g. "/docs/report.pdf"
      "size":     int,         # logical file size in bytes
      "deleted":  bool,        # True if recovered from free/MFT space
      "fs_type":  str,         # "FAT32" | "NTFS" | "exFAT" | "Unknown"
      "metadata": {
          "created":   str | None,   # ISO-8601 or None
          "modified":  str | None,
          "accessed":  str | None,
          "attrs":     str,          # e.g. "RHSA" (Read-only/Hidden/System/Archive)
          "inode":     int | None,   # MFT record number (NTFS) or cluster (FAT)
          "cluster":   int | None,   # first cluster / VCN
      }
  }

Error / partial-result envelope returned by analyze():
  {
      "fs_type":      str,
      "files":        list[dict],   # whatever was recovered
      "total_found":  int,
      "error":        str | None,   # set when partial results returned
      "partial":      bool,
      "engine":       str,          # "pytsk3" | "fallback"
  }
"""

import os
import sys
import struct
import logging
import platform
from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

# ── pytsk3 import (optional) ──────────────────────────────────────────────────

try:
    import pytsk3
    _PYTSK3_AVAILABLE = True
except ImportError:
    _PYTSK3_AVAILABLE = False
    logger.info(
        "pytsk3 not found — using pure-Python fallback parser. "
        "Install pytsk3 for full functionality: pip install pytsk3"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def analyze(device_path: str,
            partition_offset_sectors: int = 0,
            sector_size: int = 512,
            recover_deleted: bool = True,
            max_files: int = 50_000) -> dict:
    """
    Main entry point. Analyze a filesystem on *device_path*.

    Args:
        device_path              : raw device path (e.g. PhysicalDrive1 on Windows)
                                   or image file path
        partition_offset_sectors : LBA start of the partition (0 for images
                                   that begin at the VBR)
        sector_size              : bytes per physical sector (usually 512)
        recover_deleted          : attempt deleted-file recovery
        max_files                : safety cap; stops after this many entries

    Returns:
        dict with keys: fs_type, files, total_found, error, partial, engine
    """
    result = {
        "fs_type":     "Unknown",
        "files":       [],
        "total_found": 0,
        "error":       None,
        "partial":     False,
        "engine":      "none",
    }

    # ── Detect filesystem type from VBR ────────────────────────────────────
    try:
        fs_type = _detect_fs_type(device_path, partition_offset_sectors, sector_size)
        result["fs_type"] = fs_type
    except Exception as exc:
        result["error"]   = f"FS detection failed: {exc}"
        result["partial"] = True
        logger.error("FS detection error: %s", exc)
        return result

    logger.info("Detected filesystem: %s on %s (offset=%d sectors)",
                fs_type, device_path, partition_offset_sectors)

    # ── exFAT: basic metadata only (pytsk3 handles traversal if available) ─
    if fs_type == "exFAT" and not _PYTSK3_AVAILABLE:
        try:
            meta = _exfat_basic_info(device_path, partition_offset_sectors, sector_size)
            result["files"]       = []
            result["total_found"] = 0
            result["error"]       = (
                "exFAT traversal requires pytsk3. Install it for full support. "
                f"Volume label: {meta.get('label','?')}"
            )
            result["partial"]     = True
            result["engine"]      = "fallback"
        except Exception as exc:
            result["error"]   = f"exFAT metadata read failed: {exc}"
            result["partial"] = True
        return result

    # ── Try pytsk3 first ───────────────────────────────────────────────────
    if _PYTSK3_AVAILABLE:
        try:
            files, engine = _pytsk3_analyze(
                device_path, partition_offset_sectors, sector_size,
                fs_type, recover_deleted, max_files
            )
            result["files"]       = files
            result["total_found"] = len(files)
            result["engine"]      = engine
            return result
        except Exception as exc:
            logger.warning("pytsk3 analysis failed (%s) — falling back to pure-Python", exc)
            result["error"]   = f"pytsk3 error (using fallback): {exc}"
            result["partial"] = True

    # ── Pure-Python fallback ───────────────────────────────────────────────
    try:
        files = _fallback_analyze(
            device_path, partition_offset_sectors, sector_size,
            fs_type, recover_deleted, max_files
        )
        result["files"]       = files
        result["total_found"] = len(files)
        result["engine"]      = "fallback"
    except Exception as exc:
        err_msg = f"Fallback analysis failed: {exc}"
        if result["error"]:
            result["error"] += f" | {err_msg}"
        else:
            result["error"] = err_msg
        result["partial"] = True
        logger.error("Fallback analysis error: %s", exc)

    return result


def detect_filesystem(device_path: str,
                      partition_offset_sectors: int = 0,
                      sector_size: int = 512) -> str:
    """
    Return the filesystem type string without full traversal.
    Returns one of: "FAT32", "NTFS", "exFAT", "FAT16", "Unknown"
    """
    return _detect_fs_type(device_path, partition_offset_sectors, sector_size)


# ═══════════════════════════════════════════════════════════════════════════════
# FS DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def _detect_fs_type(device_path: str,
                    partition_offset_sectors: int,
                    sector_size: int) -> str:
    """
    Read the Volume Boot Record (VBR) / BPB and identify the filesystem.

    Detection order:
      1. NTFS  — OEM ID "NTFS    " at offset 3
      2. exFAT — OEM ID "EXFAT   " at offset 3
      3. FAT32 — type label "FAT32   " at offset 82
      4. FAT16 — type label "FAT16   " at offset 54
    """
    vbr = _read_raw(device_path, partition_offset_sectors, 1, sector_size)
    if len(vbr) < 512:
        raise ValueError(f"Could not read VBR: only {len(vbr)} bytes returned")

    oem_id = vbr[3:11]

    if oem_id == b"NTFS    ":
        return "NTFS"

    if oem_id == b"EXFAT   ":
        return "exFAT"

    # FAT32 / FAT16 — check type label (may also be in the extended BPB)
    fat_type_32 = vbr[82:90]
    fat_type_16 = vbr[54:62]

    if fat_type_32 == b"FAT32   ":
        return "FAT32"
    if fat_type_16 == b"FAT16   ":
        return "FAT16"

    # ── APFS detection (basic) ──────────────────────────────────────────────
    # APFS Container Superblock magic: 'NXSB' at offset 32 within the block
    # On Apple devices the first block is typically 4096 bytes.
    # We probe both sector 0 and a wider read in case of 4K native sectors.
    try:
        apfs_probe = _read_raw(device_path, partition_offset_sectors, 8, sector_size)
        # Magic 'NXSB' = 0x4E585342 at byte offset 32 in the container superblock
        if len(apfs_probe) >= 36 and apfs_probe[32:36] == b"NXSB":
            return "APFS"
        # APFS volume superblock magic 'APSB' = 0x41505342
        if len(apfs_probe) >= 36 and apfs_probe[32:36] == b"APSB":
            return "APFS"
    except Exception:
        pass

    # ── EXT2/3/4 detection ────────────────────────────────────────────────
    # Superblock starts at byte 1024; magic = 0xEF53 at offset +56
    try:
        ext_probe = _read_raw(device_path, partition_offset_sectors, 4, sector_size)
        if len(ext_probe) >= 1024 + 58:
            magic = struct.unpack_from("<H", ext_probe, 1024 + 56)[0]
            if magic == 0xEF53:
                rev = struct.unpack_from("<I", ext_probe, 1024 + 76)[0]
                return "EXT4" if rev >= 1 else "EXT2"
    except Exception:
        pass

    # Heuristic: bytes-per-sector + sectors-per-cluster sanity check
    bps = struct.unpack_from("<H", vbr, 11)[0]
    if bps in (512, 1024, 2048, 4096):
        rsvd = struct.unpack_from("<H", vbr, 14)[0]
        num_fats = vbr[16]
        if num_fats in (1, 2) and rsvd > 0:
            fat32_sectors = struct.unpack_from("<I", vbr, 36)[0]
            if fat32_sectors > 0:
                return "FAT32"
            return "FAT16"

    return "Unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# pytsk3 ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def _pytsk3_analyze(device_path: str,
                    partition_offset_sectors: int,
                    sector_size: int,
                    fs_type: str,
                    recover_deleted: bool,
                    max_files: int) -> tuple[list[dict], str]:
    """
    Use pytsk3 (The Sleuth Kit) to traverse the filesystem.
    Returns (files_list, engine_name).
    """
    img_info  = pytsk3.Img_Info(device_path)
    fs_offset = partition_offset_sectors * sector_size
    fs_info   = pytsk3.FS_Info(img_info, offset=fs_offset)

    files: list[dict] = []

    def _walk(directory: pytsk3.Directory, current_path: str) -> None:
        if len(files) >= max_files:
            return
        for entry in directory:
            if entry.info is None or entry.info.name is None:
                continue

            raw_name = entry.info.name.name
            if isinstance(raw_name, bytes):
                name = _safe_decode(raw_name)
            else:
                name = str(raw_name)

            # Skip junk entries
            if not name or name in (".", "..") or _is_null_name(name):
                continue

            is_deleted = _pytsk3_is_deleted(entry)
            is_dir     = _pytsk3_is_dir(entry)
            size       = _pytsk3_file_size(entry)
            meta       = _pytsk3_metadata(entry, fs_type)
            full_path  = current_path.rstrip("/") + "/" + name

            files.append({
                "name":     name,
                "path":     full_path,
                "size":     size,
                "deleted":  is_deleted,
                "fs_type":  fs_type,
                "metadata": meta,
            })

            if is_dir and not is_deleted:
                try:
                    sub_dir = entry.as_directory()
                    _walk(sub_dir, full_path)
                except Exception as exc:
                    logger.debug("Cannot descend into %s: %s", full_path, exc)

    root_dir = fs_info.open_dir(path="/")
    _walk(root_dir, "")

    # Deleted file scan via orphan directory (TSK special)
    if recover_deleted and len(files) < max_files:
        try:
            orphan_dir = fs_info.open_dir(inode=fs_info.info.root_inum)
            _pytsk3_scan_orphans(orphan_dir, fs_info, files, fs_type, max_files)
        except Exception as exc:
            logger.debug("Orphan scan skipped: %s", exc)

    return files, "pytsk3"


def _pytsk3_is_deleted(entry) -> bool:
    try:
        flags = entry.info.meta.flags if entry.info.meta else 0
        return bool(flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
    except Exception:
        return False


def _pytsk3_is_dir(entry) -> bool:
    try:
        t = entry.info.meta.type if entry.info.meta else None
        return t == pytsk3.TSK_FS_META_TYPE_DIR
    except Exception:
        return False


def _pytsk3_file_size(entry) -> int:
    try:
        return entry.info.meta.size if entry.info.meta else 0
    except Exception:
        return 0


def _pytsk3_metadata(entry, fs_type: str) -> dict:
    meta = {
        "created":  None,
        "modified": None,
        "accessed": None,
        "attrs":    "",
        "inode":    None,
        "cluster":  None,
    }
    try:
        m = entry.info.meta
        if m is None:
            return meta

        meta["inode"] = int(m.addr) if m.addr else None

        if m.crtime:
            meta["created"]  = _ts_to_iso(m.crtime)
        if m.mtime:
            meta["modified"] = _ts_to_iso(m.mtime)
        if m.atime:
            meta["accessed"] = _ts_to_iso(m.atime)

        # Attribute flags
        attr_flags = m.flags if m.flags else 0
        attrs = []
        if attr_flags & getattr(pytsk3, "TSK_FS_META_FLAG_UNALLOC", 2):
            attrs.append("D")   # Deleted
        meta["attrs"] = "".join(attrs) if attrs else "A"

    except Exception as exc:
        logger.debug("Metadata extraction error: %s", exc)

    return meta


def _pytsk3_scan_orphans(directory, fs_info, files: list, fs_type: str, max_files: int) -> None:
    """Walk the TSK orphan virtual directory to find unlinked deleted files."""
    try:
        for entry in directory:
            if len(files) >= max_files:
                break
            if entry.info is None or entry.info.name is None:
                continue
            raw_name = entry.info.name.name
            name = _safe_decode(raw_name) if isinstance(raw_name, bytes) else str(raw_name)
            if not name or name in (".", "..") or _is_null_name(name):
                continue

            meta = _pytsk3_metadata(entry, fs_type)
            files.append({
                "name":     name,
                "path":     "/$OrphanFiles/" + name,
                "size":     _pytsk3_file_size(entry),
                "deleted":  True,
                "fs_type":  fs_type,
                "metadata": meta,
            })
    except Exception as exc:
        logger.debug("Orphan iteration error: %s", exc)


# ═══════════════════════════════════════════════════════════════════════════════
# PURE-PYTHON FALLBACK ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def _fallback_analyze(device_path: str,
                      partition_offset_sectors: int,
                      sector_size: int,
                      fs_type: str,
                      recover_deleted: bool,
                      max_files: int) -> list[dict]:
    """
    Dispatch to the appropriate pure-Python parser.
    """
    if fs_type == "NTFS":
        return _ntfs_fallback(device_path, partition_offset_sectors,
                              sector_size, recover_deleted, max_files)
    elif fs_type in ("FAT32", "FAT16"):
        return _fat_fallback(device_path, partition_offset_sectors,
                             sector_size, fs_type, recover_deleted, max_files)
    else:
        raise ValueError(f"No fallback parser for filesystem type: {fs_type}")


# ─── FAT32 / FAT16 Fallback ───────────────────────────────────────────────────

class _FAT32BPB:
    """Parsed BIOS Parameter Block for FAT32."""
    __slots__ = (
        "bytes_per_sector", "sectors_per_cluster", "reserved_sectors",
        "num_fats", "root_entry_count", "total_sectors_16", "fat_size_16",
        "total_sectors_32", "fat_size_32", "root_cluster",
        "volume_label", "fs_type_label",
    )

    def __init__(self, vbr: bytes):
        u16 = lambda o: struct.unpack_from("<H", vbr, o)[0]
        u32 = lambda o: struct.unpack_from("<I", vbr, o)[0]

        self.bytes_per_sector     = u16(11)
        self.sectors_per_cluster  = vbr[13]
        self.reserved_sectors     = u16(14)
        self.num_fats             = vbr[16]
        self.root_entry_count     = u16(17)   # 0 for FAT32
        self.total_sectors_16     = u16(19)
        self.fat_size_16          = u16(22)
        self.total_sectors_32     = u32(32)
        self.fat_size_32          = u32(36)   # FAT32 only
        self.root_cluster         = u32(44)   # FAT32 only (usually 2)
        self.volume_label         = _safe_decode(vbr[71:82]).strip()
        self.fs_type_label        = _safe_decode(vbr[82:90]).strip()

    @property
    def fat_size(self) -> int:
        return self.fat_size_32 if self.fat_size_32 else self.fat_size_16

    @property
    def first_fat_sector(self) -> int:
        return self.reserved_sectors

    @property
    def first_data_sector(self) -> int:
        root_dir_sectors = (
            (self.root_entry_count * 32) + (self.bytes_per_sector - 1)
        ) // self.bytes_per_sector
        return (self.reserved_sectors
                + self.num_fats * self.fat_size
                + root_dir_sectors)

    def cluster_to_sector(self, cluster: int) -> int:
        return self.first_data_sector + (cluster - 2) * self.sectors_per_cluster

    @property
    def bytes_per_cluster(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster


def _fat_fallback(device_path: str,
                  partition_offset_sectors: int,
                  sector_size: int,
                  fs_type: str,
                  recover_deleted: bool,
                  max_files: int) -> list[dict]:
    vbr = _read_raw(device_path, partition_offset_sectors, 1, sector_size)
    bpb = _FAT32BPB(vbr)

    # Read FAT table into memory (cap at 32 MB to be safe)
    fat_sectors = min(bpb.fat_size, 65536)
    fat_data = _read_raw(
        device_path,
        partition_offset_sectors + bpb.first_fat_sector,
        fat_sectors, sector_size
    )

    def next_cluster(c: int) -> int:
        """Follow FAT32 chain."""
        if len(fat_data) < (c + 1) * 4:
            return 0x0FFFFFFF
        val = struct.unpack_from("<I", fat_data, c * 4)[0] & 0x0FFFFFFF
        return val

    def is_free_cluster(c: int) -> bool:
        if len(fat_data) < (c + 1) * 4:
            return False
        return (struct.unpack_from("<I", fat_data, c * 4)[0] & 0x0FFFFFFF) == 0

    files: list[dict] = []

    def read_cluster_chain(start_cluster: int) -> bytes:
        data = b""
        seen = set()
        c = start_cluster
        while c < 0x0FFFFFF8 and c >= 2:
            if c in seen:
                break
            seen.add(c)
            sec = bpb.cluster_to_sector(c)
            data += _read_raw(
                device_path,
                partition_offset_sectors + sec,
                bpb.sectors_per_cluster,
                sector_size
            )
            c = next_cluster(c)
            if len(data) > 32 * 1024 * 1024:  # 32 MB cap per cluster chain read
                break
        return data

    def parse_dir_entries(entries_data: bytes,
                          current_path: str,
                          deleted: bool = False) -> None:
        """Parse a block of 32-byte directory entries."""
        if len(files) >= max_files:
            return

        lfn_parts: list[str] = []
        i = 0
        while i + 32 <= len(entries_data) and len(files) < max_files:
            entry = entries_data[i:i + 32]
            first_byte = entry[0]

            # 0x00 = end of directory
            if first_byte == 0x00:
                break

            # LFN entry (attribute == 0x0F)
            attr = entry[11]
            if attr == 0x0F:
                lfn_parts.append(_parse_lfn_entry(entry))
                i += 32
                continue

            is_entry_deleted = (first_byte == 0xE5)

            # Skip volume label, skip "." and ".."
            if attr & 0x08:       # volume label
                lfn_parts = []
                i += 32
                continue

            # Reconstruct name
            if lfn_parts:
                lfn_parts.reverse()
                name = "".join(lfn_parts).rstrip("\x00").rstrip("\uFFFF")
                lfn_parts = []
            else:
                name = _fat_83_name(entry)

            if not name or name in (".", "..") or _is_null_name(name):
                i += 32
                continue

            is_dir   = bool(attr & 0x10)
            size     = struct.unpack_from("<I", entry, 28)[0]
            hi       = struct.unpack_from("<H", entry, 20)[0]
            lo       = struct.unpack_from("<H", entry, 26)[0]
            start_cl = (hi << 16) | lo

            created  = _fat_datetime(entry, 16, 14)
            modified = _fat_datetime(entry, 24, 22)
            accessed = _fat_date_only(entry, 18)

            full_path = current_path.rstrip("/") + "/" + name

            files.append({
                "name":    name,
                "path":    full_path,
                "size":    size if not is_dir else 0,
                "deleted": is_entry_deleted,
                "fs_type": fs_type,
                "metadata": {
                    "created":  created,
                    "modified": modified,
                    "accessed": accessed,
                    "attrs":    _fat_attrs(attr),
                    "inode":    None,
                    "cluster":  start_cl,
                },
            })

            # Recurse into subdirectories (only non-deleted)
            if is_dir and not is_entry_deleted and start_cl >= 2:
                sub_data = read_cluster_chain(start_cl)
                parse_dir_entries(sub_data, full_path)

            i += 32

    # Start from root cluster
    root_data = read_cluster_chain(bpb.root_cluster)
    parse_dir_entries(root_data, "")

    # Deleted file recovery: scan free clusters for orphaned directory entries
    if recover_deleted and len(files) < max_files:
        _fat_recover_deleted(
            device_path, partition_offset_sectors, sector_size,
            bpb, fat_data, files, fs_type, max_files
        )

    return files


def _fat_recover_deleted(device_path: str,
                         partition_offset: int,
                         sector_size: int,
                         bpb: _FAT32BPB,
                         fat_data: bytes,
                         files: list,
                         fs_type: str,
                         max_files: int) -> None:
    """
    Scan sectors in the data area for 0xE5-prefixed directory entries
    that don't appear in the live tree (basic undelete).
    """
    existing_paths = {f["path"] for f in files}
    total_data_sectors = min(
        bpb.total_sectors_32 - bpb.first_data_sector,
        4096  # limit scan to first 4096 data sectors for performance
    )

    for sec_offset in range(0, total_data_sectors, bpb.sectors_per_cluster):
        if len(files) >= max_files:
            break
        abs_sector = partition_offset + bpb.first_data_sector + sec_offset
        try:
            cluster_data = _read_raw(device_path, abs_sector,
                                     bpb.sectors_per_cluster, sector_size)
        except OSError:
            continue

        for i in range(0, len(cluster_data) - 32, 32):
            entry = cluster_data[i:i + 32]
            if entry[0] != 0xE5:
                continue
            attr = entry[11]
            if attr in (0x0F, 0x08):  # skip LFN / volume
                continue
            name = _fat_83_name(entry, deleted=True)
            if not name or _is_null_name(name):
                continue
            is_dir   = bool(attr & 0x10)
            size     = struct.unpack_from("<I", entry, 28)[0]
            hi       = struct.unpack_from("<H", entry, 20)[0]
            lo       = struct.unpack_from("<H", entry, 26)[0]
            start_cl = (hi << 16) | lo
            path     = "/$Deleted/" + name
            if path in existing_paths:
                continue
            existing_paths.add(path)
            files.append({
                "name":    name,
                "path":    path,
                "size":    size if not is_dir else 0,
                "deleted": True,
                "fs_type": fs_type,
                "metadata": {
                    "created":  _fat_datetime(entry, 16, 14),
                    "modified": _fat_datetime(entry, 24, 22),
                    "accessed": _fat_date_only(entry, 18),
                    "attrs":    _fat_attrs(attr) + "D",
                    "inode":    None,
                    "cluster":  start_cl,
                },
            })


def _parse_lfn_entry(entry: bytes) -> str:
    """Extract the 13 UTF-16LE characters from an LFN directory entry."""
    parts = entry[1:11] + entry[14:26] + entry[28:32]
    try:
        return parts.decode("utf-16-le")
    except Exception:
        return ""


def _fat_83_name(entry: bytes, deleted: bool = False) -> str:
    """
    Build a filename from the 8.3 directory entry.
    Handles the 0xE5 → 0x05 substitution for Kanji and deleted markers.
    Never returns a name consisting only of null bytes.
    """
    raw8 = bytearray(entry[0:8])
    raw3 = bytearray(entry[8:11])

    if deleted and raw8[0] == 0xE5:
        raw8[0] = ord("_")   # placeholder for unknown first char
    elif raw8[0] == 0x05:
        raw8[0] = 0xE5       # Kanji initial byte

    name_part = bytes(raw8).rstrip(b" ").decode("ascii", errors="replace")
    ext_part  = bytes(raw3).rstrip(b" ").decode("ascii", errors="replace")

    if not name_part or all(c in ("\x00", "\ufffd") for c in name_part):
        return ""

    if ext_part:
        return f"{name_part}.{ext_part}"
    return name_part


def _fat_attrs(attr: int) -> str:
    result = ""
    if attr & 0x01: result += "R"
    if attr & 0x02: result += "H"
    if attr & 0x04: result += "S"
    if attr & 0x20: result += "A"
    if attr & 0x10: result += "D"
    return result or "A"


def _fat_datetime(entry: bytes, date_offset: int, time_offset: int) -> Optional[str]:
    try:
        date_val = struct.unpack_from("<H", entry, date_offset)[0]
        time_val = struct.unpack_from("<H", entry, time_offset)[0]
        if date_val == 0:
            return None
        year  = ((date_val >> 9) & 0x7F) + 1980
        month = (date_val >> 5) & 0x0F
        day   =  date_val & 0x1F
        hour  = (time_val >> 11) & 0x1F
        minute= (time_val >> 5) & 0x3F
        second= (time_val & 0x1F) * 2
        if month < 1 or month > 12 or day < 1 or day > 31:
            return None
        return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}"
    except Exception:
        return None


def _fat_date_only(entry: bytes, date_offset: int) -> Optional[str]:
    return _fat_datetime(entry, date_offset, date_offset)  # time part will be 0


# ─── NTFS Fallback ────────────────────────────────────────────────────────────

class _NTFSBoot:
    """Parsed NTFS Boot Record."""
    __slots__ = (
        "bytes_per_sector", "sectors_per_cluster",
        "mft_lcn", "mft_mirror_lcn",
        "clusters_per_mft_record", "bytes_per_mft_record",
        "cluster_size",
    )

    def __init__(self, vbr: bytes):
        self.bytes_per_sector     = struct.unpack_from("<H", vbr, 11)[0]
        self.sectors_per_cluster  = vbr[13]
        self.mft_lcn              = struct.unpack_from("<q", vbr, 48)[0]  # signed
        self.mft_mirror_lcn       = struct.unpack_from("<q", vbr, 56)[0]
        raw_cpmr                  = struct.unpack_from("<b", vbr, 64)[0]  # signed
        if raw_cpmr < 0:
            self.bytes_per_mft_record = 2 ** (-raw_cpmr)
        else:
            self.bytes_per_mft_record = raw_cpmr * self.bytes_per_sector * self.sectors_per_cluster
        self.clusters_per_mft_record = raw_cpmr
        self.cluster_size         = self.bytes_per_sector * self.sectors_per_cluster

    def lcn_to_byte_offset(self, lcn: int) -> int:
        return lcn * self.cluster_size


# Standard MFT attribute type constants
_ATTR_STANDARD_INFO = 0x10
_ATTR_FILE_NAME     = 0x30
_ATTR_DATA          = 0x80
_ATTR_END           = 0xFFFFFFFF


def _ntfs_fallback(device_path: str,
                   partition_offset_sectors: int,
                   sector_size: int,
                   recover_deleted: bool,
                   max_files: int) -> list[dict]:
    """
    Walk the $MFT sequentially and decode FILE records.
    Extracts $STANDARD_INFORMATION + $FILE_NAME attributes.
    """
    vbr   = _read_raw(device_path, partition_offset_sectors, 1, sector_size)
    boot  = _NTFSBoot(vbr)

    part_byte_offset = partition_offset_sectors * sector_size
    mft_byte_offset  = part_byte_offset + boot.lcn_to_byte_offset(boot.mft_lcn)
    record_size      = boot.bytes_per_mft_record

    files: list[dict] = []
    # inode → name/path map for building paths on second pass
    inode_map: dict[int, dict] = {}

    # ── Pass 1: read MFT records sequentially ─────────────────────────────
    record_index = 0
    MAX_MFT_RECORDS = min(max_files * 2, 500_000)

    while record_index < MAX_MFT_RECORDS:
        offset = mft_byte_offset + record_index * record_size
        try:
            raw = _read_bytes(device_path, offset, record_size)
        except OSError:
            break

        if len(raw) < 48:
            break

        # Signature check: "FILE" = 0x46 0x49 0x4C 0x45
        if raw[:4] != b"FILE":
            record_index += 1
            continue

        parsed = _ntfs_parse_record(raw, record_index, boot)
        if parsed:
            inode_map[record_index] = parsed

        record_index += 1

    # ── Pass 2: resolve paths using parent inode references ───────────────
    def resolve_path(inode_num: int, visited: set) -> str:
        if inode_num in visited:
            return "/$CircularRef"
        visited.add(inode_num)
        rec = inode_map.get(inode_num)
        if rec is None:
            return ""
        name   = rec.get("name", "")
        parent = rec.get("parent_inode")
        if parent is None or parent == inode_num or parent == 5:  # 5 = root
            return "/" + name if name else "/"
        parent_path = resolve_path(parent, visited)
        return parent_path.rstrip("/") + "/" + name

    for inode_num, rec in inode_map.items():
        if len(files) >= max_files:
            break
        name = rec.get("name", "")
        if not name or _is_null_name(name):
            continue
        is_deleted = rec.get("deleted", False)
        if is_deleted and not recover_deleted:
            continue
        path = resolve_path(inode_num, set())
        files.append({
            "name":    name,
            "path":    path,
            "size":    rec.get("size", 0),
            "deleted": is_deleted,
            "fs_type": "NTFS",
            "metadata": {
                "created":  rec.get("created"),
                "modified": rec.get("modified"),
                "accessed": rec.get("accessed"),
                "attrs":    rec.get("attrs", ""),
                "inode":    inode_num,
                "cluster":  None,
            },
        })

    return files


def _ntfs_parse_record(raw: bytes, record_num: int, boot: _NTFSBoot) -> Optional[dict]:
    """
    Parse a single FILE record from the $MFT.
    Returns a partial dict or None if the record is corrupt/empty.
    """
    try:
        record_size = boot.bytes_per_mft_record

        # Apply fixup (Update Sequence Array)
        raw = bytearray(raw)
        usn_offset = struct.unpack_from("<H", raw, 4)[0]
        usn_count  = struct.unpack_from("<H", raw, 6)[0]
        if usn_offset + usn_count * 2 <= len(raw):
            usn_value = struct.unpack_from("<H", raw, usn_offset)[0]
            for i in range(1, usn_count):
                sector_end = i * boot.bytes_per_sector - 2
                if sector_end + 1 < len(raw):
                    raw[sector_end]     = raw[usn_offset + i * 2]
                    raw[sector_end + 1] = raw[usn_offset + i * 2 + 1]

        # MFT record flags: 0x01 = in use, 0x02 = directory
        flags       = struct.unpack_from("<H", raw, 22)[0]
        in_use      = bool(flags & 0x01)
        is_dir      = bool(flags & 0x02)
        is_deleted  = not in_use

        attr_offset = struct.unpack_from("<H", raw, 20)[0]

        result = {
            "name":         "",
            "size":         0,
            "deleted":      is_deleted,
            "is_dir":       is_dir,
            "parent_inode": None,
            "created":      None,
            "modified":     None,
            "accessed":     None,
            "attrs":        "",
        }

        pos = attr_offset
        while pos + 8 <= record_size and pos + 8 <= len(raw):
            attr_type = struct.unpack_from("<I", raw, pos)[0]
            if attr_type == _ATTR_END:
                break

            attr_len = struct.unpack_from("<I", raw, pos + 4)[0]
            if attr_len == 0 or pos + attr_len > len(raw):
                break

            non_resident = raw[pos + 8]

            if attr_type == _ATTR_STANDARD_INFO and not non_resident:
                content_off  = struct.unpack_from("<H", raw, pos + 20)[0]
                content_start = pos + content_off
                if content_start + 48 <= len(raw):
                    result["created"]  = _ntfs_filetime(raw, content_start)
                    result["modified"] = _ntfs_filetime(raw, content_start + 8)
                    result["accessed"] = _ntfs_filetime(raw, content_start + 24)
                    fa = struct.unpack_from("<I", raw, content_start + 32)[0]
                    result["attrs"]    = _ntfs_attrs(fa)

            elif attr_type == _ATTR_FILE_NAME and not non_resident:
                content_off   = struct.unpack_from("<H", raw, pos + 20)[0]
                content_start = pos + content_off
                if content_start + 66 <= len(raw):
                    parent_ref = struct.unpack_from("<Q", raw, content_start)[0]
                    # Low 48 bits = inode, high 16 = sequence
                    result["parent_inode"] = int(parent_ref & 0x0000FFFFFFFFFFFF)
                    alloc_size = struct.unpack_from("<Q", raw, content_start + 40)[0]
                    data_size  = struct.unpack_from("<Q", raw, content_start + 48)[0]
                    result["size"] = data_size or alloc_size

                    name_len = raw[content_start + 64]
                    name_ns  = raw[content_start + 65]
                    name_start = content_start + 66
                    name_end   = name_start + name_len * 2
                    if name_end <= len(raw):
                        try:
                            name = raw[name_start:name_end].decode("utf-16-le")
                            # Prefer POSIX namespace (ns=1) or Win32 (ns=1,3)
                            # Skip DOS namespace (ns=2) if we already have a name
                            if name and (not result["name"] or name_ns != 2):
                                result["name"] = name
                        except Exception:
                            pass

            pos += attr_len

        return result if result["name"] else None

    except Exception as exc:
        logger.debug("MFT record %d parse error: %s", record_num, exc)
        return None


def _ntfs_filetime(data: bytes, offset: int) -> Optional[str]:
    """Convert Windows FILETIME (100ns intervals since 1601-01-01) to ISO 8601."""
    try:
        ft = struct.unpack_from("<Q", data, offset)[0]
        if ft == 0:
            return None
        # Convert to Unix timestamp
        EPOCH = 116444736000000000  # 1970-01-01 in 100ns intervals from 1601-01-01
        us = (ft - EPOCH) // 10
        dt = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
        return dt.isoformat(timespec="seconds")
    except Exception:
        return None


def _ntfs_attrs(file_attributes: int) -> str:
    parts = []
    if file_attributes & 0x01: parts.append("R")   # Read-only
    if file_attributes & 0x02: parts.append("H")   # Hidden
    if file_attributes & 0x04: parts.append("S")   # System
    if file_attributes & 0x20: parts.append("A")   # Archive
    if file_attributes & 0x10: parts.append("D")   # Directory
    if file_attributes & 0x400: parts.append("C")  # Compressed
    if file_attributes & 0x4000: parts.append("E") # Encrypted
    return "".join(parts) or "A"


# ─── exFAT basic metadata ─────────────────────────────────────────────────────

def _exfat_basic_info(device_path: str,
                      partition_offset_sectors: int,
                      sector_size: int) -> dict:
    """
    Parse the exFAT VBR to extract basic volume information.
    Full traversal requires pytsk3.
    """
    vbr = _read_raw(device_path, partition_offset_sectors, 1, sector_size)

    bytes_per_sector_shift  = vbr[108]
    sectors_per_cluster_shift = vbr[109]
    cluster_count           = struct.unpack_from("<I", vbr, 92)[0]
    root_dir_cluster        = struct.unpack_from("<I", vbr, 96)[0]
    volume_serial           = struct.unpack_from("<I", vbr, 100)[0]
    label                   = ""  # label is stored in directory

    bytes_per_sector  = 2 ** bytes_per_sector_shift
    bytes_per_cluster = 2 ** (bytes_per_sector_shift + sectors_per_cluster_shift)
    total_bytes       = cluster_count * bytes_per_cluster

    return {
        "label":             label,
        "bytes_per_sector":  bytes_per_sector,
        "bytes_per_cluster": bytes_per_cluster,
        "cluster_count":     cluster_count,
        "root_dir_cluster":  root_dir_cluster,
        "volume_serial":     f"{volume_serial:08X}",
        "total_bytes":       total_bytes,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def _read_raw(device_path: str,
              sector_offset: int,
              sector_count: int,
              sector_size: int) -> bytes:
    """Read *sector_count* sectors from *device_path* at *sector_offset*."""
    byte_offset = sector_offset * sector_size
    byte_count  = sector_count  * sector_size
    return _read_bytes(device_path, byte_offset, byte_count)


def _read_bytes(device_path: str, byte_offset: int, byte_count: int) -> bytes:
    """
    Read *byte_count* bytes from *device_path* starting at *byte_offset*.
    Uses sector-aligned reads for raw devices.
    """
    alignment   = 512
    aligned_off = (byte_offset // alignment) * alignment
    prefix_skip = byte_offset - aligned_off
    aligned_len = ((prefix_skip + byte_count + alignment - 1) // alignment) * alignment

    try:
        with open(device_path, "rb") as fh:
            fh.seek(aligned_off)
            raw = fh.read(aligned_len)
    except PermissionError:
        raise PermissionError(
            f"Cannot read {device_path!r}: administrator / root rights required"
        )

    return raw[prefix_skip: prefix_skip + byte_count]


def _safe_decode(data: bytes, encodings=("utf-8", "cp1252", "latin-1")) -> str:
    """
    Decode bytes to str, trying encodings in order.
    Never raises; falls back to replacing undecodable bytes with '?'.
    """
    for enc in encodings:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            pass
    return data.decode("latin-1", errors="replace")


def _is_null_name(name: str) -> bool:
    """Return True if name is composed entirely of null/replacement characters."""
    return all(c in ("\x00", "\uFFFF", "\uFFFD", " ") for c in name)


def _ts_to_iso(ts: int) -> Optional[str]:
    """Convert a Unix timestamp integer to ISO 8601 string."""
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# FLASK INTEGRATION HELPER
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_for_api(device_path: str,
                    partition_offset_sectors: int = 0,
                    sector_size: int = 512,
                    recover_deleted: bool = True,
                    max_files: int = 10_000) -> dict:
    """
    Wrapper for Flask API routes. Returns the full result envelope and
    guarantees the return value is always JSON-serialisable.

    Usage in app.py:
        from core.filesystem_analyzer import analyze_for_api
        result = analyze_for_api(device_path, partition_offset_sectors=2048)
        return jsonify(result)
    """
    try:
        result = analyze(
            device_path,
            partition_offset_sectors=partition_offset_sectors,
            sector_size=sector_size,
            recover_deleted=recover_deleted,
            max_files=max_files,
        )
    except PermissionError as exc:
        result = {
            "fs_type":     "Unknown",
            "files":       [],
            "total_found": 0,
            "error":       f"PERMISSION_DENIED: {exc}",
            "partial":     True,
            "engine":      "none",
        }
    except FileNotFoundError as exc:
        result = {
            "fs_type":     "Unknown",
            "files":       [],
            "total_found": 0,
            "error":       f"DEVICE_NOT_FOUND: {exc}",
            "partial":     True,
            "engine":      "none",
        }
    except Exception as exc:
        result = {
            "fs_type":     "Unknown",
            "files":       [],
            "total_found": 0,
            "error":       f"UNEXPECTED_ERROR: {exc}",
            "partial":     True,
            "engine":      "none",
        }

    return result
