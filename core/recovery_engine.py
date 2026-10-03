"""
recovery_engine.py  ─  EDRT Unified Recovery Engine
=====================================================

Implements four recovery modes that work independently or together:

  A. FILESYSTEM METADATA RECOVERY
     Reads the MFT ($MFT walk) for NTFS or the FAT directory entries for
     FAT12/16/32 to enumerate deleted files by their original metadata
     (name, size, timestamps, cluster chain).

  B. RAW CARVING ENGINE
     Scans raw sectors chunk-by-chunk for file signatures (magic bytes).
     Recovers JPG (FF D8 FF), PNG (89 50 4E 47), TXT (printable ASCII),
     PDF, ZIP, MP4, and 25+ more types without relying on any filesystem.

  C. CORRUPTION HANDLING
     Detects and repairs common damage:
       • Missing / truncated JPEG headers  → synthetic SOI + APP0 injected
       • Missing PNG IHDR chunk            → synthesised from available data
       • Truncated files                   → padded to valid boundary
       • Partial ZIP central directory     → local-file-header fallback
       • NTFS fixup (Update Sequence Array) applied before MFT parsing
     Every recovery path records a "repair_log" so callers know what was done.

  D. EFFICIENT SCANNING
     • Chunk-based reading (default 1 MB) — the full disk is never in memory.
     • Overlap window (512 B) handles signatures that straddle chunk boundaries.
     • Bad-sector skip: OSError on a chunk advances the cursor and continues.
     • Optional byte-range limits for partial-disk scans.
     • Worker-friendly generator API so callers can stream results.

OUTPUT
------
Every recovered item is a RecoveredObject (TypedDict / plain dict):

    {
        "id":          str,          # stable hex ID (MD5 of source + offset)
        "source":      str,          # "metadata" | "carving" | "carving+repair"
        "name":        str,          # original name (metadata) or synthetic name
        "path":        str,          # filesystem path or "" for carved files
        "extension":   str,          # lower-case, no dot
        "description": str,          # human-readable type label
        "offset":      int,          # byte offset in the image/device
        "offset_hex":  str,          # e.g. "0x00123ABC"
        "size_bytes":  int,          # recovered data length
        "size_str":    str,          # human-readable size
        "confidence":  int,          # 0-99
        "deleted":     bool,         # True if marked deleted in metadata
        "has_footer":  bool,         # carving: footer signature found
        "repaired":    bool,         # True if corruption repair was applied
        "repair_log":  list[str],    # what was patched/rebuilt
        "fs_type":     str,          # "NTFS" | "FAT32" | "FAT16" | "" for carved
        "metadata": {
            "created":   str | None,
            "modified":  str | None,
            "accessed":  str | None,
            "attrs":     str,
            "inode":     int | None,
            "cluster":   int | None,
        },
        "data":        bytes | None, # raw recovered bytes (None until extracted)
    }

USAGE EXAMPLES
--------------
# 1. Full combined scan (metadata + carving)
results = recover_all("path/to/image.dd")

# 2. Carving only, streaming
for obj in carve_stream("path/to/image.dd"):
    print(obj["name"], obj["confidence"])

# 3. Metadata recovery only
results = recover_from_metadata("path/to/image.dd", fs_type="NTFS")

# 4. Extract data for one result
populated = extract_data("path/to/image.dd", result_obj)
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import struct
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Generator, Iterator, Optional

logger = logging.getLogger(__name__)


def _resolve_path(path: str) -> str:
    """
    Convert a logical drive letter (e.g. 'E:\\') to a raw device path
    ('\\\\.\\ E:') so it can be opened with open() for binary reading.
    Image files and already-resolved UNC paths are returned unchanged.
    """
    if platform.system() != "Windows":
        return path
    # Already a raw device path or UNC path — leave as-is
    if path.startswith("\\\\.\\") or path.startswith("\\\\"):
        return path
    # Image file that exists on disk — leave as-is
    if os.path.isfile(path):
        return path
    # Logical drive letter: 'E:\\' or 'E:' → '\\\\.\\E:'
    if len(path) >= 2 and path[1] == ":":
        return f"\\\\.\\{path[0].upper()}:"
    return path


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

CHUNK_SIZE    = 1024 * 1024          # 1 MB read chunks
OVERLAP_SIZE  = 512                  # bytes kept across chunk boundary
READ_AHEAD    = 8 * 1024 * 1024      # max look-ahead for footer search (8 MB)
MAX_CARVE_SZ  = 200 * 1024 * 1024   # 200 MB single-file cap
MAX_FILES     = 5000                 # hard stop

# Printable ASCII threshold for TXT detection (% of bytes that must be printable)
TXT_PRINTABLE_RATIO = 0.85
TXT_MIN_RUN = 64                     # consecutive printable bytes to trigger

# ── File signatures ────────────────────────────────────────────────────────────
# Each entry: (magic_bytes, extension, description, max_size, footer_or_None)
FILE_SIGNATURES: list[tuple[bytes, str, str, int, Optional[bytes]]] = [
    # Images
    (b'\xff\xd8\xff\xe0', "jpg",  "JPEG Image",            15*1024*1024,   b'\xff\xd9'),
    (b'\xff\xd8\xff\xe1', "jpg",  "JPEG Image (EXIF)",     15*1024*1024,   b'\xff\xd9'),
    (b'\xff\xd8\xff\xdb', "jpg",  "JPEG Image",            15*1024*1024,   b'\xff\xd9'),
    (b'\xff\xd8\xff\xee', "jpg",  "JPEG Image",            15*1024*1024,   b'\xff\xd9'),
    (b'\x89PNG\r\n\x1a\n',"png",  "PNG Image",             20*1024*1024,   b'IEND\xaeB`\x82'),
    (b'GIF89a',           "gif",  "GIF Image",             10*1024*1024,   b'\x00;'),
    (b'GIF87a',           "gif",  "GIF Image (87a)",       10*1024*1024,   b'\x00;'),
    (b'BM',               "bmp",  "Bitmap Image",          50*1024*1024,   None),
    (b'\x00\x00\x01\x00', "ico",  "Icon File",             2*1024*1024,    None),
    (b'II*\x00',          "tiff", "TIFF Image (LE)",       100*1024*1024,  None),
    (b'MM\x00*',          "tiff", "TIFF Image (BE)",       100*1024*1024,  None),
    (b'WEBP',             "webp", "WebP Image",            20*1024*1024,   None),

    # Documents
    (b'%PDF-',            "pdf",  "PDF Document",          200*1024*1024,  b'%%EOF'),
    (b'PK\x03\x04',       "zip",  "ZIP / Office Document", 500*1024*1024,  b'PK\x05\x06'),
    (b'\xd0\xcf\x11\xe0', "doc",  "Legacy Office (OLE)",   50*1024*1024,   None),
    (b'{\rtf1',           "rtf",  "Rich Text File",        20*1024*1024,   b'}'),

    # Video
    (b'\x00\x00\x00\x18ftyp', "mp4", "MP4 Video",         4*1024*1024*1024, None),
    (b'\x00\x00\x00\x20ftyp', "mp4", "MP4 Video",         4*1024*1024*1024, None),
    (b'\x00\x00\x00\x1cftyp', "mp4", "MP4 Video",         4*1024*1024*1024, None),
    (b'ftypisom',         "mp4",  "MP4 Video (isom)",      4*1024*1024*1024, None),
    (b'ftypmp42',         "mp4",  "MP4 Video (mp42)",      4*1024*1024*1024, None),
    (b'RIFF',             "avi",  "AVI Video",             4*1024*1024*1024, None),
    (b'\x1aE\xdf\xa3',   "mkv",  "MKV Video",             4*1024*1024*1024, None),
    (b'FLV\x01',          "flv",  "Flash Video",           2*1024*1024*1024, None),
    (b'\x00\x00\x01\xba', "mpg",  "MPEG Video",            2*1024*1024*1024, None),

    # Audio
    (b'ID3',              "mp3",  "MP3 Audio",             50*1024*1024,   None),
    (b'\xff\xfb',         "mp3",  "MP3 Audio Frame",       50*1024*1024,   None),
    (b'fLaC',             "flac", "FLAC Audio",            500*1024*1024,  None),
    (b'OggS',             "ogg",  "OGG Audio",             200*1024*1024,  None),
    (b'MAC ',             "ape",  "APE Audio",             500*1024*1024,  None),

    # Archives
    (b'Rar!\x1a\x07\x00', "rar",  "RAR Archive",           2*1024*1024*1024, None),
    (b'\x1f\x8b\x08',     "gz",   "GZip Archive",          500*1024*1024,  None),
    (b'7z\xbc\xaf\x27\x1c',"7z", "7-Zip Archive",         2*1024*1024*1024, None),
    (b'BZh',              "bz2",  "BZip2 Archive",         500*1024*1024,  None),

    # Database / code
    (b'SQLite format 3\x00',"db", "SQLite Database",       2*1024*1024*1024, None),
    (b'<?xml',            "xml",  "XML File",              50*1024*1024,   None),
    (b'<!DOCTYPE html',   "html", "HTML File",             10*1024*1024,   None),
    (b'<html',            "html", "HTML File",             10*1024*1024,   None),

    # Executables
    (b'MZ',               "exe",  "Windows Executable",    500*1024*1024,  None),
    (b'\x7fELF',          "elf",  "Linux Executable",      500*1024*1024,  None),
]

# ── NTFS MFT attribute types ───────────────────────────────────────────────────
_ATTR_STANDARD_INFO = 0x10
_ATTR_FILE_NAME     = 0x30
_ATTR_DATA          = 0x80
_ATTR_END           = 0xFFFFFFFF

# ── FAT constants ──────────────────────────────────────────────────────────────
FAT_DIR_ENTRY_SIZE   = 32
FAT_DELETED_MARKER   = 0xE5
FAT_LAST_ENTRY       = 0x00
FAT_ATTR_VOLUME      = 0x08
FAT_ATTR_LFN         = 0x0F
FAT_ATTR_DIR         = 0x10


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def recover_all(
    source_path: str,
    *,
    recover_deleted: bool = True,
    carve_raw: bool = True,
    repair_corrupted: bool = True,
    start_offset: int = 0,
    end_offset: Optional[int] = None,
    max_files: int = MAX_FILES,
) -> dict:
    """
    Master recovery function.  Combines metadata recovery + raw carving.

    Returns
    -------
    {
        "source":           str,           # path scanned
        "fs_type":          str,
        "engine":           str,
        "scanned_bytes":    int,
        "files":            list[RecoveredObject],
        "total_found":      int,
        "metadata_count":   int,
        "carved_count":     int,
        "repaired_count":   int,
        "type_summary":     dict[str, int],
        "errors":           list[str],
        "scanned_at":       str,           # ISO-8601
    }
    """
    source_path = _resolve_path(source_path)
    errors: list[str] = []
    all_files: list[dict] = []

    # ── A: Filesystem metadata recovery ───────────────────────────────────
    meta_result = {"fs_type": "Unknown", "files": [], "engine": "none", "error": None}
    try:
        meta_result = recover_from_metadata(
            source_path,
            recover_deleted=recover_deleted,
            max_files=max_files,
        )
        all_files.extend(meta_result["files"])
        if meta_result.get("error"):
            errors.append(f"Metadata: {meta_result['error']}")
    except Exception as exc:
        errors.append(f"Metadata recovery failed: {exc}")
        logger.warning("Metadata recovery exception: %s", exc, exc_info=True)

    metadata_count = len(all_files)

    # ── B + C: Raw carving (with optional corruption repair) ───────────────
    carved: list[dict] = []
    if carve_raw:
        try:
            existing_offsets = {f["offset"] for f in all_files}
            for obj in carve_stream(
                source_path,
                repair_corrupted=repair_corrupted,
                start_offset=start_offset,
                end_offset=end_offset,
                max_files=max_files - len(all_files),
            ):
                # Deduplicate: skip if metadata recovery already found this offset
                if obj["offset"] not in existing_offsets:
                    carved.append(obj)
                    existing_offsets.add(obj["offset"])
        except Exception as exc:
            errors.append(f"Carving failed: {exc}")
            logger.warning("Carving exception: %s", exc, exc_info=True)

    all_files.extend(carved)
    carved_count  = len(carved)
    repaired_count = sum(1 for f in all_files if f.get("repaired"))

    # ── Deduplicate globally by (offset, extension) ───────────────────────
    seen: set[tuple] = set()
    unique: list[dict] = []
    for f in all_files:
        key = (f["offset"], f["extension"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    all_files = unique[:max_files]

    # ── Type summary ──────────────────────────────────────────────────────
    type_summary: dict[str, int] = {}
    for f in all_files:
        k = f["extension"].upper() or "?"
        type_summary[k] = type_summary.get(k, 0) + 1

    return {
        "source":         source_path,
        "fs_type":        meta_result.get("fs_type", "Unknown"),
        "engine":         meta_result.get("engine", "carving_only"),
        "scanned_bytes":  _file_size(source_path),
        "files":          all_files,
        "total_found":    len(all_files),
        "metadata_count": metadata_count,
        "carved_count":   carved_count,
        "repaired_count": repaired_count,
        "type_summary":   type_summary,
        "errors":         errors,
        "scanned_at":     datetime.now().isoformat(),
    }


# ── A. METADATA RECOVERY ──────────────────────────────────────────────────────

def recover_from_metadata(
    source_path: str,
    *,
    fs_type: Optional[str] = None,
    partition_offset_sectors: int = 0,
    sector_size: int = 512,
    recover_deleted: bool = True,
    max_files: int = MAX_FILES,
) -> dict:
    """
    Recover file list from filesystem metadata (MFT for NTFS, directory
    entries for FAT12/FAT16/FAT32).

    Returns the same envelope as filesystem_analyzer.analyze():
        { fs_type, files, total_found, error, partial, engine }
    """
    result: dict = {
        "fs_type": "Unknown", "files": [], "total_found": 0,
        "error": None, "partial": False, "engine": "recovery_engine",
    }

    source_path = _resolve_path(source_path)

    # Try pytsk3 first (full featured)
    try:
        import pytsk3  # type: ignore
        result = _pytsk3_recover(
            source_path, partition_offset_sectors, sector_size,
            recover_deleted, max_files,
        )
        return result
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("pytsk3 metadata recovery failed: %s", exc)
        result["error"] = f"pytsk3 failed ({exc}); using pure-Python fallback"
        result["partial"] = True

    # Pure-Python fallback
    try:
        detected = fs_type or _detect_fs(source_path, partition_offset_sectors, sector_size)
        result["fs_type"] = detected

        if "NTFS" in detected:
            files = _ntfs_recover(
                source_path, partition_offset_sectors, sector_size,
                recover_deleted, max_files,
            )
        elif "FAT" in detected or "exFAT" in detected:
            files = _fat_recover(
                source_path, partition_offset_sectors, sector_size,
                recover_deleted, max_files,
            )
        else:
            result["error"] = f"Unsupported filesystem: {detected}"
            result["partial"] = True
            return result

        result["files"]       = files
        result["total_found"] = len(files)
    except Exception as exc:
        result["error"]   = str(exc)
        result["partial"] = True
        logger.error("Pure-Python metadata recovery error: %s", exc, exc_info=True)

    return result


# ── B. RAW CARVING (streaming) ─────────────────────────────────────────────────

def carve_stream(
    source_path: str,
    *,
    repair_corrupted: bool = True,
    start_offset: int = 0,
    end_offset: Optional[int] = None,
    max_files: int = MAX_FILES,
    _stop_event=None,
    _progress_cb=None,
) -> Generator[dict, None, None]:
    """
    Streaming file-carver — v4.9: powered by RecoverPy's binary_scanner.

    RecoverPy's iter_scan_hits() replaces the hand-rolled chunk loop:
      - 8 MB chunks with proper cross-chunk overlap (vs 1 MB before)
      - pread-based random access — thread-safe, no seek races
      - Pause / stop event support via threading.Event
      - Bounded backpressure avoids memory blowup on dense signatures

    Post-processing (corruption repair, TXT detection) is preserved from
    the original EDRT engine so forensic output quality is unchanged.

    Parameters
    ----------
    source_path      : disk image or raw device path
    repair_corrupted : attempt to fix damaged file structures
    start_offset     : byte offset to begin scanning (default 0)
    end_offset       : stop scanning here (default: end of file)
    max_files        : stop after this many finds
    _stop_event      : optional threading.Event to abort scan
    _progress_cb     : optional callable(bytes_done, total_bytes)
    """
    from core.scan_bridge import rp_carve_stream, rp_get_device_size

    source_path = _resolve_path(source_path)
    found_count = 0
    seen_offsets: set[tuple] = set()

    # ── Determine scan window ──────────────────────────────────────────────
    total_bytes = rp_get_device_size(source_path) or _file_size(source_path)
    scan_end    = end_offset if end_offset is not None else total_bytes

    # ── B1: signature-based carving via RecoverPy binary_scanner ──────────
    try:
        for obj in rp_carve_stream(
            source_path,
            stop_event=_stop_event,
            progress_cb=_progress_cb,
            max_files=max_files,
        ):
            if found_count >= max_files:
                return

            abs_offset = obj["offset"]

            # Honour start/end window
            if abs_offset < start_offset:
                continue
            if end_offset is not None and abs_offset >= scan_end:
                continue

            key = (abs_offset, obj["extension"])
            if key in seen_offsets:
                continue
            seen_offsets.add(key)

            # ── Corruption repair post-processing (EDRT feature) ──────────
            if repair_corrupted:
                ext        = obj["extension"]
                size       = obj["size_bytes"]
                has_footer = obj["has_footer"]
                repair_log: list[str] = []
                try:
                    with open(source_path, "rb") as fh:
                        size, repair_log = _apply_corruption_repair(
                            fh, abs_offset, ext, size, has_footer, repair_log
                        )
                    obj["size_bytes"] = size
                    obj["size_str"]   = _fmt(size)
                    if repair_log:
                        obj["repaired"]   = True
                        obj["repair_log"] = repair_log
                except Exception as exc:
                    logger.debug("Repair skipped for offset %d: %s", abs_offset, exc)

            yield obj
            found_count += 1

    except PermissionError:
        raise
    except Exception as exc:
        logger.error("carve_stream (rp) fatal error: %s", exc, exc_info=True)
        raise

    # ── B2: TXT detection — kept from original EDRT engine ────────────────
    # RecoverPy's scanner works on fixed byte patterns; printable-ASCII run
    # detection needs its own pass with a small sliding window.
    if found_count >= max_files:
        return

    try:
        offset  = start_offset
        overlap = b""
        with open(source_path, "rb") as fh:
            if start_offset:
                fh.seek(start_offset)
            while offset < scan_end and found_count < max_files:
                remaining = scan_end - offset
                read_size = min(CHUNK_SIZE, remaining)
                try:
                    chunk = fh.read(read_size)
                except OSError as e:
                    logger.warning("TXT pass read error at %d: %s", offset, e)
                    offset += CHUNK_SIZE
                    overlap = b""
                    try:
                        fh.seek(offset)
                    except Exception:
                        break
                    continue
                if not chunk:
                    break
                buf      = overlap + chunk
                txt_objs = _detect_txt_runs(buf, offset, len(overlap), seen_offsets)
                for obj in txt_objs:
                    if found_count >= max_files:
                        return
                    yield obj
                    seen_offsets.add((obj["offset"], "txt"))
                    found_count += 1
                overlap = buf[-OVERLAP_SIZE:]
                offset += len(chunk)
    except PermissionError:
        raise
    except Exception as exc:
        logger.warning("TXT pass error: %s", exc)


def carve_to_memory(source_path: str, **kwargs) -> list[dict]:
    """Convenience wrapper — collects carve_stream into a list."""
    return list(carve_stream(source_path, **kwargs))


# ── DATA EXTRACTION ───────────────────────────────────────────────────────────

def extract_data(source_path: str, obj: dict) -> dict:
    """
    Populate obj["data"] with the raw recovered bytes for a single item.
    Returns a copy of obj with the "data" key filled.

    For carved objects: reads from disk at obj["offset"].
    For metadata objects with cluster info: falls through to raw read.
    """
    result = dict(obj)
    result["data"] = None
    source_path = _resolve_path(source_path)
    offset = obj.get("offset", 0)
    size   = obj.get("size_bytes", 0)
    ext    = obj.get("extension", "")

    if not offset and not size:
        result["data"] = b""
        return result

    try:
        with open(source_path, "rb") as fh:
            raw = _carve_bytes(fh, offset, size, ext)

        # Apply corruption repair to the actual data bytes
        if obj.get("repaired") or True:  # always try to repair
            raw, extra_log = _repair_bytes(raw, ext)
            if extra_log:
                result["repair_log"] = list(obj.get("repair_log") or []) + extra_log
                result["repaired"]   = True

        result["data"]       = raw
        result["size_bytes"] = len(raw)
        result["size_str"]   = _fmt(len(raw))
    except Exception as exc:
        logger.error("extract_data error for offset %d: %s", offset, exc)

    return result


def save_to_dir(source_path: str, objects: list[dict], output_dir: str) -> dict:
    """
    Extract and save a list of RecoveredObjects to output_dir.

    Returns
    -------
    { "saved": [...], "failed": [...], "output_dir": str, "total_saved": int }
    """
    os.makedirs(output_dir, exist_ok=True)
    source_path = _resolve_path(source_path)
    saved: list[dict] = []
    failed: list[dict] = []

    with open(source_path, "rb") as fh:
        for obj in objects:
            ext   = obj.get("extension", "bin")
            fname = f"recovered_{obj['id']}.{ext}"
            out   = os.path.join(output_dir, fname)
            try:
                raw = _carve_bytes(fh, obj["offset"], obj["size_bytes"], ext)
                raw, _ = _repair_bytes(raw, ext)
                with open(out, "wb") as wf:
                    wf.write(raw)
                saved.append({"file": fname, "path": out, "size_str": _fmt(len(raw))})
            except Exception as exc:
                failed.append({"file": fname, "error": str(exc)})

    return {"saved": saved, "failed": failed, "output_dir": output_dir, "total_saved": len(saved)}


def save_to_zip(source_path: str, objects: list[dict]) -> str:
    """
    Carve and compress recovered files into a temporary ZIP.
    Returns the temp file path (caller must delete it).
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.close()
    source_path = _resolve_path(source_path)

    with open(source_path, "rb") as fh:
        with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
            for obj in objects:
                ext   = obj.get("extension", "bin")
                fname = f"recovered_{obj['id']}.{ext}"
                try:
                    raw = _carve_bytes(fh, obj["offset"], obj["size_bytes"], ext)
                    raw, _ = _repair_bytes(raw, ext)
                    zf.writestr(fname, raw)
                except Exception:
                    pass

    return tmp.name


# ═══════════════════════════════════════════════════════════════════════════════
# A. FILESYSTEM METADATA — INTERNAL IMPLEMENTATION
# ═══════════════════════════════════════════════════════════════════════════════

def _detect_fs(source_path: str, offset_sectors: int, sector_size: int) -> str:
    """Detect filesystem type from the Volume Boot Record."""
    try:
        vbr = _raw_read(source_path, offset_sectors * sector_size, sector_size)
    except Exception:
        return "Unknown"

    if len(vbr) < 512:
        return "Unknown"

    # NTFS: OEM ID at offset 3
    if vbr[3:11] == b'NTFS    ':
        return "NTFS"

    # exFAT: OEM ID at offset 3
    if vbr[3:11] == b'EXFAT   ':
        return "exFAT"

    # FAT: check OEM name and filesystem type string
    fat_type_str = vbr[54:62]
    fat32_type   = vbr[82:90]
    if b'FAT32' in fat32_type:
        return "FAT32"
    if b'FAT16' in fat_type_str or b'FAT12' in fat_type_str:
        return "FAT16"
    if b'FAT' in fat_type_str:
        return "FAT32"  # generic FAT

    return "Unknown"


# ── A1. NTFS MFT RECOVERY ─────────────────────────────────────────────────────

class _NTFSBootBlock:
    __slots__ = (
        "bytes_per_sector", "sectors_per_cluster", "mft_lcn",
        "bytes_per_mft_record", "cluster_size",
    )

    def __init__(self, vbr: bytes):
        self.bytes_per_sector    = struct.unpack_from("<H", vbr, 11)[0] or 512
        self.sectors_per_cluster = vbr[13] or 8
        self.mft_lcn             = struct.unpack_from("<q", vbr, 48)[0]
        raw_cpmr                 = struct.unpack_from("<b", vbr, 64)[0]
        if raw_cpmr < 0:
            self.bytes_per_mft_record = 2 ** (-raw_cpmr)
        else:
            bps = self.bytes_per_sector
            spc = self.sectors_per_cluster
            self.bytes_per_mft_record = max(raw_cpmr * bps * spc, 1024)
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster

    def lcn_to_offset(self, lcn: int) -> int:
        return lcn * self.cluster_size


def _ntfs_recover(
    source_path: str,
    partition_offset_sectors: int,
    sector_size: int,
    recover_deleted: bool,
    max_files: int,
) -> list[dict]:
    """Walk $MFT sequentially and return RecoveredObjects for every FILE record."""
    vbr  = _raw_read(source_path, partition_offset_sectors * sector_size, sector_size)
    boot = _NTFSBootBlock(vbr)

    part_byte = partition_offset_sectors * sector_size
    mft_byte  = part_byte + boot.lcn_to_offset(boot.mft_lcn)
    rec_size  = boot.bytes_per_mft_record

    inode_map: dict[int, dict] = {}
    MAX_MFT = min(max_files * 3, 1_000_000)

    for idx in range(MAX_MFT):
        offset = mft_byte + idx * rec_size
        try:
            raw = _raw_read(source_path, offset, rec_size)
        except OSError:
            break

        if len(raw) < 48 or raw[:4] != b"FILE":
            continue

        parsed = _ntfs_parse_record(raw, idx, boot)
        if parsed:
            inode_map[idx] = parsed

    # Resolve paths
    def resolve(inum: int, visited: set) -> str:
        if inum in visited:
            return "/$CircularRef"
        visited.add(inum)
        rec = inode_map.get(inum)
        if not rec:
            return ""
        name   = rec.get("name", "")
        parent = rec.get("parent_inode")
        if parent is None or parent == inum or parent == 5:
            return "/" + name if name else "/"
        return resolve(parent, visited).rstrip("/") + "/" + name

    files: list[dict] = []
    for inum, rec in inode_map.items():
        if len(files) >= max_files:
            break
        name = rec.get("name", "")
        if not name or _is_null_name(name):
            continue
        is_deleted = rec.get("deleted", False)
        if is_deleted and not recover_deleted:
            continue

        path = resolve(inum, set())
        ext  = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        obj  = _make_metadata_obj(
            name=name,
            path=path,
            extension=ext,
            size=rec.get("size", 0),
            deleted=is_deleted,
            fs_type="NTFS",
            created=rec.get("created"),
            modified=rec.get("modified"),
            accessed=rec.get("accessed"),
            attrs=rec.get("attrs", ""),
            inode=inum,
            cluster=None,
            source_path=source_path,
        )
        files.append(obj)

    return files


def _ntfs_parse_record(raw: bytes, record_num: int, boot: _NTFSBootBlock) -> Optional[dict]:
    """
    Parse one NTFS FILE record.

    C. CORRUPTION HANDLING: applies Update Sequence Array (USN fixup)
    before reading, which is necessary on any real-world MFT — without it,
    the last 2 bytes of every sector contain the USN placeholder, not real data.
    """
    try:
        raw = bytearray(raw)
        rec_size = boot.bytes_per_mft_record

        # Apply USN fixup (corruption step: sector-boundary bytes are replaced)
        usn_off   = struct.unpack_from("<H", raw, 4)[0]
        usn_count = struct.unpack_from("<H", raw, 6)[0]
        if 0 < usn_off < rec_size and usn_off + usn_count * 2 <= len(raw):
            for i in range(1, usn_count):
                sec_end = i * boot.bytes_per_sector - 2
                if sec_end + 1 < len(raw) and usn_off + i * 2 + 1 < len(raw):
                    raw[sec_end]     = raw[usn_off + i * 2]
                    raw[sec_end + 1] = raw[usn_off + i * 2 + 1]

        flags      = struct.unpack_from("<H", raw, 22)[0]
        in_use     = bool(flags & 0x01)
        is_deleted = not in_use

        attr_offset = struct.unpack_from("<H", raw, 20)[0]
        result = {
            "name": "", "size": 0, "deleted": is_deleted,
            "parent_inode": None,
            "created": None, "modified": None, "accessed": None,
            "attrs": "",
        }

        pos = attr_offset
        while pos + 8 <= min(rec_size, len(raw)):
            attr_type = struct.unpack_from("<I", raw, pos)[0]
            if attr_type == _ATTR_END:
                break
            attr_len = struct.unpack_from("<I", raw, pos + 4)[0]
            if attr_len == 0 or pos + attr_len > len(raw):
                break

            non_res = raw[pos + 8]

            if attr_type == _ATTR_STANDARD_INFO and not non_res:
                co = struct.unpack_from("<H", raw, pos + 20)[0]
                cs = pos + co
                if cs + 48 <= len(raw):
                    result["created"]  = _ntfs_filetime(raw, cs)
                    result["modified"] = _ntfs_filetime(raw, cs + 8)
                    result["accessed"] = _ntfs_filetime(raw, cs + 24)
                    fa = struct.unpack_from("<I", raw, cs + 32)[0]
                    result["attrs"]    = _ntfs_attrs(fa)

            elif attr_type == _ATTR_FILE_NAME and not non_res:
                co = struct.unpack_from("<H", raw, pos + 20)[0]
                cs = pos + co
                if cs + 66 <= len(raw):
                    pref = struct.unpack_from("<Q", raw, cs)[0]
                    result["parent_inode"] = int(pref & 0x0000FFFFFFFFFFFF)
                    data_sz = struct.unpack_from("<Q", raw, cs + 48)[0]
                    alloc_sz = struct.unpack_from("<Q", raw, cs + 40)[0]
                    result["size"]     = data_sz or alloc_sz
                    name_len = raw[cs + 64]
                    name_ns  = raw[cs + 65]
                    ns = cs + 66
                    ne = ns + name_len * 2
                    if ne <= len(raw):
                        try:
                            name = raw[ns:ne].decode("utf-16-le")
                            if name and (not result["name"] or name_ns != 2):
                                result["name"] = name
                        except Exception:
                            pass

            pos += attr_len

        return result if result["name"] else None

    except Exception as exc:
        logger.debug("MFT record %d parse error: %s", record_num, exc)
        return None


# ── A2. FAT DIRECTORY RECOVERY ────────────────────────────────────────────────

class _FATBootBlock:
    __slots__ = (
        "bytes_per_sector", "sectors_per_cluster", "reserved_sectors",
        "fat_count", "root_entry_count", "total_sectors",
        "sectors_per_fat", "root_cluster", "fat_type",
        "cluster_size", "fat_start_sector", "root_dir_sector",
        "data_start_sector", "total_clusters",
    )

    def __init__(self, vbr: bytes, fs_type: str):
        self.bytes_per_sector  = struct.unpack_from("<H", vbr, 11)[0] or 512
        self.sectors_per_cluster = vbr[13] or 8
        self.reserved_sectors  = struct.unpack_from("<H", vbr, 14)[0]
        self.fat_count         = vbr[16] or 2
        self.root_entry_count  = struct.unpack_from("<H", vbr, 17)[0]
        self.total_sectors     = (struct.unpack_from("<H", vbr, 19)[0] or
                                  struct.unpack_from("<I", vbr, 32)[0])
        self.fat_type          = fs_type

        if fs_type == "FAT32":
            self.sectors_per_fat = struct.unpack_from("<I", vbr, 36)[0]
            self.root_cluster    = struct.unpack_from("<I", vbr, 44)[0]
        else:
            self.sectors_per_fat = struct.unpack_from("<H", vbr, 22)[0]
            self.root_cluster    = 0

        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.fat_start_sector = self.reserved_sectors
        root_sectors = (self.root_entry_count * 32 + self.bytes_per_sector - 1) // self.bytes_per_sector
        self.root_dir_sector  = self.fat_start_sector + self.fat_count * self.sectors_per_fat
        self.data_start_sector = self.root_dir_sector + root_sectors
        self.total_clusters   = (self.total_sectors - self.data_start_sector) // self.sectors_per_cluster

    def cluster_to_sector(self, cluster: int) -> int:
        return self.data_start_sector + (cluster - 2) * self.sectors_per_cluster


def _fat_recover(
    source_path: str,
    partition_offset_sectors: int,
    sector_size: int,
    recover_deleted: bool,
    max_files: int,
) -> list[dict]:
    """Traverse FAT directory entries, including deleted ones (0xE5 marker)."""
    vbr = _raw_read(source_path, partition_offset_sectors * sector_size, sector_size)
    fs_type = _detect_fs(source_path, partition_offset_sectors, sector_size)
    if fs_type == "Unknown":
        fs_type = "FAT32"

    try:
        boot = _FATBootBlock(vbr, fs_type)
    except Exception as exc:
        raise ValueError(f"Cannot parse FAT BPB: {exc}") from exc

    part_offset = partition_offset_sectors * sector_size
    files: list[dict] = []

    # Read root directory
    if fs_type == "FAT32":
        root_offset = part_offset + boot.cluster_to_sector(boot.root_cluster) * boot.bytes_per_sector
    else:
        root_offset = part_offset + boot.root_dir_sector * boot.bytes_per_sector

    root_size = boot.root_entry_count * FAT_DIR_ENTRY_SIZE if boot.root_entry_count else 16 * 1024

    try:
        root_data = _raw_read(source_path, root_offset, root_size)
    except Exception:
        return files

    _parse_fat_dir(root_data, "/", files, boot, source_path, part_offset,
                   recover_deleted, max_files, depth=0)

    return files[:max_files]


def _parse_fat_dir(
    data: bytes,
    parent_path: str,
    files: list[dict],
    boot: _FATBootBlock,
    source_path: str,
    part_offset: int,
    recover_deleted: bool,
    max_files: int,
    depth: int,
) -> None:
    """Parse raw FAT directory data block into file entries."""
    if depth > 16 or len(files) >= max_files:
        return

    lfn_parts: list[str] = []

    for i in range(0, len(data) - FAT_DIR_ENTRY_SIZE + 1, FAT_DIR_ENTRY_SIZE):
        if len(files) >= max_files:
            break

        entry = data[i: i + FAT_DIR_ENTRY_SIZE]
        first = entry[0]

        if first == FAT_LAST_ENTRY:
            break

        attrs = entry[11]

        # Long File Name entry — collect Unicode fragments
        if attrs == FAT_ATTR_LFN:
            try:
                seq  = entry[0] & 0x1F
                part = (entry[1:11] + entry[14:26] + entry[28:32])
                frag = part.decode("utf-16-le").rstrip("\x00\xFF")
                lfn_parts.insert(0, frag)
            except Exception:
                pass
            continue

        # Skip volume labels
        if attrs & FAT_ATTR_VOLUME and not (attrs & FAT_ATTR_DIR):
            lfn_parts.clear()
            continue

        is_deleted = (first == FAT_DELETED_MARKER)
        if is_deleted and not recover_deleted:
            lfn_parts.clear()
            continue

        # Reconstruct name
        if lfn_parts:
            name = "".join(lfn_parts).strip()
            lfn_parts.clear()
        else:
            raw_name = entry[0:8].rstrip(b' ')
            raw_ext  = entry[8:11].rstrip(b' ')
            if is_deleted:
                raw_name = b'?' + raw_name[1:]
            try:
                stem = raw_name.decode("cp437", errors="replace")
                ext_s = raw_ext.decode("cp437", errors="replace")
                name  = f"{stem}.{ext_s}" if ext_s else stem
            except Exception:
                name = "???"

        if not name or name.startswith('.'):
            continue

        cluster_hi = struct.unpack_from("<H", entry, 20)[0]
        cluster_lo = struct.unpack_from("<H", entry, 26)[0]
        cluster    = (cluster_hi << 16) | cluster_lo
        size       = struct.unpack_from("<I", entry, 28)[0]

        created  = _fat_datetime(entry, 16, 14)
        modified = _fat_datetime(entry, 24, 22)

        is_dir   = bool(attrs & FAT_ATTR_DIR)
        path     = parent_path.rstrip("/") + "/" + name
        ext      = name.rsplit(".", 1)[-1].lower() if "." in name and not is_dir else ""

        # Compute byte offset from cluster number
        if cluster >= 2:
            byte_offset = part_offset + boot.cluster_to_sector(cluster) * boot.bytes_per_sector
        else:
            byte_offset = 0

        obj = _make_metadata_obj(
            name=name, path=path, extension=ext, size=size,
            deleted=is_deleted, fs_type=boot.fat_type,
            created=created, modified=modified, accessed=None,
            attrs=_fat_attrs(attrs), inode=None, cluster=cluster,
            source_path=source_path, offset=byte_offset,
        )
        files.append(obj)

        # Recurse into subdirectories (non-deleted only, to avoid loops)
        if is_dir and not is_deleted and cluster >= 2 and depth < 8:
            try:
                dir_offset = part_offset + boot.cluster_to_sector(cluster) * boot.bytes_per_sector
                dir_data   = _raw_read(source_path, dir_offset, boot.cluster_size)
                _parse_fat_dir(dir_data, path, files, boot, source_path,
                               part_offset, recover_deleted, max_files, depth + 1)
            except Exception:
                pass


# ── pytsk3 fallback wrapper ───────────────────────────────────────────────────

def _pytsk3_recover(
    source_path: str,
    partition_offset_sectors: int,
    sector_size: int,
    recover_deleted: bool,
    max_files: int,
) -> dict:
    import pytsk3  # type: ignore

    result: dict = {
        "fs_type": "Unknown", "files": [], "total_found": 0,
        "error": None, "partial": False, "engine": "pytsk3",
    }

    img = pytsk3.Img_Info(source_path)
    fs  = pytsk3.FS_Info(img, offset=partition_offset_sectors * sector_size)
    result["fs_type"] = {
        pytsk3.TSK_FS_TYPE_NTFS: "NTFS",
        pytsk3.TSK_FS_TYPE_FAT32: "FAT32",
        pytsk3.TSK_FS_TYPE_FAT16: "FAT16",
        pytsk3.TSK_FS_TYPE_FAT12: "FAT12",
        pytsk3.TSK_FS_TYPE_EXFAT: "exFAT",
    }.get(fs.info.ftype, "Unknown")

    files: list[dict] = []

    def walk(directory, parent_path: str):
        if len(files) >= max_files:
            return
        for entry in directory:
            try:
                meta = entry.info.meta
                name_info = entry.info.name
                if name_info is None:
                    continue
                name = name_info.name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue
                is_deleted = (meta is not None and
                              meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
                if is_deleted and not recover_deleted:
                    continue
                size = meta.size if meta else 0
                path = parent_path.rstrip("/") + "/" + name
                ext  = name.rsplit(".", 1)[-1].lower() if "." in name else ""
                obj  = _make_metadata_obj(
                    name=name, path=path, extension=ext, size=size,
                    deleted=bool(is_deleted), fs_type=result["fs_type"],
                    created=None, modified=None, accessed=None,
                    attrs="", inode=meta.addr if meta else None, cluster=None,
                    source_path=source_path,
                )
                files.append(obj)
                if (meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR):
                    try:
                        sub = fs.open_dir(inode=meta.addr)
                        walk(sub, path)
                    except Exception:
                        pass
            except Exception:
                pass

    root = fs.open_dir("/")
    walk(root, "/")

    result["files"]       = files
    result["total_found"] = len(files)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# B. RAW CARVING — INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _find_size(
    fh,
    buf: bytes,
    idx: int,
    abs_offset: int,
    ext: str,
    footer: Optional[bytes],
    max_sz: int,
) -> tuple[int, bool]:
    """
    Determine the size of a carved file.
    Returns (size_bytes, footer_found).

    Strategies (in priority order):
      1. Footer found in current buffer window
      2. Read-ahead to locate footer (saves a second open)
      3. Extract size from internal header fields (JPEG, MP4, RIFF, etc.)
      4. Estimate as max_sz / 8 capped at 5 MB
    """
    # ── JPEG ──────────────────────────────────────────────────────────────
    if ext == "jpg":
        end = buf.find(b'\xff\xd9', idx + 2)
        if end != -1:
            return end - idx + 2, True
        fh.seek(abs_offset)
        ahead = fh.read(min(max_sz, READ_AHEAD))
        end   = ahead.rfind(b'\xff\xd9')
        if end != -1:
            return end + 2, True
        return min(max_sz, 3 * 1024 * 1024), False

    # ── PNG ───────────────────────────────────────────────────────────────
    if ext == "png":
        fp = b'IEND\xaeB`\x82'
        end = buf.find(fp, idx + 8)
        if end != -1:
            return end - idx + len(fp), True
        fh.seek(abs_offset)
        ahead = fh.read(min(max_sz, READ_AHEAD))
        end   = ahead.find(fp)
        if end != -1:
            return end + len(fp), True
        return min(max_sz, 5 * 1024 * 1024), False

    # ── PDF ───────────────────────────────────────────────────────────────
    if ext == "pdf":
        fh.seek(abs_offset)
        ahead = fh.read(min(max_sz, READ_AHEAD))
        end   = ahead.rfind(b'%%EOF')
        if end != -1:
            return end + 5, True
        return min(max_sz, 10 * 1024 * 1024), False

    # ── ZIP / Office (OOXML) ──────────────────────────────────────────────
    if ext in ("zip", "docx", "xlsx", "pptx"):
        fh.seek(abs_offset)
        ahead = fh.read(min(max_sz, READ_AHEAD))
        end   = ahead.rfind(b'PK\x05\x06')
        if end != -1:
            # EOCD is 22 bytes minimum; read comment length from offset 20
            comment_len_off = end + 20
            if comment_len_off + 2 <= len(ahead):
                comment_len = struct.unpack_from("<H", ahead, comment_len_off)[0]
            else:
                comment_len = 0
            return end + 22 + comment_len, True
        return min(max_sz, 10 * 1024 * 1024), False

    # ── GIF ───────────────────────────────────────────────────────────────
    if ext == "gif":
        fh.seek(abs_offset)
        ahead = fh.read(min(max_sz, 10 * 1024 * 1024))
        end   = ahead.find(b'\x00;')
        if end != -1:
            return end + 2, True
        return min(max_sz, 2 * 1024 * 1024), False

    # ── MP4: size from ftyp atom (first 4 bytes) ──────────────────────────
    if ext == "mp4" and idx + 4 <= len(buf):
        try:
            atom = struct.unpack_from(">I", buf, idx)[0]
            if 1024 < atom < max_sz:
                return atom, False
        except Exception:
            pass

    # ── AVI / WAV: RIFF chunk size at bytes 4-8 ───────────────────────────
    if ext in ("avi", "wav") and idx + 8 <= len(buf):
        try:
            chunk_sz = struct.unpack_from("<I", buf, idx + 4)[0]
            total    = chunk_sz + 8
            if 1024 < total < max_sz:
                return total, False
        except Exception:
            pass

    # ── Generic footer search ─────────────────────────────────────────────
    if footer:
        end = buf.find(footer, idx + len(footer))
        if end != -1:
            return end - idx + len(footer), True
        try:
            fh.seek(abs_offset)
            ahead = fh.read(min(max_sz, READ_AHEAD))
            end   = ahead.find(footer)
            if end != -1:
                return end + len(footer), True
        except Exception:
            pass

    # ── Fallback estimate ─────────────────────────────────────────────────
    return min(max_sz // 8, 5 * 1024 * 1024), False


def _detect_txt_runs(
    buf: bytes,
    chunk_base_offset: int,
    overlap_len: int,
    seen: set,
) -> list[dict]:
    """
    Detect runs of printable ASCII in the buffer.
    Emits one RecoveredObject per run >= TXT_MIN_RUN bytes.
    """
    results: list[dict] = []
    run_start = -1
    run_len   = 0

    for i, byte in enumerate(buf):
        is_printable = (0x20 <= byte <= 0x7E) or byte in (0x09, 0x0A, 0x0D)
        if is_printable:
            if run_start == -1:
                run_start = i
            run_len += 1
        else:
            if run_len >= TXT_MIN_RUN:
                abs_offset = chunk_base_offset - overlap_len + run_start
                if abs_offset >= 0:
                    key = (abs_offset, "txt")
                    if key not in seen:
                        obj = _make_carved_obj(
                            abs_offset, "txt", "Plain Text", run_len,
                            False, False, [], "",
                        )
                        results.append(obj)
            run_start = -1
            run_len   = 0

    # Trailing run
    if run_len >= TXT_MIN_RUN and run_start != -1:
        abs_offset = chunk_base_offset - overlap_len + run_start
        if abs_offset >= 0:
            key = (abs_offset, "txt")
            if key not in seen:
                obj = _make_carved_obj(
                    abs_offset, "txt", "Plain Text", run_len,
                    False, False, [], "",
                )
                results.append(obj)

    return results


def _carve_bytes(fh, offset: int, size: int, ext: str) -> bytes:
    """Read and trim raw bytes for one carved object."""
    size = min(size, MAX_CARVE_SZ)
    fh.seek(offset)
    data = fh.read(size)

    # Trim to footer if applicable
    footer = _footer_for(ext)
    if footer and footer in data:
        end  = data.rfind(footer) + len(footer)
        data = data[:end]

    return data


def _footer_for(ext: str) -> Optional[bytes]:
    return {
        "jpg":  b'\xff\xd9',
        "png":  b'IEND\xaeB`\x82',
        "pdf":  b'%%EOF',
        "gif":  b'\x00;',
        "zip":  b'PK\x05\x06',
        "docx": b'PK\x05\x06',
        "xlsx": b'PK\x05\x06',
        "pptx": b'PK\x05\x06',
    }.get(ext)


# ═══════════════════════════════════════════════════════════════════════════════
# C. CORRUPTION REPAIR
# ═══════════════════════════════════════════════════════════════════════════════

def _apply_corruption_repair(
    fh,
    abs_offset: int,
    ext: str,
    size: int,
    has_footer: bool,
    repair_log: list[str],
) -> tuple[int, list[str]]:
    """
    During scanning, decide whether a structural repair is needed and adjust size.
    Heavy byte-level repair happens in _repair_bytes() at extraction time.
    """
    if ext == "jpg" and not has_footer:
        # Extend read-ahead to locate EOI marker
        try:
            fh.seek(abs_offset)
            ahead = fh.read(min(MAX_CARVE_SZ, READ_AHEAD * 2))
            eoi   = ahead.rfind(b'\xff\xd9')
            if eoi != -1:
                size = eoi + 2
                has_footer = True
                repair_log.append("JPEG: located EOI marker in extended look-ahead")
            else:
                # Will synthesise EOI at extraction time
                repair_log.append("JPEG: EOI not found — will append synthetic EOI")
        except Exception:
            pass

    if ext == "png" and not has_footer:
        repair_log.append("PNG: IEND not found — will synthesise IEND chunk")

    if ext == "zip" and not has_footer:
        repair_log.append("ZIP: EOCD not found — will attempt local-file-header rebuild")

    return size, repair_log


def _repair_bytes(data: bytes, ext: str) -> tuple[bytes, list[str]]:
    """
    Byte-level corruption repair applied to extracted data.

    Handles:
      • JPEG: missing SOI header, missing/truncated EOI
      • PNG:  missing IHDR, missing IEND
      • ZIP:  missing EOCD, try local-file-header scan
      • Generic: pad truncated data to sector boundary
    """
    if not data:
        return data, []

    log: list[str] = []

    if ext == "jpg":
        data, log = _repair_jpeg(data, log)

    elif ext == "png":
        data, log = _repair_png(data, log)

    elif ext in ("zip", "docx", "xlsx", "pptx"):
        data, log = _repair_zip(data, log)

    elif ext == "pdf":
        data, log = _repair_pdf(data, log)

    # Generic: ensure we end on a 512-byte sector boundary to avoid partial reads
    if len(data) % 512 != 0 and ext not in ("txt", "xml", "html", "rtf"):
        pad = 512 - (len(data) % 512)
        data = data + b'\x00' * pad
        log.append(f"Padded {pad} null bytes to reach sector boundary")

    return data, log


def _repair_jpeg(data: bytes, log: list[str]) -> tuple[bytes, list[str]]:
    """Repair common JPEG corruption."""
    # Missing SOI (Start of Image: FF D8)
    if not data.startswith(b'\xff\xd8'):
        # Search for the first valid JPEG marker after a potential garbage prefix
        for i in range(min(512, len(data) - 1)):
            if data[i] == 0xFF and data[i+1] in (0xD8, 0xE0, 0xE1, 0xDB, 0xC0):
                data = b'\xff\xd8' + data[i:]
                log.append(f"JPEG: prepended SOI marker (skipped {i} garbage bytes)")
                break
        else:
            data = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + data
            log.append("JPEG: synthesised SOI + JFIF APP0 header")

    # Missing EOI (End of Image: FF D9)
    if not data.endswith(b'\xff\xd9'):
        # Trim any trailing nulls first, then add EOI
        stripped = data.rstrip(b'\x00')
        data     = stripped + b'\xff\xd9'
        log.append("JPEG: appended missing EOI marker")

    # Detect and skip corrupted scan data (MCU blocks with wrong length fields)
    # This is best-effort — just log without modifying
    if b'\xff\x00' not in data[2:] and len(data) > 1024:
        log.append("JPEG: warning — no escaped FF bytes in scan data (may be garbled)")

    return data, log


def _repair_png(data: bytes, log: list[str]) -> tuple[bytes, list[str]]:
    """Repair common PNG corruption."""
    PNG_SIG = b'\x89PNG\r\n\x1a\n'
    IHDR_SIG = b'IHDR'
    IEND_CHUNK = b'\x00\x00\x00\x00IEND\xaeB`\x82'

    # Missing PNG signature
    if not data.startswith(PNG_SIG):
        if PNG_SIG in data:
            idx = data.index(PNG_SIG)
            data = data[idx:]
            log.append(f"PNG: trimmed {idx} garbage bytes before signature")
        else:
            data = PNG_SIG + data
            log.append("PNG: prepended missing PNG signature")

    # Check IHDR presence (must be at offset 8)
    if len(data) >= 16 and data[12:16] != IHDR_SIG:
        # Try to synthesise a minimal IHDR if we can read width/height from data
        if len(data) >= 24:
            # Guess 800×600 if we can't parse — better than nothing
            width  = 800
            height = 600
            ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
            ihdr_crc  = _png_crc(IHDR_SIG + ihdr_data)
            ihdr_chunk = struct.pack(">I", 13) + IHDR_SIG + ihdr_data + struct.pack(">I", ihdr_crc)
            data = PNG_SIG + ihdr_chunk + data[8:]
            log.append("PNG: synthesised IHDR chunk (guessed 800×600 RGB)")

    # Missing IEND
    if not data.endswith(b'IEND\xaeB`\x82'):
        data = data + IEND_CHUNK
        log.append("PNG: appended synthetic IEND chunk")

    return data, log


def _repair_zip(data: bytes, log: list[str]) -> tuple[bytes, list[str]]:
    """Repair truncated ZIP — locate EOCD or rebuild from local file headers."""
    EOCD_SIG = b'PK\x05\x06'

    if EOCD_SIG in data:
        # Trim anything after the first valid EOCD
        idx  = data.rfind(EOCD_SIG)
        if idx + 22 <= len(data):
            return data, log  # intact
        data = data[:idx + 22]
        log.append("ZIP: trimmed data after EOCD signature")
        return data, log

    # No EOCD — scan local file headers (PK 03 04) and rebuild a minimal EOCD
    LOCAL_SIG = b'PK\x03\x04'
    entries   = []
    pos       = 0
    while pos < len(data) - 4:
        if data[pos:pos+4] != LOCAL_SIG:
            pos += 1
            continue
        try:
            fname_len  = struct.unpack_from("<H", data, pos + 26)[0]
            extra_len  = struct.unpack_from("<H", data, pos + 28)[0]
            comp_size  = struct.unpack_from("<I", data, pos + 18)[0]
            entries.append((pos, fname_len, extra_len, comp_size))
            pos += 30 + fname_len + extra_len + comp_size
        except Exception:
            pos += 4

    if entries:
        # Append a minimal synthetic central directory + EOCD
        central_dir = b""
        central_off = len(data)
        for (lh_off, fn_len, ex_len, cs) in entries:
            fname = data[lh_off + 30: lh_off + 30 + fn_len]
            cd_entry = (b'PK\x01\x02'          # Central dir signature
                        + data[lh_off+4:lh_off+4+26]  # version/flags/method/etc
                        + b'\x00\x00'           # file comment length
                        + b'\x00\x00'           # disk number start
                        + b'\x00\x00'           # internal attributes
                        + b'\x00\x00\x00\x00'   # external attributes
                        + struct.pack("<I", lh_off)  # relative offset
                        + fname)
            central_dir += cd_entry

        eocd = (EOCD_SIG
                + b'\x00\x00'                           # disk number
                + b'\x00\x00'                           # start disk
                + struct.pack("<H", len(entries))       # entries on disk
                + struct.pack("<H", len(entries))       # total entries
                + struct.pack("<I", len(central_dir))   # central dir size
                + struct.pack("<I", central_off)        # central dir offset
                + b'\x00\x00')                          # comment length

        data = data + central_dir + eocd
        log.append(f"ZIP: rebuilt central directory + EOCD for {len(entries)} local entries")

    return data, log


def _repair_pdf(data: bytes, log: list[str]) -> tuple[bytes, list[str]]:
    """Ensure PDF has a valid %%EOF marker."""
    if b'%%EOF' not in data:
        data = data + b'\n%%EOF\n'
        log.append("PDF: appended missing %%EOF marker")
    return data, log


def _png_crc(data: bytes) -> int:
    """Compute CRC32 for PNG chunk (standard zlib CRC)."""
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF


# ═══════════════════════════════════════════════════════════════════════════════
# OBJECT FACTORIES
# ═══════════════════════════════════════════════════════════════════════════════

def _make_carved_obj(
    offset: int,
    ext: str,
    desc: str,
    size: int,
    has_footer: bool,
    repaired: bool,
    repair_log: list[str],
    source_path: str,
) -> dict:
    fid = hashlib.md5(f"{source_path}:{offset}:{ext}".encode()).hexdigest()[:12]
    src = "carving+repair" if repaired else "carving"
    return {
        "id":          fid,
        "source":      src,
        "name":        f"carved_{fid}.{ext}",
        "path":        "",
        "extension":   ext,
        "description": desc,
        "offset":      offset,
        "offset_hex":  f"0x{offset:08X}",
        "size_bytes":  size,
        "size_str":    _fmt(size),
        "confidence":  _score(ext, size, has_footer),
        "deleted":     False,
        "has_footer":  has_footer,
        "repaired":    repaired,
        "repair_log":  repair_log,
        "fs_type":     "",
        "metadata": {
            "created": None, "modified": None, "accessed": None,
            "attrs": "", "inode": None, "cluster": None,
        },
        "data": None,
    }


def _make_metadata_obj(
    *,
    name: str,
    path: str,
    extension: str,
    size: int,
    deleted: bool,
    fs_type: str,
    created: Optional[str],
    modified: Optional[str],
    accessed: Optional[str],
    attrs: str,
    inode: Optional[int],
    cluster: Optional[int],
    source_path: str,
    offset: int = 0,
) -> dict:
    fid = hashlib.md5(f"{source_path}:meta:{path}:{name}".encode()).hexdigest()[:12]
    ext = extension.lstrip(".").lower()
    return {
        "id":          fid,
        "source":      "metadata",
        "name":        name,
        "path":        path,
        "extension":   ext,
        "description": _ext_desc(ext),
        "offset":      offset,
        "offset_hex":  f"0x{offset:08X}" if offset else "N/A",
        "size_bytes":  size,
        "size_str":    _fmt(size),
        "confidence":  85 if deleted else 99,
        "deleted":     deleted,
        "has_footer":  False,
        "repaired":    False,
        "repair_log":  [],
        "fs_type":     fs_type,
        "metadata": {
            "created":  created,
            "modified": modified,
            "accessed": accessed,
            "attrs":    attrs,
            "inode":    inode,
            "cluster":  cluster,
        },
        "data": None,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def _score(ext: str, size: int, has_footer: bool) -> int:
    """Confidence score 0–99."""
    if has_footer:
        score = 90
        if size > 1024:         score += 3
        if size > 100 * 1024:   score += 3
        if ext in ("jpg", "png", "pdf", "gif", "zip"): score += 3
        return min(score, 99)
    score = 55
    if size > 10 * 1024:        score += 8
    if size > 100 * 1024:       score += 7
    if ext in ("jpg", "png", "pdf", "mp4", "mp3", "docx", "xlsx"): score += 5
    if ext in ("bmp", "exe", "elf", "rtf"): score += 3
    return min(score, 88)


def _fmt(b: int) -> str:
    if b >= 1024 ** 3: return f"{b/1024**3:.1f} GB"
    if b >= 1024 ** 2: return f"{b/1024**2:.1f} MB"
    if b >= 1024:      return f"{b/1024:.1f} KB"
    return f"{b} B"


def _file_size(path: str) -> int:
    path = _resolve_path(path)
    try:
        # os.path.getsize returns 0 for raw devices; seek to end instead
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            return fh.tell()
    except Exception:
        try:
            return os.path.getsize(path)
        except Exception:
            return 0


def _raw_read(source_path: str, byte_offset: int, length: int) -> bytes:
    """Sector-aligned read from any file or raw device."""
    source_path  = _resolve_path(source_path)
    alignment    = 512
    aligned_off  = (byte_offset // alignment) * alignment
    prefix_skip  = byte_offset - aligned_off
    aligned_len  = ((prefix_skip + length + alignment - 1) // alignment) * alignment

    with open(source_path, "rb") as fh:
        fh.seek(aligned_off)
        raw = fh.read(aligned_len)

    return raw[prefix_skip: prefix_skip + length]


def _ntfs_filetime(data: bytes, offset: int) -> Optional[str]:
    try:
        ft = struct.unpack_from("<Q", data, offset)[0]
        if ft == 0:
            return None
        EPOCH = 116444736000000000
        us    = (ft - EPOCH) // 10
        dt    = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
        return dt.isoformat(timespec="seconds")
    except Exception:
        return None


def _ntfs_attrs(fa: int) -> str:
    parts = []
    if fa & 0x01:   parts.append("R")
    if fa & 0x02:   parts.append("H")
    if fa & 0x04:   parts.append("S")
    if fa & 0x20:   parts.append("A")
    if fa & 0x10:   parts.append("D")
    if fa & 0x400:  parts.append("C")
    if fa & 0x4000: parts.append("E")
    return "".join(parts) or "A"


def _fat_attrs(fa: int) -> str:
    parts = []
    if fa & 0x01: parts.append("R")
    if fa & 0x02: parts.append("H")
    if fa & 0x04: parts.append("S")
    if fa & 0x08: parts.append("V")
    if fa & 0x10: parts.append("D")
    if fa & 0x20: parts.append("A")
    return "".join(parts) or "A"


def _fat_datetime(entry: bytes, date_off: int, time_off: int) -> Optional[str]:
    try:
        date = struct.unpack_from("<H", entry, date_off)[0]
        time = struct.unpack_from("<H", entry, time_off)[0]
        year  = ((date >> 9) & 0x7F) + 1980
        month = (date >> 5) & 0x0F
        day   = date & 0x1F
        hour  = (time >> 11) & 0x1F
        minute= (time >> 5) & 0x3F
        sec   = (time & 0x1F) * 2
        if not (1 <= month <= 12 and 1 <= day <= 31):
            return None
        dt = datetime(year, month, day, hour, minute, min(sec, 59), tzinfo=timezone.utc)
        return dt.isoformat(timespec="seconds")
    except Exception:
        return None


def _is_null_name(name: str) -> bool:
    return all(c in ("\x00", "\uFFFF", "\uFFFD", " ") for c in name)


def _ext_desc(ext: str) -> str:
    MAP = {
        "jpg": "JPEG Image", "jpeg": "JPEG Image", "png": "PNG Image",
        "gif": "GIF Image", "bmp": "Bitmap Image", "tiff": "TIFF Image",
        "webp": "WebP Image", "pdf": "PDF Document", "doc": "Word Document",
        "docx": "Word Document", "xls": "Excel Spreadsheet",
        "xlsx": "Excel Spreadsheet", "pptx": "PowerPoint", "zip": "ZIP Archive",
        "rar": "RAR Archive", "7z": "7-Zip Archive", "gz": "GZip Archive",
        "mp4": "MP4 Video", "avi": "AVI Video", "mkv": "MKV Video",
        "mp3": "MP3 Audio", "flac": "FLAC Audio", "ogg": "OGG Audio",
        "exe": "Windows Executable", "elf": "Linux Executable",
        "db": "SQLite Database", "xml": "XML File", "html": "HTML File",
        "txt": "Plain Text", "rtf": "Rich Text File",
    }
    return MAP.get(ext.lower(), ext.upper() + " File")
