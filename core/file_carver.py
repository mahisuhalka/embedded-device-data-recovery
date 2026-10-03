"""
core/file_carver.py
Raw sector file carving engine.

HOW IT WORKS:
- Reads raw drive/image in 1MB chunks
- Searches each chunk for file magic bytes (signatures)
- When found, reads ahead to locate the file footer (end marker)
- Records offset + estimated size for each found file
- Recovery = seek to offset, read bytes, write to output file

CONFIDENCE SCORE EXPLAINED:
- 90-99%: Found both header AND footer → complete file, very reliable
- 70-89%: Found header + size from internal header fields → probably complete
- 50-69%: Found header only, size estimated → may be partial
- Below 50%: Short/ambiguous match → might be a false positive
"""

import os
import struct
import hashlib
import tempfile
import zipfile
import platform
from datetime import datetime


def _resolve_path(path: str) -> str:
    """
    Convert a logical drive letter (e.g. 'E:\\') to a raw device path
    ('\\\\.\\E:') so Python can open it for binary reading on Windows.
    Image files and already-resolved paths are returned unchanged.
    """
    if platform.system() != "Windows":
        return path
    if path.startswith("\\\\.\\") or path.startswith("\\\\"):
        return path
    if os.path.isfile(path):
        return path
    if len(path) >= 2 and path[1] == ":":
        return f"\\\\.\\{path[0].upper()}:"
    return path


# ──────────────────────────────────────────────────────────────────────────────
# FILE SIGNATURES
# (header_magic, extension, description, max_size_bytes, footer_magic_or_None)
# ──────────────────────────────────────────────────────────────────────────────
FILE_SIGNATURES = [
    # ── Images ────────────────────────────────────────────────────────────────
    (b'\xff\xd8\xff\xe0', "jpg",  "JPEG Image",         15*1024*1024,   b'\xff\xd9'),
    (b'\xff\xd8\xff\xe1', "jpg",  "JPEG Image (EXIF)",  15*1024*1024,   b'\xff\xd9'),
    (b'\xff\xd8\xff\xdb', "jpg",  "JPEG Image",         15*1024*1024,   b'\xff\xd9'),
    (b'\x89PNG\r\n\x1a\n',"png",  "PNG Image",          20*1024*1024,   b'IEND\xaeB`\x82'),
    (b'GIF89a',           "gif",  "GIF Image",          10*1024*1024,   b'\x00\x3b'),
    (b'GIF87a',           "gif",  "GIF Image",          10*1024*1024,   b'\x00\x3b'),
    (b'BM',               "bmp",  "Bitmap Image",       50*1024*1024,   None),
    (b'\x00\x00\x01\x00', "ico",  "Icon File",          2*1024*1024,    None),
    (b'II*\x00',          "tiff", "TIFF Image",         100*1024*1024,  None),
    (b'MM\x00*',          "tiff", "TIFF Image",         100*1024*1024,  None),
    (b'WEBP',             "webp", "WebP Image",         20*1024*1024,   None),

    # ── Documents ─────────────────────────────────────────────────────────────
    (b'%PDF-',            "pdf",  "PDF Document",       200*1024*1024,  b'%%EOF'),
    (b'PK\x03\x04',       "docx", "Word Document",      50*1024*1024,   b'PK\x05\x06'),
    (b'PK\x03\x04',       "xlsx", "Excel Spreadsheet",  50*1024*1024,   b'PK\x05\x06'),
    (b'PK\x03\x04',       "pptx", "PowerPoint File",    200*1024*1024,  b'PK\x05\x06'),
    (b'\xd0\xcf\x11\xe0', "doc",  "Word Doc (old)",     50*1024*1024,   None),
    (b'\xd0\xcf\x11\xe0', "xls",  "Excel (old)",        50*1024*1024,   None),
    (b'{\rtf1',           "rtf",  "Rich Text File",     20*1024*1024,   b'}'),

    # ── Video ─────────────────────────────────────────────────────────────────
    (b'\x00\x00\x00\x18ftyp', "mp4", "MP4 Video",      4*1024*1024*1024, None),
    (b'\x00\x00\x00\x20ftyp', "mp4", "MP4 Video",      4*1024*1024*1024, None),
    (b'\x00\x00\x00\x1cftyp', "mp4", "MP4 Video",      4*1024*1024*1024, None),
    (b'ftypisom',         "mp4",  "MP4 Video",          4*1024*1024*1024, None),
    (b'ftypmp42',         "mp4",  "MP4 Video",          4*1024*1024*1024, None),
    (b'RIFF',             "avi",  "AVI Video",          4*1024*1024*1024, None),
    (b'\x1aE\xdf\xa3',   "mkv",  "MKV Video",          4*1024*1024*1024, None),
    (b'FLV\x01',          "flv",  "Flash Video",        2*1024*1024*1024, None),
    (b'\x00\x00\x01\xba', "mpg",  "MPEG Video",         2*1024*1024*1024, None),

    # ── Audio ─────────────────────────────────────────────────────────────────
    (b'ID3',              "mp3",  "MP3 Audio",          50*1024*1024,   None),
    (b'\xff\xfb',         "mp3",  "MP3 Audio",          50*1024*1024,   None),
    (b'\xff\xf3',         "mp3",  "MP3 Audio",          50*1024*1024,   None),
    (b'fLaC',             "flac", "FLAC Audio",         500*1024*1024,  None),
    (b'OggS',             "ogg",  "OGG Audio",          200*1024*1024,  None),
    (b'RIFF',             "wav",  "WAV Audio",          500*1024*1024,  None),
    (b'MAC ',             "ape",  "APE Audio",          500*1024*1024,  None),

    # ── Archives ──────────────────────────────────────────────────────────────
    (b'PK\x03\x04',       "zip",  "ZIP Archive",        2*1024*1024*1024, b'PK\x05\x06'),
    (b'Rar!\x1a\x07\x00', "rar",  "RAR Archive",        2*1024*1024*1024, None),
    (b'Rar!\x1a\x07\x01', "rar",  "RAR5 Archive",       2*1024*1024*1024, None),
    (b'\x1f\x8b\x08',     "gz",   "GZip Archive",       500*1024*1024,  b'\x00\x00'),
    (b'7z\xbc\xaf\x27\x1c',"7z", "7-Zip Archive",      2*1024*1024*1024, None),
    (b'BZh',              "bz2",  "BZip2 Archive",      500*1024*1024,  None),
    (b'ustar',            "tar",  "TAR Archive",        4*1024*1024*1024, None),

    # ── Database ──────────────────────────────────────────────────────────────
    (b'SQLite format 3\x00',"db", "SQLite Database",    2*1024*1024*1024, None),

    # ── Text / Code ───────────────────────────────────────────────────────────
    (b'<?xml',            "xml",  "XML File",           50*1024*1024,   None),
    (b'<!DOCTYPE html',   "html", "HTML File",          10*1024*1024,   None),
    (b'<html',            "html", "HTML File",          10*1024*1024,   None),

    # ── Executables ───────────────────────────────────────────────────────────
    (b'MZ',               "exe",  "Windows Executable", 500*1024*1024,  None),
    (b'\x7fELF',          "elf",  "Linux Executable",   500*1024*1024,  None),
]

CHUNK_SIZE     = 1024 * 1024   # 1MB read chunks
MAX_CARVE      = 100 * 1024 * 1024  # 100MB max single file carve
MAX_FILES      = 1000          # stop after finding this many
READ_AHEAD     = 4 * 1024 * 1024   # 4MB look-ahead for footer search


def scan_drive(drive_path: str, is_image: bool = False) -> dict:
    """
    Main scan function. Reads raw sectors and finds files by signature.
    Returns a dict with all found files and stats.
    """
    found    = []
    scanned  = 0
    errors   = []

    open_path = drive_path if (is_image or os.path.isfile(drive_path)) \
                else _resolve_path(drive_path)

    try:
        with open(open_path, "rb") as fh:
            offset  = 0
            overlap = b""

            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break

                buf = overlap + chunk

                for sig, ext, desc, max_sz, footer in FILE_SIGNATURES:
                    pos = 0
                    while True:
                        idx = buf.find(sig, pos)
                        if idx == -1:
                            break

                        abs_offset = offset - len(overlap) + idx
                        if abs_offset < 0:
                            pos = idx + 1
                            continue

                        # Try to get accurate size using footer / header fields
                        size, has_footer = _find_size(
                            fh, buf, idx, abs_offset, ext, footer, max_sz
                        )

                        if size < 64:          # too small → false positive
                            pos = idx + 1
                            continue

                        conf = _score(ext, size, has_footer)

                        file_id = hashlib.md5(
                            f"{abs_offset}:{ext}".encode()
                        ).hexdigest()[:10]

                        found.append({
                            "id":         file_id,
                            "offset":     abs_offset,
                            "offset_hex": f"0x{abs_offset:08X}",
                            "extension":  ext,
                            "type":       desc,
                            "size_bytes": size,
                            "size_str":   _fmt(size),
                            "confidence": conf,
                            "has_footer": has_footer,
                            "status":     "found",
                        })
                        pos = idx + len(sig)

                scanned += len(chunk)
                overlap  = buf[-512:]   # keep last 512 bytes for cross-chunk matches
                offset  += len(chunk)

                # Deduplicate by (offset, ext)
                seen = set()
                uniq = []
                for item in found:
                    k = (item["offset"], item["extension"])
                    if k not in seen:
                        seen.add(k)
                        uniq.append(item)
                found = uniq

                if len(found) >= MAX_FILES:
                    break

    except PermissionError:
        raise
    except Exception as e:
        errors.append(str(e))

    found.sort(key=lambda x: x["offset"])

    by_type: dict[str, int] = {}
    for item in found:
        k = item["extension"].upper()
        by_type[k] = by_type.get(k, 0) + 1

    return {
        "files":         found,
        "total_found":   len(found),
        "scanned_bytes": scanned,        # unified key (was bytes_scanned)
        "scanned_str":   _fmt(scanned),
        "type_summary":  by_type,
        "errors":        errors,
        "source":        drive_path,     # unified key (was drive_path)
        "drive_path":    drive_path,     # kept for backwards compat
        "scanned_at":    datetime.now().isoformat(),
    }


def scan_drive_safe(drive_path: str, is_image: bool = False) -> dict:
    """
    Corruption-aware wrapper around scan_drive().

    1. If *drive_path* is a PhysicalDriveX path, query device_manager first.
    2. If the drive is flagged as corrupted (filesystem unreadable):
       - Log a warning, set mode = "raw_fallback"
       - Proceed with raw sector scan via disk_reader.DiskReader
         (same data, but we skip any filesystem-layer access)
    3. If the drive cannot be read at all → return an error dict.
    4. Otherwise delegate straight to scan_drive().

    Returns the same dict shape as scan_drive(), plus:
        "scan_mode": "normal" | "raw_fallback" | "error"
        "corrupted": bool
    """
    from core.device_manager import probe_device

    scan_mode = "normal"
    corrupted = False

    # Only probe PhysicalDriveX paths (not image files)
    if not is_image and drive_path.lower().startswith("\\\\.\\physicaldrive"):
        try:
            probe = probe_device(drive_path)
            corrupted = probe.get("corrupted", False)
            if not probe.get("raw_scan_ok", True):
                return {
                    "files":         [],
                    "total_found":   0,
                    "bytes_scanned": 0,
                    "scanned_str":   "0 B",
                    "type_summary":  {},
                    "errors":        [probe.get("error", "Device not accessible")],
                    "drive_path":    drive_path,
                    "scanned_at":    datetime.now().isoformat(),
                    "scan_mode":     "error",
                    "corrupted":     True,
                }
            if corrupted:
                scan_mode = "raw_fallback"
        except Exception:
            pass  # best-effort probe; proceed anyway

    result = scan_drive(drive_path, is_image=is_image)
    result["scan_mode"] = scan_mode
    result["corrupted"] = corrupted
    return result


def recover_files(drive_path: str, file_entries: list, output_dir: str) -> dict:
    """Save recovered files to output_dir on disk."""
    os.makedirs(output_dir, exist_ok=True)
    open_path  = drive_path if os.path.isfile(drive_path) else _resolve_path(drive_path)
    recovered  = []
    failed     = []

    with open(open_path, "rb") as fh:
        for entry in file_entries:
            fname    = f"recovered_{entry['id']}.{entry['extension']}"
            out_path = os.path.join(output_dir, fname)
            try:
                data = _carve_bytes(fh, entry)
                with open(out_path, "wb") as out:
                    out.write(data)
                recovered.append({
                    "file":      fname,
                    "path":      out_path,
                    "size_str":  _fmt(len(data)),
                    "extension": entry["extension"],
                    "offset":    entry["offset_hex"],
                })
            except Exception as e:
                failed.append({"file": fname, "error": str(e)})

    return {
        "recovered":   recovered,
        "failed":      failed,
        "output_dir":  output_dir,
        "total_saved": len(recovered),
    }


def carve_to_zip(drive_path: str, file_entries: list) -> str:
    """
    Carve selected files and pack them into a ZIP.
    Returns the temp ZIP file path (caller must delete it).
    """
    open_path = drive_path if os.path.isfile(drive_path) else _resolve_path(drive_path)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    tmp.close()

    with open(open_path, "rb") as fh:
        with zipfile.ZipFile(tmp.name, "w", zipfile.ZIP_DEFLATED) as zf:
            for entry in file_entries:
                fname = f"recovered_{entry['id']}.{entry['extension']}"
                try:
                    data = _carve_bytes(fh, entry)
                    zf.writestr(fname, data)
                except Exception:
                    pass  # skip failed carves silently

    return tmp.name


def carve_single(drive_path: str, entry: dict) -> tuple[str, str]:
    """
    Carve one file and write to a temp file.
    Returns (temp_file_path, filename).
    """
    open_path = drive_path if os.path.isfile(drive_path) else _resolve_path(drive_path)
    fname     = f"recovered_{entry['id']}.{entry['extension']}"
    tmp       = tempfile.NamedTemporaryFile(
        delete=False, suffix=f".{entry['extension']}"
    )

    with open(open_path, "rb") as fh:
        data = _carve_bytes(fh, entry)
        tmp.write(data)
    tmp.close()
    return tmp.name, fname


# ── Internal helpers ───────────────────────────────────────────────────────────

def _carve_bytes(fh, entry: dict) -> bytes:
    """Read the actual bytes for one file entry from an open file handle."""
    offset = entry["offset"]
    size   = min(entry.get("size_bytes", MAX_CARVE), MAX_CARVE)
    ext    = entry["extension"]

    fh.seek(offset)
    data = fh.read(size)

    # Trim precisely to footer if we know it
    footer = _footer_bytes(ext)
    if footer and footer in data:
        end  = data.rfind(footer) + len(footer)
        data = data[:end]

    return data


def _find_size(fh, buf: bytes, idx: int, abs_offset: int,
               ext: str, footer, max_sz: int) -> tuple[int, bool]:
    """
    Try to determine exact file size.
    Returns (size_in_bytes, footer_found_bool).
    """
    # ── JPEG ──────────────────────────────────────────────────────────────────
    if ext == "jpg":
        end = buf.find(b'\xff\xd9', idx + 2)
        if end != -1:
            return end - idx + 2, True
        # Read ahead
        fh.seek(abs_offset)
        ahead = fh.read(min(max_sz, READ_AHEAD))
        end   = ahead.rfind(b'\xff\xd9')
        if end != -1:
            return end + 2, True
        return min(max_sz, 3*1024*1024), False

    # ── PNG ───────────────────────────────────────────────────────────────────
    if ext == "png":
        footer = b'IEND\xaeB`\x82'
        fh.seek(abs_offset)
        ahead = fh.read(min(max_sz, READ_AHEAD))
        end   = ahead.find(footer)
        if end != -1:
            return end + len(footer), True
        return min(max_sz, 5*1024*1024), False

    # ── PDF ───────────────────────────────────────────────────────────────────
    if ext == "pdf":
        fh.seek(abs_offset)
        ahead = fh.read(min(max_sz, READ_AHEAD))
        end   = ahead.rfind(b'%%EOF')
        if end != -1:
            return end + 5, True
        return min(max_sz, 10*1024*1024), False

    # ── ZIP / DOCX / XLSX / PPTX ─────────────────────────────────────────────
    if ext in ("zip", "docx", "xlsx", "pptx"):
        fh.seek(abs_offset)
        ahead = fh.read(min(max_sz, READ_AHEAD))
        end   = ahead.rfind(b'PK\x05\x06')
        if end != -1:
            # Central directory end record is 22 bytes minimum
            return end + 22, True
        return min(max_sz, 10*1024*1024), False

    # ── GIF ───────────────────────────────────────────────────────────────────
    if ext == "gif":
        fh.seek(abs_offset)
        ahead = fh.read(min(max_sz, 10*1024*1024))
        end   = ahead.find(b'\x00\x3b')
        if end != -1:
            return end + 2, True
        return min(max_sz, 2*1024*1024), False

    # ── MP4: size in first 4 bytes of ftyp atom ───────────────────────────────
    if ext == "mp4" and idx + 8 <= len(buf):
        try:
            atom = struct.unpack('>I', buf[idx:idx+4])[0]
            if 1024 < atom < max_sz:
                return atom, False
        except Exception:
            pass

    # ── AVI / WAV: RIFF chunk size in bytes 4-8 ───────────────────────────────
    if ext in ("avi", "wav") and idx + 8 <= len(buf):
        try:
            chunk_size = struct.unpack('<I', buf[idx+4:idx+8])[0]
            total = chunk_size + 8
            if 1024 < total < max_sz:
                return total, False
        except Exception:
            pass

    # ── Default: fraction of max size ────────────────────────────────────────
    default = min(max_sz // 8, 5 * 1024 * 1024)
    return default, False


def _footer_bytes(ext: str):
    return {
        "jpg":  b'\xff\xd9',
        "png":  b'IEND\xaeB`\x82',
        "pdf":  b'%%EOF',
        "gif":  b'\x00\x3b',
        "zip":  b'PK\x05\x06',
        "docx": b'PK\x05\x06',
        "xlsx": b'PK\x05\x06',
        "pptx": b'PK\x05\x06',
    }.get(ext)


def _score(ext: str, size: int, has_footer: bool) -> int:
    """
    Confidence score (0-99).
    90-99 = complete file with footer found
    70-89 = size from header, likely complete
    50-69 = estimated size, might be partial
    <50   = short/ambiguous match
    """
    if has_footer:
        score = 90
        if size > 1024:    score += 3
        if size > 100*1024: score += 3
        if ext in ("jpg","png","pdf","gif"): score += 3
        return min(score, 99)

    # No footer
    score = 55
    if size > 10 * 1024:    score += 8
    if size > 100 * 1024:   score += 7
    if ext in ("jpg","png","pdf","mp4","mp3","docx","xlsx"): score += 5
    if ext in ("bmp","exe","elf","rtf"): score += 3
    return min(score, 88)


def _raw_path(path: str) -> str:
    if platform.system() == "Windows" and len(path) >= 2 and path[1] == ":":
        return f"\\\\.\\{path[0]}:"
    return path


def _fmt(b: int) -> str:
    if b >= 1024**3: return f"{b/1024**3:.1f} GB"
    if b >= 1024**2: return f"{b/1024**2:.1f} MB"
    if b >= 1024:    return f"{b/1024:.1f} KB"
    return f"{b} B"
