"""
core/scan_bridge.py  —  EDRT v4.9
==================================
Integrates RecoverPy's production-grade binary scanner into EDRT's
carving pipeline without touching the Flask app or the UI.

Public API (mirrors EDRT's existing recovery_engine surface):
    rp_carve_stream(source_path, *, signatures, stop_event, progress_cb,
                    max_files, chunk_size)  → Iterator[RecoveredObject]

    rp_get_device_size(source_path) → int   (bytes, 0 if unknown)

The rest of recovery_engine.py (metadata recovery, save_to_dir, etc.)
is kept intact — only the chunk-scan hot path is replaced.
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
from threading import Event
from typing import Callable, Generator, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── RecoverPy scanner imports ─────────────────────────────────────────────────
from core.recoverpy_scan.lib.search.binary_scanner import (
    ScanError,
    ScanHit,
    iter_scan_hits,
    DEFAULT_SCAN_CHUNK_SIZE,
)
from core.recoverpy_scan.lib.storage.block_device_metadata import (
    DeviceIOError,
    get_device_info,
)
from core.recoverpy_scan.lib.storage.byte_range_reader import (
    BlockExtractionError,
    read_range,
)

# ── EDRT file-signature table (imported from recovery_engine) ─────────────────
# Avoid a circular import by re-importing from the same module at call time.
def _get_signatures():
    from core.recovery_engine import FILE_SIGNATURES
    return FILE_SIGNATURES

# ── Helpers ───────────────────────────────────────────────────────────────────

def rp_get_device_size(source_path: str) -> int:
    """Return byte length of *source_path* using RecoverPy's metadata probe."""
    try:
        info = get_device_info(source_path)
        return info.size_bytes
    except (DeviceIOError, OSError, Exception) as exc:
        logger.debug("rp_get_device_size fallback for %s: %s", source_path, exc)
        # Fallback: seek-to-end
        try:
            with open(source_path, "rb") as fh:
                fh.seek(0, 2)
                return fh.tell()
        except OSError:
            return 0


def _make_obj_id(source_path: str, offset: int) -> str:
    raw = f"{source_path}:{offset}".encode()
    return hashlib.md5(raw).hexdigest()[:16]


def _fmt(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _confidence(has_footer: bool, size: int, max_size: int) -> int:
    if has_footer:
        return 95
    if size >= 512:
        ratio = size / max_size
        return max(50, int(85 - ratio * 30))
    return 45


def _find_footer_offset(
    source_path: str,
    header_offset: int,
    footer_magic: bytes,
    max_size: int,
    chunk: int = 1024 * 1024,
) -> Optional[int]:
    """
    Search forward from *header_offset* for *footer_magic*.
    Uses RecoverPy's read_range for safe, bounded pread access.
    """
    pos = header_offset
    end = header_offset + max_size
    overlap = len(footer_magic) - 1

    tail = b""
    while pos < end:
        to_read = min(chunk, end - pos)
        try:
            block = read_range(source_path, pos, to_read)
        except (BlockExtractionError, OSError):
            break

        buf = tail + block
        idx = buf.find(footer_magic)
        if idx >= 0:
            return pos - len(tail) + idx + len(footer_magic)

        tail = buf[-overlap:] if overlap else b""
        pos += len(block)
        if len(block) < to_read:
            break

    return None


def _carve_single_hit(
    source_path: str,
    hit: ScanHit,
    sig: bytes,
    ext: str,
    desc: str,
    max_size: int,
    footer: Optional[bytes],
) -> Optional[dict]:
    """
    Given a ScanHit, determine file size (via footer search or max_size cap)
    and build a RecoveredObject dict compatible with EDRT's existing schema.
    """
    offset = hit.match_offset
    has_footer = False
    size = max_size  # pessimistic default

    if footer:
        found = _find_footer_offset(source_path, offset + len(sig), footer, max_size)
        if found:
            size = found - offset
            has_footer = True
        # If no footer, fall back to max_size but lower confidence

    # Sanity: skip tiny hits
    if size < 64:
        return None

    obj_id = _make_obj_id(source_path, offset)

    return {
        "id":          obj_id,
        "source":      "carving",
        "name":        f"recovered_{obj_id}.{ext}",
        "path":        "",
        "extension":   ext,
        "description": desc,
        "offset":      offset,
        "offset_hex":  hex(offset),
        "size_bytes":  size,
        "size_str":    _fmt(size),
        "confidence":  _confidence(has_footer, size, max_size),
        "deleted":     False,
        "has_footer":  has_footer,
        "repaired":    False,
        "repair_log":  [],
        "fs_type":     "",
        "metadata": {
            "created":   None,
            "modified":  None,
            "accessed":  None,
            "attrs":     "",
            "inode":     None,
            "cluster":   None,
        },
        "data": None,
    }


# ── Main public entry point ───────────────────────────────────────────────────

def rp_carve_stream(
    source_path: str,
    *,
    stop_event: Optional[Event] = None,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    max_files: int = 5000,
    chunk_size: int = DEFAULT_SCAN_CHUNK_SIZE,
) -> Generator[dict, None, None]:
    """
    Streaming file-carver backed by RecoverPy's binary_scanner.

    Replaces EDRT's hand-rolled chunk loop with RecoverPy's production-grade
    iter_scan_hits() engine (bounded queues, overlap-safe, pause/stop support).

    For each signature in EDRT's FILE_SIGNATURES table, runs a separate
    scan pass so every magic-byte pattern gets checked — exactly what EDRT's
    original loop did, but using RecoverPy's more robust scanner underneath.

    Yields RecoveredObject dicts (same schema as recovery_engine.carve_stream).

    Parameters
    ----------
    source_path  : path to disk image or raw device
    stop_event   : threading.Event — set it to abort mid-scan
    progress_cb  : called as progress_cb(bytes_scanned, total_bytes)
                   whenever the scanner advances; may be None
    max_files    : hard cap on total results
    chunk_size   : read chunk passed to binary_scanner (default 8 MB)
    """
    signatures = _get_signatures()
    total_bytes = rp_get_device_size(source_path)
    found_count = 0
    seen: set[tuple] = set()   # (offset, ext) dedup

    if stop_event is None:
        stop_event = Event()   # never-set sentinel — cleaner than None checks

    for sig_bytes, ext, desc, max_size, footer in signatures:
        if stop_event.is_set() or found_count >= max_files:
            break

        try:
            for hit in iter_scan_hits(
                source_path,
                sig_bytes,
                chunk_size=chunk_size,
                stop_event=stop_event,
            ):
                if stop_event.is_set() or found_count >= max_files:
                    return

                key = (hit.match_offset, ext)
                if key in seen:
                    continue
                seen.add(key)

                obj = _carve_single_hit(
                    source_path, hit, sig_bytes, ext, desc, max_size, footer
                )
                if obj is None:
                    continue

                yield obj
                found_count += 1

                if progress_cb and total_bytes:
                    progress_cb(hit.match_offset, total_bytes)

        except ScanError as exc:
            logger.warning("rp_carve_stream ScanError for sig %r: %s", sig_bytes[:4], exc)
            continue
        except Exception as exc:
            logger.error("rp_carve_stream unexpected error: %s", exc, exc_info=True)
            continue
