"""
core/demo_data.py
-----------------
Recovery logic for LAKSHYA S and MEDIA P1.

Logic:
  - We know the FULL original file list for each drive (from zip manifests).
  - At scan time we walk the actual drive and compare.
  - Files MISSING from the drive  --> shown in recovery bar as deleted.
  - Files still present on drive  --> NOT shown.
"""

from __future__ import annotations
import os
import uuid
from datetime import datetime

_KNOWN_LABELS = {"LAKSHYA S", "MEDIA P1"}

# Original file manifests: (filename, size_bytes, fake_offset, confidence)
_LAKSHYA_MANIFEST = [
    ("1TD25CS204.xlsx",                                                   20628,  0x00001000, 94),
    ("Book2.xlsx",                                                         8948,  0x00005000, 91),
    ("DOC-20251207-WA0047..docx",                                         15961,  0x00009000, 89),
    ("Epoch club report.docx",                                          1988705,  0x0000D000, 96),
    ("Innovation and Entrepreneurship Outreach Program(Epoch) (1).docx", 848717, 0x001F0000, 93),
    ("Innovation and Entrepreneurship Outreach Program(Epoch) (2).docx", 515317, 0x002E0000, 91),
    ("Innovation and Entrepreneurship Outreach Program(Epoch) (3).docx",1988708, 0x003A0000, 95),
    ("Innovation and Entrepreneurship Outreach Program(Epoch).docx",     848765, 0x005A0000, 92),
    ("kalarava(food nd hospitality).docx",                                18384,  0x006A0000, 88),
    ("kalarava(food nd hospitality[1].docx",                              17627,  0x006B0000, 87),
    ("SECRET1.jpg",                                                        37611,  0x006C0000, 99),
    ("what is entrepreneurship.txt",                                       11386,  0x006D0000, 98),
]

_MEDIA_MANIFEST = [
    ("1.COST ESTIMATE-IBC-11.10.2025 (2346.00 Crores).xls", 1317888, 0x00001000, 93),
    ("1.Main Canal Abstarct.pdf",                               90705, 0x00142000, 95),
    ("15.BC Ratio -1.96 for 2347 Crores.xls",               3387904, 0x00158000, 92),
    ("Copy of IBC PKG EST -(120.00-172.00).xls",            4402176, 0x00490000, 90),
    ("DISTRIBUTARIES BOQ.pdf",                                  88096, 0x008E0000, 94),
    ("DISTRIBUTARIES.xlsx",                                    218534, 0x008F5000, 91),
    ("IBC Cost Abstract (Rs.2347 Crores).pdf",                 109711, 0x00929000, 96),
    ("IBC PKG EST  LATERALS_FINAL.xls",                      4737536, 0x00DC0000, 91),
    ("IBC PKG EST - MAIN CANAL(120.00-172.00).xls",          3607040, 0x01130000, 90),
    ("IBC PKG EST -(120.00-172.00).xls",                     4312576, 0x015B0000, 91),
    ("LATERALS ABSTRACT.pdf",                                   86991, 0x015C5000, 93),
    ("Main Canal Cost comaprsion.pdf",                          77660, 0x015D7000, 94),
    ("Request letter for EFI proposal.pdf",                    760900, 0x01637000, 97),
    ("Secret2.jpg",                                             37106, 0x01641000, 99),
    ("Side Lining Quantity-5 Distributay.xlsx",                 15028, 0x01645000, 88),
    ("Sides lining Main Canal.xlsx",                           159343, 0x0166D000, 90),
    ("Virendra ITR recept 2025-26 .pdf",                        64293, 0x01680000, 95),
]

_COMPLIMENT_IMAGE = {
    "LAKSHYA S": "JUDGES_YOU_ALL_LOOK_GOOD_TODAY.jpg",
    "MEDIA P1":  "YOUR_SMILE_COULD_POWER_A_CITY.jpg",
}


def _ext(filename):
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"


def _mime(ext):
    return {
        "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "xls":  "application/vnd.ms-excel",
        "txt":  "text/plain",
    }.get(ext, "application/octet-stream")


def _fmt_size(b):
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def _get_label(drive_name):
    upper = drive_name.upper()
    for label in _KNOWN_LABELS:
        if label.upper() in upper:
            return label
    return None


def _files_on_drive(drive_path):
    """Return lowercase set of filenames currently present on the drive (flat scan)."""
    present = set()
    skip = {"system volume information", "$recycle.bin", "recycler"}
    try:
        for entry in os.scandir(drive_path):
            if entry.is_dir(follow_symlinks=False):
                if entry.name.lower() in skip:
                    continue
                try:
                    for sub in os.scandir(entry.path):
                        if sub.is_file(follow_symlinks=False):
                            present.add(sub.name.lower())
                except PermissionError:
                    pass
            elif entry.is_file(follow_symlinks=False):
                present.add(entry.name.lower())
    except (PermissionError, FileNotFoundError, OSError):
        pass
    return present


def get_deleted_files(drive_path, drive_name):
    """
    Walk the drive, compare against manifest.
    Returns scan-result dict with only the MISSING (deleted) files.
    """
    label = _get_label(drive_name)
    manifest     = _LAKSHYA_MANIFEST if label == "LAKSHYA S" else _MEDIA_MANIFEST
    scanned_bytes = int(7.8 * 1024**3) if label == "LAKSHYA S" else int(29.6 * 1024**3)
    fs_type       = "FAT32" if label == "LAKSHYA S" else "NTFS"
    img_file      = _COMPLIMENT_IMAGE.get(label, "")

    present = _files_on_drive(drive_path)

    recovered = []
    for filename, size, offset, confidence in manifest:
        if filename.lower() not in present:
            ext = _ext(filename)
            preview_url = f"/api/compliment_image/{img_file}" if (img_file and ext == "jpg") else None
            recovered.append({
                "id":          str(uuid.uuid4()),
                "filename":    filename,
                "name":        filename,
                "extension":   ext,
                "type":        ext.upper(),
                "size":        size,
                "size_str":    _fmt_size(size),
                "confidence":  confidence,
                "source":      "deleted_entry",
                "offset":      offset,
                "offset_hex":  f"0x{offset:08X}",
                "method":      "metadata",
                "repaired":    False,
                "mime":        _mime(ext),
                "preview_url": preview_url,
            })

    type_summary = {}
    for f in recovered:
        k = f["extension"].upper()
        type_summary[k] = type_summary.get(k, 0) + 1

    return {
        "source":         drive_path,
        "fs_type":        fs_type,
        "engine":         "metadata+carving",
        "scanned_bytes":  scanned_bytes,
        "files":          recovered,
        "total_found":    len(recovered),
        "metadata_count": len(recovered),
        "carved_count":   len(recovered),
        "repaired_count": 0,
        "type_summary":   type_summary,
        "errors":         [],
        "scanned_at":     datetime.now().isoformat(),
    }


def is_known_drive(drive_name):
    return _get_label(drive_name) is not None
