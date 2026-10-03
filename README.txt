EDRT — External Data Recovery Tool
Version: 4.9
Team: Data ka BHOOT | Problem SW-5
============================================================

WHAT'S NEW IN v4.9
-------------------
ENGINE UPGRADE (RecoverPy integration):
  The raw-carving hot path now uses RecoverPy's production-grade
  binary_scanner under the hood:

  • 8 MB chunks (was 1 MB) — fewer syscalls, faster scans
  • pread()-based random access — fully thread-safe, no seek races
  • Proper cross-chunk overlap — signatures spanning chunk boundaries
    are now always detected (was a subtle bug in v4.8)
  • Threading.Event stop support — the UI Stop button now immediately
    interrupts the scanner at the next chunk boundary
  • Bounded backpressure queue — memory stays stable even on disks
    dense with signatures
  • Cross-platform device-size probe — works for raw devices on
    Windows (IOCTL), Linux (ioctl/seek), and macOS (seek)

NEW ENDPOINT:
  POST /api/stop/<scan_id>   — abort a running scan immediately

All existing features preserved:
  • NTFS MFT + FAT directory metadata recovery
  • Corruption repair (JPEG/PNG/ZIP/PDF synthetic headers)
  • Forensic log report (SHA-256, acquisition event log)
  • TXT printable-ASCII run detection
  • Real-time SSE progress stream
  • ZIP export / single-file download

WHAT'S NEW IN v4.8 (previous)
------------------------------
BUG FIX:  Scan crash "Cannot read properties of undefined (reading 'filter')"
          FIXED — scan now properly polls /api/progress then /api/results.
FEATURE:  Quick Scan & Deep Scan modes correctly sent to backend engine.
FEATURE:  Real-time progress bar tied to actual backend scan progress.
FEATURE:  Proper Stop button — signals the polling loop cleanly.
FEATURE:  Filename sanitization — null bytes stripped from names.
FEATURE:  APFS detection (basic).
FEATURE:  EXT4/EXT2 detection via superblock magic 0xEF53.
FEATURE:  Improved corruption detection (MBR/GPT/NTFS checks).
FEATURE:  Professional forensic log report (SHA-256, FTK-style footer).
FEATURE:  Live forensic log messages during scan.

HOW TO RUN
----------
Windows:   Double-click START_WINDOWS.bat  (run as Administrator)
Mac/Linux: sudo bash START_MAC_LINUX.sh

Then open: http://localhost:5000

REQUIREMENTS
------------
Python 3.8+
pip install -r requirements.txt
