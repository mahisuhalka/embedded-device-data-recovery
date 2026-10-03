#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════
#  EDRT v5 — External Data Recovery Tool
#  Team: Data ka BHOOT | SW-5
#  Run with: bash START_MAC_LINUX.sh
#  On Mac/Linux sudo may be needed for raw disk access.
# ══════════════════════════════════════════════════════════

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo " ================================================"
echo "   EDRT v5 — External Data Recovery Tool"
echo "   Team: Data ka BHOOT  |  SW-5"
echo " ================================================"
echo ""

# ── Check Python ─────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo " [ERROR] python3 not found."
    echo " Install it from https://python.org or via your package manager."
    exit 1
fi

echo " Python: $(python3 --version)"
echo ""

# ── Install dependencies ──────────────────────────────────
echo " Installing / verifying dependencies..."
pip3 install flask psutil --quiet --disable-pip-version-check 2>/dev/null || \
python3 -m pip install flask psutil --quiet --disable-pip-version-check
echo " Dependencies OK."
echo ""

# ── Open browser after 2s ────────────────────────────────
(sleep 2 && \
  if command -v open &>/dev/null; then
    open "http://localhost:5000"
  elif command -v xdg-open &>/dev/null; then
    xdg-open "http://localhost:5000"
  fi
) &

# ── Warn if not root (needed for raw disk reads) ─────────
if [ "$EUID" -ne 0 ]; then
    echo " [WARNING] Not running as root."
    echo " Raw disk access may fail. Re-run with: sudo bash START_MAC_LINUX.sh"
    echo ""
fi

echo " Starting server at http://localhost:5000"
echo " Press Ctrl+C to stop."
echo ""

python3 -B app.py
