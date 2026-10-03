"""
core/ai_classifier.py — EDRT AI-Style File Content Classifier
==============================================================

Structured as a lightweight ML pipeline (no heavy dependencies):

  Stage 1 — FEATURE EXTRACTION
     Extracts signals from raw bytes + metadata:
       • magic / header bytes
       • printable-text ratio
       • entropy (randomness measure)
       • extension
       • has_footer / has_header flags
       • confidence from carver engine

  Stage 2 — RULE MATCHING  (heuristic "model")
     Each category has a set of weighted rules that fire on features.
     Rules return a partial score (0–100) + a human-readable reason token.

  Stage 3 — SCORING & AGGREGATION
     Scores from all matching rules are merged.
     Header validity, file completeness, and signature strength
     each contribute to the final 0–100 confidence band.

  Stage 4 — OUTPUT
     Returns:
       {
           "type":       str,   # Logs | Credentials | Config | Media | Unknown
           "confidence": int,   # 0–100
           "reason":     str,   # human-readable explanation
       }

PUBLIC API
----------
  classify(entry: dict, raw_bytes: bytes | None = None) -> dict

  entry   — a RecoveredObject dict produced by file_carver / recovery_engine
  raw_bytes — optional: up to 4 KB of the file's content for deep inspection
              (pass None to rely on metadata only)

EXAMPLE
-------
  from core.ai_classifier import classify

  result = classify(entry, raw_bytes=file_header_bytes)
  print(result)
  # → {'type': 'Credentials', 'confidence': 87, 'reason': 'SSID+PASS keyword match; high header validity'}
"""

import re
import math
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

# Final output categories
CATEGORY_LOGS        = "Logs"
CATEGORY_CREDENTIALS = "Credentials"
CATEGORY_CONFIG      = "Config"
CATEGORY_MEDIA       = "Media"
CATEGORY_UNKNOWN     = "Unknown"

ALL_CATEGORIES = (
    CATEGORY_LOGS,
    CATEGORY_CREDENTIALS,
    CATEGORY_CONFIG,
    CATEGORY_MEDIA,
    CATEGORY_UNKNOWN,
)

# Extensions pre-mapped to a strong category prior
_EXT_CATEGORY_MAP: dict[str, str] = {
    # Logs
    "log":   CATEGORY_LOGS,
    "out":   CATEGORY_LOGS,
    "trace": CATEGORY_LOGS,
    "evt":   CATEGORY_LOGS,
    "evtx":  CATEGORY_LOGS,
    # Credentials / secrets
    "key":   CATEGORY_CREDENTIALS,
    "pem":   CATEGORY_CREDENTIALS,
    "pfx":   CATEGORY_CREDENTIALS,
    "p12":   CATEGORY_CREDENTIALS,
    "kdbx":  CATEGORY_CREDENTIALS,
    "ovpn":  CATEGORY_CREDENTIALS,
    # Config
    "cfg":   CATEGORY_CONFIG,
    "conf":  CATEGORY_CONFIG,
    "ini":   CATEGORY_CONFIG,
    "json":  CATEGORY_CONFIG,
    "yaml":  CATEGORY_CONFIG,
    "yml":   CATEGORY_CONFIG,
    "toml":  CATEGORY_CONFIG,
    "xml":   CATEGORY_CONFIG,
    "env":   CATEGORY_CONFIG,
    "properties": CATEGORY_CONFIG,
    # Media
    "jpg":   CATEGORY_MEDIA,
    "jpeg":  CATEGORY_MEDIA,
    "png":   CATEGORY_MEDIA,
    "gif":   CATEGORY_MEDIA,
    "bmp":   CATEGORY_MEDIA,
    "tiff":  CATEGORY_MEDIA,
    "webp":  CATEGORY_MEDIA,
    "ico":   CATEGORY_MEDIA,
    "mp3":   CATEGORY_MEDIA,
    "flac":  CATEGORY_MEDIA,
    "ogg":   CATEGORY_MEDIA,
    "wav":   CATEGORY_MEDIA,
    "mp4":   CATEGORY_MEDIA,
    "mkv":   CATEGORY_MEDIA,
    "avi":   CATEGORY_MEDIA,
    "mov":   CATEGORY_MEDIA,
    "flv":   CATEGORY_MEDIA,
    "pdf":   CATEGORY_MEDIA,
    "docx":  CATEGORY_MEDIA,
    "xlsx":  CATEGORY_MEDIA,
    "pptx":  CATEGORY_MEDIA,
}

# Keyword patterns compiled once at import time
_CRED_PATTERNS = re.compile(
    r'\b(SSID|password|passwd|PASS|secret|token|api[_\-]?key|auth[_\-]?key'
    r'|private[_\-]?key|credentials?|username|user[_\-]?id|access[_\-]?key'
    r'|bearer|oauth|jwt|salt|hash|md5|sha1|sha256)\b',
    re.IGNORECASE,
)

_CONFIG_PATTERNS = re.compile(
    r'(\{[\s\S]{0,300}\}|\[[\s\S]{0,300}\]'           # JSON / TOML / INI blocks
    r'|^\s*\w+\s*=\s*.+$'                              # key = value lines
    r'|<\w[\w\s="\'./:-]{0,200}>'                      # XML / HTML tags
    r'|\bhost\b|\bport\b|\bendpoint\b|\burl\b|\bpath\b'
    r'|\bdatabase\b|\bserver\b|\bnamespace\b)',
    re.IGNORECASE | re.MULTILINE,
)

_LOG_TIMESTAMP_PATTERNS = re.compile(
    r'('
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'        # ISO-8601
    r'|\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}'         # US date + time
    r'|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'           # syslog: Jan  3 14:22:01
    r'|\[\d{4}-\d{2}-\d{2}\]'                          # [2024-01-01]
    r'|\d{10,13}'                                       # Unix epoch (10-13 digits)
    r')'
)

_LOG_LEVEL_PATTERNS = re.compile(
    r'\b(DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE|NOTICE'
    r'|\[ERR\]|\[WRN\]|\[INF\]|\[DBG\])\b',
    re.IGNORECASE,
)

_LOG_ENTRY_PATTERNS = re.compile(
    r'(Exception|Traceback|stack\s+trace|at\s+\w+\.\w+\('
    r'|HTTP/[12]\.[01]\s+\d{3}'                        # HTTP status lines
    r'|\d+\.\d+\.\d+\.\d+\s+\S+\s+\S+\s+\[)',         # Apache/Nginx access log
    re.IGNORECASE,
)

# Binary magic bytes that confirm Media
_MEDIA_MAGIC: tuple[bytes, ...] = (
    b'\xff\xd8\xff',       # JPEG
    b'\x89PNG\r\n\x1a\n', # PNG
    b'GIF8',               # GIF
    b'BM',                 # BMP
    b'ID3',                # MP3
    b'fLaC',               # FLAC
    b'OggS',               # OGG
    b'RIFF',               # WAV / AVI
    b'\x1aE\xdf\xa3',     # MKV
    b'%PDF-',              # PDF
    b'PK\x03\x04',        # DOCX/XLSX/PPTX/ZIP
    b'\xd0\xcf\x11\xe0',  # legacy OLE2 (DOC/XLS)
    b'{\rtf1',             # RTF
)


# ──────────────────────────────────────────────────────────────────────────────
# STAGE 1 — FEATURE EXTRACTION
# ──────────────────────────────────────────────────────────────────────────────

class _Features:
    """Container for all signals extracted from an entry + raw bytes."""

    __slots__ = (
        "extension",
        "ext_category",
        "carver_confidence",
        "has_header",
        "has_footer",
        "size_bytes",
        "is_repaired",

        # text-content signals (None if raw_bytes not supplied)
        "text_sample",
        "printable_ratio",
        "entropy",
        "cred_hits",
        "config_hits",
        "log_ts_hits",
        "log_level_hits",
        "log_entry_hits",
        "media_magic_match",
    )

    def __init__(self) -> None:
        for s in self.__slots__:
            setattr(self, s, None)


def _shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of a byte sequence (0–8 bits/byte)."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_features(entry: dict, raw_bytes: Optional[bytes]) -> _Features:
    """
    Stage 1: pull every available signal out of `entry` and `raw_bytes`.

    Parameters
    ----------
    entry : dict
        RecoveredObject dict from file_carver or recovery_engine.
    raw_bytes : bytes | None
        Up to 4 KB of content read from the recovered file.
        Pass None to run metadata-only classification.
    """
    f = _Features()

    # ── metadata signals ──────────────────────────────────────────────────────
    f.extension       = (entry.get("extension") or "").lower().strip(".")
    f.ext_category    = _EXT_CATEGORY_MAP.get(f.extension)
    try:
        f.carver_confidence = int(entry.get("confidence", 0))
    except (TypeError, ValueError):
        f.carver_confidence = 0
    f.has_header      = True   # presence in carver implies a header was matched
    f.has_footer      = bool(entry.get("has_footer", False))
    f.size_bytes      = int(entry.get("size_bytes", 0))
    f.is_repaired     = bool(entry.get("repaired", False))
    f.media_magic_match = False

    # ── raw bytes signals ─────────────────────────────────────────────────────
    if raw_bytes:
        sample = raw_bytes[:4096]

        # Check binary media magic
        for magic in _MEDIA_MAGIC:
            if sample.startswith(magic):
                f.media_magic_match = True
                break

        # Printable-text ratio
        printable = sum(0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d) for b in sample)
        f.printable_ratio = printable / len(sample) if sample else 0.0

        # Entropy
        f.entropy = _shannon_entropy(sample)

        # Try to decode as text for pattern matching
        try:
            text = sample.decode("utf-8", errors="ignore")
        except Exception:
            text = ""

        f.text_sample    = text
        f.cred_hits      = len(_CRED_PATTERNS.findall(text))
        f.config_hits    = len(_CONFIG_PATTERNS.findall(text))
        f.log_ts_hits    = len(_LOG_TIMESTAMP_PATTERNS.findall(text))
        f.log_level_hits = len(_LOG_LEVEL_PATTERNS.findall(text))
        f.log_entry_hits = len(_LOG_ENTRY_PATTERNS.findall(text))

    return f


# ──────────────────────────────────────────────────────────────────────────────
# STAGE 2 — RULE MATCHING
# ──────────────────────────────────────────────────────────────────────────────
# Each rule is a callable (features) -> (partial_score: int, reason_token: str)
# returning (0, "") means the rule did not fire.

def _rule_ext_prior(f: _Features) -> tuple[int, str]:
    """Extension is a reliable category prior."""
    if f.ext_category:
        return 55, f"ext:{f.extension}"
    return 0, ""


def _rule_media_magic(f: _Features) -> tuple[int, str]:
    """Binary magic bytes directly confirm Media."""
    if f.media_magic_match:
        return 70, "binary-magic:media"
    return 0, ""


def _rule_cred_keywords(f: _Features) -> tuple[int, str]:
    """SSID / PASS / secret / key keywords → Credentials."""
    if f.cred_hits is None:
        return 0, ""
    if f.cred_hits >= 3:
        return 90, f"cred-keywords:{f.cred_hits}hits"   # decisive override vs config
    if f.cred_hits >= 1:
        return 55, f"cred-keywords:{f.cred_hits}hit"
    return 0, ""


def _rule_config_structure(f: _Features) -> tuple[int, str]:
    """JSON-like / INI / XML / key=value structure → Config."""
    if f.config_hits is None:
        return 0, ""
    if f.config_hits >= 4:
        return 68, f"config-pattern:{f.config_hits}hits"
    if f.config_hits >= 2:
        return 45, f"config-pattern:{f.config_hits}hits"
    return 0, ""


def _rule_log_timestamps(f: _Features) -> tuple[int, str]:
    """Multiple timestamps → Logs."""
    if f.log_ts_hits is None:
        return 0, ""
    if f.log_ts_hits >= 5:
        return 70, f"timestamps:{f.log_ts_hits}"
    if f.log_ts_hits >= 2:
        return 48, f"timestamps:{f.log_ts_hits}"
    return 0, ""


def _rule_log_levels(f: _Features) -> tuple[int, str]:
    """Log severity keywords (DEBUG / ERROR / etc.) → Logs."""
    if f.log_level_hits is None:
        return 0, ""
    if f.log_level_hits >= 3:
        return 60, f"log-levels:{f.log_level_hits}"
    if f.log_level_hits >= 1:
        return 35, f"log-levels:{f.log_level_hits}"
    return 0, ""


def _rule_log_entries(f: _Features) -> tuple[int, str]:
    """Stack traces / HTTP logs / syslog patterns → Logs."""
    if f.log_entry_hits is None:
        return 0, ""
    if f.log_entry_hits >= 2:
        return 55, f"log-entries:{f.log_entry_hits}"
    if f.log_entry_hits >= 1:
        return 30, "log-entry:1"
    return 0, ""


def _rule_high_entropy_binary(f: _Features) -> tuple[int, str]:
    """High entropy + low printable ratio → compressed/encrypted → Unknown or Media."""
    if f.entropy is None:
        return 0, ""
    if f.entropy > 7.5 and f.printable_ratio is not None and f.printable_ratio < 0.15:
        return 30, f"high-entropy:{f.entropy:.1f}"  # weak signal — might be archive/crypto
    return 0, ""


def _rule_mostly_text(f: _Features) -> tuple[int, str]:
    """Almost entirely printable text → likely Logs or Config (keeps options open)."""
    if f.printable_ratio is None:
        return 0, ""
    if f.printable_ratio > 0.92:
        return 20, "mostly-text"
    return 0, ""


# Rule registry: (rule_fn, target_category)
# "target_category = None" means the rule contributes to whatever is leading.
_RULES: list[tuple] = [
    (_rule_ext_prior,           None),               # directs to ext_category
    (_rule_media_magic,         CATEGORY_MEDIA),
    (_rule_cred_keywords,       CATEGORY_CREDENTIALS),
    (_rule_config_structure,    CATEGORY_CONFIG),
    (_rule_log_timestamps,      CATEGORY_LOGS),
    (_rule_log_levels,          CATEGORY_LOGS),
    (_rule_log_entries,         CATEGORY_LOGS),
    (_rule_high_entropy_binary, CATEGORY_UNKNOWN),
    (_rule_mostly_text,         None),
]


# ──────────────────────────────────────────────────────────────────────────────
# STAGE 3 — SCORING & AGGREGATION
# ──────────────────────────────────────────────────────────────────────────────

def _header_validity_bonus(f: _Features) -> int:
    """
    +0 to +15 based on header presence, footer presence, size sanity.
    Maps to the 'header validity' component of the confidence spec.
    """
    score = 0
    if f.has_header:
        score += 5
    if f.has_footer:
        score += 7
    if f.size_bytes and f.size_bytes > 64:
        score += 3
    return score


def _completeness_bonus(f: _Features) -> int:
    """
    +0 to +10 based on file completeness signals.
    Repaired files get a slight penalty.
    """
    if f.has_footer and not f.is_repaired:
        return 10
    if f.has_footer and f.is_repaired:
        return 5
    if f.carver_confidence >= 80:
        return 7
    if f.carver_confidence >= 60:
        return 4
    return 0


def _signature_strength_bonus(f: _Features) -> int:
    """
    +0 to +10 from carver engine's own confidence score.
    """
    c = f.carver_confidence
    if c >= 90:
        return 10
    if c >= 70:
        return 7
    if c >= 50:
        return 4
    return 0


def aggregate_scores(
    f: _Features,
    rule_results: list[tuple[str, int, str]],
) -> tuple[str, int, str]:
    """
    Stage 3: merge rule hits into a single (category, confidence, reason).

    Parameters
    ----------
    f : _Features
    rule_results : list of (category, partial_score, reason_token)

    Returns
    -------
    (category, confidence_0_100, reason_string)
    """
    # Accumulate partial scores per category
    cat_scores: dict[str, int] = {c: 0 for c in ALL_CATEGORIES}
    cat_reasons: dict[str, list[str]] = {c: [] for c in ALL_CATEGORIES}

    for cat, pscore, token in rule_results:
        if pscore == 0:
            continue
        cat_scores[cat] += pscore
        if token:
            cat_reasons[cat].append(token)

    # ── Special override: strong credential keywords beat the ext-category prior ──
    # When cred_hits is high enough, reduce Config's ext/structure contribution
    # so that "cfg with SSID+password inside" → Credentials, not Config.
    cred_score = cat_scores[CATEGORY_CREDENTIALS]
    config_score = cat_scores[CATEGORY_CONFIG]
    if (
        cred_score > 0
        and config_score > cred_score
        and f.cred_hits is not None
        and f.cred_hits >= 3
    ):
        # Remove the ext-category contribution from Config
        # (the ext prior added at most 55 pts; subtract it so content wins)
        ext_prior_contribution = 55 if f.ext_category == CATEGORY_CONFIG else 0
        cat_scores[CATEGORY_CONFIG] = max(0, config_score - ext_prior_contribution)

    # Pick the category with the highest accumulated score
    winner = max(cat_scores, key=cat_scores.__getitem__)
    raw_score = cat_scores[winner]

    if raw_score == 0:
        winner = CATEGORY_UNKNOWN
        raw_score = 10

    # Structural bonuses (header validity, completeness, signature match)
    bonus = (
        _header_validity_bonus(f)
        + _completeness_bonus(f)
        + _signature_strength_bonus(f)
    )

    # Final confidence: blend rule signal (70 %) + structural bonuses (30 %)
    # Cap partial score at 100 before blending
    raw_capped = min(raw_score, 100)
    confidence = int(raw_capped * 0.70 + bonus * 0.30 * (100 / 35))
    confidence = max(0, min(100, confidence))

    # Build reason string
    reason_parts = cat_reasons[winner][:4]  # top 4 tokens max
    if bonus >= 15:
        reason_parts.append("high structural validity")
    elif bonus >= 8:
        reason_parts.append("moderate structural validity")
    elif f.is_repaired:
        reason_parts.append("file was repaired")

    reason = "; ".join(reason_parts) if reason_parts else "no strong signal"

    return winner, confidence, reason


# ──────────────────────────────────────────────────────────────────────────────
# STAGE 4 — PIPELINE ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def classify(entry: dict, raw_bytes: Optional[bytes] = None) -> dict:
    """
    Run the full heuristic classification pipeline on a recovered file entry.

    Parameters
    ----------
    entry : dict
        A RecoveredObject dict as produced by file_carver.py or recovery_engine.py.
        Required keys (used when present):
          extension, confidence, has_footer, size_bytes, repaired
    raw_bytes : bytes | None
        Up to 4 KB of raw content from the recovered file.
        Omit for metadata-only classification (lower accuracy).

    Returns
    -------
    dict with keys:
        type       : str   — one of Logs / Credentials / Config / Media / Unknown
        confidence : int   — 0–100
        reason     : str   — human-readable explanation of the decision
    """
    try:
        # ── Stage 1: feature extraction ───────────────────────────────────────
        features = extract_features(entry, raw_bytes)

        # ── Stage 2: run all rules ────────────────────────────────────────────
        rule_results: list[tuple[str, int, str]] = []
        for rule_fn, target_cat in _RULES:
            pscore, token = rule_fn(features)
            # Resolve the actual category for this rule hit
            if target_cat is None:
                # ext_prior or mostly_text: use ext_category if available
                resolved = features.ext_category or CATEGORY_UNKNOWN
            else:
                resolved = target_cat
            rule_results.append((resolved, pscore, token))

        # ── Stage 3: aggregate ────────────────────────────────────────────────
        category, confidence, reason = aggregate_scores(features, rule_results)

        # ── Stage 4: emit result ──────────────────────────────────────────────
        return {
            "type":       category,
            "confidence": confidence,
            "reason":     reason,
        }

    except Exception as exc:                         # never crash the caller
        logger.exception("ai_classifier error: %s", exc)
        return {
            "type":       CATEGORY_UNKNOWN,
            "confidence": 0,
            "reason":     f"classifier error: {exc}",
        }


# ──────────────────────────────────────────────────────────────────────────────
# BATCH HELPER
# ──────────────────────────────────────────────────────────────────────────────

def classify_batch(
    entries: list[dict],
    bytes_loader=None,
) -> list[dict]:
    """
    Classify a list of RecoveredObject dicts.

    Parameters
    ----------
    entries : list[dict]
        RecoveredObject dicts.
    bytes_loader : callable | None
        Optional function (entry) -> bytes | None.
        Called for each entry to supply raw bytes for deep inspection.
        If None, every entry is classified from metadata only.

    Returns
    -------
    List of classification dicts in the same order as `entries`,
    each augmented with the original entry fields:
      { ...entry fields..., "ai_type", "ai_confidence", "ai_reason" }
    """
    results = []
    for entry in entries:
        raw = bytes_loader(entry) if bytes_loader else None
        cl = classify(entry, raw)
        results.append({
            **entry,
            "ai_type":       cl["type"],
            "ai_confidence": cl["confidence"],
            "ai_reason":     cl["reason"],
        })
    return results
