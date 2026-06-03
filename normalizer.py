"""
normalizer.py — Normalization Engine
======================================
Converts all raw IOC dicts into a unified, consistent schema.
Adds metadata: source, timestamp, category.
Removes duplicate (value, source) pairs.
"""

from datetime import datetime, timezone

# Allowed IOC types — anything else is discarded
VALID_TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256", "email"}

# Map IOC types to high-level categories
CATEGORY_MAP = {
    "ip":     "network",
    "domain": "network",
    "url":    "network",
    "md5":    "file",
    "sha1":   "file",
    "sha256": "file",
    "email":  "identity",
}


def normalize_ioc(raw_ioc):
    """
    Convert a single raw IOC dict into a normalized record.

    Input:
        { "type": "ip", "value": "1.2.3.4", "source": "FeedName" }

    Output schema:
        {
            "value":     str   — the indicator value
            "type":      str   — ip | domain | url | md5 | sha1 | sha256 | email
            "category":  str   — network | file | identity
            "source":    str   — originating feed name
            "timestamp": str   — ISO 8601 UTC ingestion time
            "severity":  str   — Low (default; updated by correlator)
        }

    Returns None if the IOC is invalid or unsupported.
    """
    ioc_type = raw_ioc.get("type", "").lower().strip()
    if ioc_type not in VALID_TYPES:
        return None

    value = raw_ioc.get("value", "").strip()
    if not value or len(value) < 4:
        return None

    return {
        "value":     value,
        "type":      ioc_type,
        "category":  CATEGORY_MAP.get(ioc_type, "unknown"),
        "source":    raw_ioc.get("source", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity":  "Low",
    }


def normalize_all(raw_iocs):
    """
    Normalize a list of raw IOC dicts.

    Deduplication strategy:
        - (value, source) pairs are unique — the same indicator from
          the same feed is counted once.
        - The same indicator from DIFFERENT feeds is kept separately
          so the correlator can count cross-feed occurrences.

    Args:
        raw_iocs: list of raw dicts from feed_parser

    Returns:
        list of normalized IOC dicts
    """
    seen      = set()
    normalized = []
    skipped    = 0

    for raw in raw_iocs:
        norm = normalize_ioc(raw)
        if norm is None:
            skipped += 1
            continue

        key = (norm["value"], norm["source"])
        if key in seen:
            continue

        seen.add(key)
        normalized.append(norm)

    print(f"[+] Normalization complete:")
    print(f"    -> {len(raw_iocs):>6} raw entries received")
    print(f"    -> {skipped:>6} entries discarded (invalid/unsupported)")
    print(f"    -> {len(normalized):>6} unique (value, source) records produced")

    return normalized


def get_type_summary(normalized_iocs):
    """
    Return a dict of { ioc_type: count } for a list of normalized IOCs.
    Useful for progress reporting.
    """
    summary = {}
    for ioc in normalized_iocs:
        t = ioc["type"]
        summary[t] = summary.get(t, 0) + 1
    return summary
