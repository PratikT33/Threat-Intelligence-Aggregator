"""
correlator.py — IOC Correlation Engine
========================================
Identifies indicators appearing across multiple feeds.
Assigns severity ratings based on cross-feed frequency.
Prioritizes repeated indicators as high-risk.
"""

from collections import defaultdict

# ── Severity thresholds (number of unique sources) ─────────────────────────────
SEVERITY_THRESHOLDS = {
    "High":   3,   # Seen in 3 or more independent feeds -> highest confidence
    "Medium": 2,   # Seen in 2 feeds -> elevated confidence
    "Low":    1,   # Seen in only 1 feed -> lowest confidence
}


def assign_severity(source_count):
    """
    Map a source count to a severity label.

    Args:
        source_count: number of unique feeds containing the indicator

    Returns:
        "High" | "Medium" | "Low"
    """
    if source_count >= SEVERITY_THRESHOLDS["High"]:
        return "High"
    elif source_count >= SEVERITY_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"


def correlate(normalized_iocs):
    """
    Group indicators by value and count unique source feeds.
    Assign a severity rating proportional to cross-feed frequency.
    Propagate severity back to individual IOC records.

    Algorithm:
        1. Build source_map: { indicator_value -> set(source_names) }
        2. Build meta_map:   { indicator_value -> first-seen metadata }
        3. For each indicator: count sources, assign severity
        4. Update severity on every individual normalized record

    Args:
        normalized_iocs: list of dicts from normalizer.normalize_all()

    Returns:
        correlated  (dict)  { value -> correlated_record }
        normalized_iocs     same list with severity field updated in-place
    """
    # Step 1: aggregate sources per indicator value
    source_map = defaultdict(set)
    meta_map   = {}

    for ioc in normalized_iocs:
        v = ioc["value"]
        source_map[v].add(ioc["source"])

        # Store first-seen metadata for this indicator value
        if v not in meta_map:
            meta_map[v] = {
                "value":     v,
                "type":      ioc["type"],
                "category":  ioc["category"],
                "timestamp": ioc["timestamp"],
            }

    # Step 2: build correlated output
    correlated = {}
    for value, sources in source_map.items():
        count    = len(sources)
        severity = assign_severity(count)

        correlated[value] = {
            **meta_map[value],
            "sources":      sorted(list(sources)),
            "source_count": count,
            "severity":     severity,
        }

    # Step 3: propagate severity back to individual records
    for ioc in normalized_iocs:
        ioc["severity"] = correlated[ioc["value"]]["severity"]

    # Step 4: print summary
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for v in correlated.values():
        counts[v["severity"]] += 1

    print(f"[+] Correlation complete:")
    print(f"    -> {len(correlated):>6} unique indicators identified")
    print(f"    -> {counts['High']:>6} High severity  (seen in 3+ feeds)")
    print(f"    -> {counts['Medium']:>6} Medium severity (seen in 2 feeds)")
    print(f"    -> {counts['Low']:>6} Low severity    (seen in 1 feed)")

    return correlated, normalized_iocs


def get_high_risk(correlated, top_n=20):
    """
    Return the top N high-severity indicators sorted by source_count descending.

    Args:
        correlated: dict from correlate()
        top_n: maximum number of results to return

    Returns:
        list of correlated record dicts
    """
    high = [v for v in correlated.values() if v["severity"] == "High"]
    high.sort(key=lambda x: x["source_count"], reverse=True)
    return high[:top_n]


def get_by_type(correlated, ioc_type):
    """
    Filter correlated indicators by IOC type.

    Args:
        correlated: dict from correlate()
        ioc_type:   "ip" | "domain" | "url" | "md5" | "sha1" | "sha256" | "email"

    Returns:
        list of matching correlated records
    """
    return [v for v in correlated.values() if v["type"] == ioc_type]


def get_by_severity(correlated, severity):
    """
    Filter correlated indicators by severity level.

    Args:
        correlated: dict from correlate()
        severity:   "High" | "Medium" | "Low"

    Returns:
        list of matching correlated records
    """
    return [v for v in correlated.values() if v["severity"] == severity]
