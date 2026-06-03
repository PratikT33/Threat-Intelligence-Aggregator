"""
reporter.py — Reporting Module
================================
Generates final threat intelligence reports:
  - Console summary (human-readable)
  - JSON report     (machine-readable, full detail)
  - CSV report      (spreadsheet-compatible, all IOCs)

Report contents:
  - Feed metadata
  - Total unique indicators
  - Breakdown by type and severity
  - Top high-priority repeated indicators
  - Full exportable IOC dataset
"""

import json
import csv
import os
from datetime import datetime, timezone
from collections import Counter

OUTPUT_DIR = os.path.join("output", "reports")
SEVERITY_RANK = {"High": 3, "Medium": 2, "Low": 1}


def _ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def _build_statistics(correlated):
    """Compute summary statistics from the correlated IOC dict."""
    type_counts = Counter(v["type"]     for v in correlated.values())
    sev_counts  = Counter(v["severity"] for v in correlated.values())
    cat_counts  = Counter(v["category"] for v in correlated.values())

    # Top 5 most-seen sources across all indicators
    source_counter = Counter()
    for v in correlated.values():
        for s in v["sources"]:
            source_counter[s] += 1

    return {
        "total_unique_iocs": len(correlated),
        "by_type":      dict(type_counts.most_common()),
        "by_severity":  dict(sev_counts),
        "by_category":  dict(cat_counts),
        "top_sources":  dict(source_counter.most_common(10)),
    }


def print_console_summary(correlated, feed_sources):
    """Print a formatted summary to stdout."""
    stats = _build_statistics(correlated)

    high_risk = sorted(
        [v for v in correlated.values() if v["severity"] == "High"],
        key=lambda x: x["source_count"],
        reverse=True
    )

    width = 62
    print("\n" + "=" * width)
    print("  THREAT INTELLIGENCE AGGREGATOR — REPORT SUMMARY")
    print("=" * width)
    print(f"  Generated  : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"  Feeds      : {len(feed_sources)}")
    for f in feed_sources:
        print(f"               - {f}")
    print("-" * width)
    print(f"  Total unique IOCs : {stats['total_unique_iocs']}")
    print(f"  High severity     : {stats['by_severity'].get('High',   0)}")
    print(f"  Medium severity   : {stats['by_severity'].get('Medium', 0)}")
    print(f"  Low severity      : {stats['by_severity'].get('Low',    0)}")
    print("-" * width)
    print("  IOC Type Breakdown:")
    for ioc_type, count in stats["by_type"].items():
        bar = "#" * min(count, 30)
        print(f"    {ioc_type:<12}: {count:>5}  {bar}")
    print("-" * width)
    if high_risk:
        print(f"  Top High-Risk Indicators (showing up to 15):")
        for item in high_risk[:15]:
            val = item["value"][:45].ljust(46)
            print(f"    [{item['type']:<6}] {val} feeds={item['source_count']}")
    else:
        print("  No High-severity indicators found.")
    print("=" * width + "\n")


def generate_json_report(correlated, feed_sources, timestamp):
    """Write a structured JSON threat intelligence report."""
    stats     = _build_statistics(correlated)
    high_risk = sorted(
        [v for v in correlated.values() if v["severity"] == "High"],
        key=lambda x: x["source_count"],
        reverse=True
    )

    report = {
        "report_metadata": {
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "report_version":  "1.0",
            "tool":            "TI Aggregator v1.0",
            "feeds_processed": feed_sources,
        },
        "statistics": stats,
        "high_risk_indicators": high_risk[:50],
        "all_indicators": sorted(
            list(correlated.values()),
            key=lambda x: (-SEVERITY_RANK[x["severity"]], x["value"])
        ),
    }

    path = os.path.join(OUTPUT_DIR, f"ti_report_{timestamp}.json")
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    print(f"[+] JSON report saved  : {path}")
    return path


def generate_csv_report(correlated, timestamp):
    """Write a flat CSV file of all correlated IOCs."""
    fieldnames = [
        "value", "type", "category", "severity",
        "source_count", "sources", "timestamp"
    ]
    path = os.path.join(OUTPUT_DIR, f"ti_report_{timestamp}.csv")

    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in sorted(
            correlated.values(),
            key=lambda x: (-SEVERITY_RANK[x["severity"]], x["value"])
        ):
            writer.writerow({
                "value":        item["value"],
                "type":         item["type"],
                "category":     item["category"],
                "severity":     item["severity"],
                "source_count": item["source_count"],
                "sources":      "|".join(item["sources"]),
                "timestamp":    item["timestamp"],
            })

    print(f"[+] CSV report saved   : {path}")
    return path


def generate_report(correlated, normalized_iocs, feed_sources):
    """
    Master reporting function — runs all three report outputs.

    Args:
        correlated:      dict from correlator.correlate()
        normalized_iocs: list from normalizer.normalize_all()
        feed_sources:    list of feed name strings

    Returns:
        dict with paths to generated report files
    """
    _ensure_output_dir()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    print_console_summary(correlated, feed_sources)

    json_path = generate_json_report(correlated, feed_sources, timestamp)
    csv_path  = generate_csv_report(correlated, timestamp)

    return {
        "json_report": json_path,
        "csv_report":  csv_path,
        "timestamp":   timestamp,
    }
