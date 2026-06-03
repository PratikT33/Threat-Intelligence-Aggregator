"""
blocklist_generator.py — Blocklist Generator
=============================================
Generates category-based blocklists from correlated IOC data.
Supports export in TXT, CSV, and JSON formats.
Targets:
  - Firewalls       -> IP blocklist
  - Web filters     -> Domain + URL blocklist
  - EDR / AV tools  -> Hash blocklist (MD5, SHA1, SHA256)
"""

import json
import csv
import os
from datetime import datetime, timezone

# Output directory for blocklists
OUTPUT_DIR = os.path.join("output", "blocklists")

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3}

# Map IOC types to blocklist bucket names
TYPE_TO_BUCKET = {
    "ip":     "ip",
    "domain": "domain",
    "url":    "url",
    "md5":    "hash",
    "sha1":   "hash",
    "sha256": "hash",
    "email":  "email",
}


def _ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def _filter_by_severity(correlated, min_severity):
    """Return only indicators at or above the minimum severity threshold."""
    min_rank = SEVERITY_RANK.get(min_severity, 1)
    return [v for v in correlated.values()
            if SEVERITY_RANK.get(v["severity"], 0) >= min_rank]


def _write_txt(filepath, items):
    """Write plain-text blocklist — one value per line. Firewall-ready."""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"# TI Aggregator Blocklist\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"# Total entries: {len(items)}\n")
        f.write("#\n")
        for item in sorted(items, key=lambda x: x["value"]):
            f.write(item["value"] + "\n")


def _write_csv(filepath, items):
    """Write CSV blocklist with full metadata for analyst review."""
    fieldnames = ["value", "type", "severity", "source_count", "sources", "category", "timestamp"]
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in sorted(items, key=lambda x: (-SEVERITY_RANK[x["severity"]], x["value"])):
            writer.writerow({
                "value":        item["value"],
                "type":         item["type"],
                "severity":     item["severity"],
                "source_count": item["source_count"],
                "sources":      "|".join(item["sources"]),
                "category":     item["category"],
                "timestamp":    item["timestamp"],
            })


def _write_json(filepath, items, bucket_name):
    """Write JSON blocklist for SIEM / SOAR / API consumption."""
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "blocklist_type": bucket_name,
        "total_entries": len(items),
        "indicators": sorted(items, key=lambda x: (-SEVERITY_RANK[x["severity"]], x["value"])),
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)


def generate_blocklists(correlated, min_severity="Low"):
    """
    Generate blocklists for all IOC categories.

    For each bucket (ip, domain, url, hash, email) writes three files:
        <bucket>_blocklist.txt   — plain text, firewall/DNS sinkhole ready
        <bucket>_blocklist.csv   — with metadata, for analyst use
        <bucket>_blocklist.json  — structured, for SIEM/SOAR ingestion

    Args:
        correlated:   dict from correlator.correlate()
        min_severity: "Low" | "Medium" | "High" — minimum severity to include

    Returns:
        dict { bucket_name: [list of items] }
    """
    _ensure_output_dir()

    # Filter by severity
    entries = _filter_by_severity(correlated, min_severity)
    print(f"[+] Blocklist generation (min severity: {min_severity})")
    print(f"    -> {len(entries)} indicators qualify")

    # Bucket by type
    buckets = {
        "ip":     [],
        "domain": [],
        "url":    [],
        "hash":   [],
        "email":  [],
    }
    for entry in entries:
        bucket = TYPE_TO_BUCKET.get(entry["type"])
        if bucket:
            buckets[bucket].append(entry)

    # Write files per bucket
    for bucket_name, items in buckets.items():
        if not items:
            print(f"    -> {bucket_name:<10}: 0 entries (skipped)")
            continue

        base = os.path.join(OUTPUT_DIR, f"{bucket_name}_blocklist")
        _write_txt( f"{base}.txt",  items)
        _write_csv( f"{base}.csv",  items)
        _write_json(f"{base}.json", items, bucket_name)

        print(f"    -> {bucket_name:<10}: {len(items)} entries -> "
              f"{base}.{{txt,csv,json}}")

    return buckets


def generate_firewall_ipset(correlated, min_severity="Medium", output_path=None):
    """
    Generate an ipset-compatible IP blocklist for Linux iptables / nftables.
    Format: plain IPs, one per line, suitable for `ipset restore`.

    Args:
        correlated:   dict from correlator.correlate()
        min_severity: minimum severity threshold
        output_path:  override default output path
    """
    _ensure_output_dir()
    entries = _filter_by_severity(correlated, min_severity)
    ips = [e["value"] for e in entries if e["type"] == "ip"]

    if not output_path:
        output_path = os.path.join(OUTPUT_DIR, "firewall_ipset.txt")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# ipset-compatible IP blocklist\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"# Entries: {len(ips)}\n")
        f.write("# Usage: ipset restore < firewall_ipset.txt\n#\n")
        f.write("create ti_block hash:ip\n")
        for ip in sorted(ips):
            f.write(f"add ti_block {ip}\n")

    print(f"[+] ipset blocklist written: {output_path} ({len(ips)} IPs)")
    return output_path
