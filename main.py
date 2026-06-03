"""
main.py — TI Aggregator Entry Point
=====================================
Orchestrates the full threat intelligence pipeline:

  STEP 1: Load Feeds          -> feed_parser.py
  STEP 2: Extract IOCs        -> feed_parser.py
  STEP 3: Normalize Data      -> normalizer.py
  STEP 4: Correlate Feeds     -> correlator.py
  STEP 5: Generate Blocklists -> blocklist_generator.py
  STEP 6: Export Reports      -> reporter.py

Configure feeds in the FEEDS list below.
Run with: python main.py
"""

import os
import sys

from feed_parser         import load_all_feeds
from normalizer          import normalize_all
from correlator          import correlate
from blocklist_generator import generate_blocklists, generate_firewall_ipset
from reporter            import generate_report


# ═══════════════════════════════════════════════════════════════════════════════
#  FEED CONFIGURATION
#  Add, remove, or comment out feeds as needed.
#
#  Each entry must have:
#    "name"  — human-readable label (used in reports and correlation)
#    "type"  — "csv" | "txt" | "json" | "stix" | "url"
#    "path"  — file path (for local feeds) or full URL (for remote feeds)
# ═══════════════════════════════════════════════════════════════════════════════

FEEDS = [
    # ── Local sample feeds (included in project) ─────────────────────────────
    {
        "name": "SampleFeed_CSV",
        "type": "csv",
        "path": os.path.join("sample_feeds", "feed1.csv"),
    },
    {
        "name": "SampleFeed_JSON",
        "type": "json",
        "path": os.path.join("sample_feeds", "feed2.json"),
    },
    {
        "name": "SampleFeed_TXT",
        "type": "txt",
        "path": os.path.join("sample_feeds", "feed3.txt"),
    },
    {
        "name": "SampleFeed_STIX",
        "type": "stix",
        "path": os.path.join("sample_feeds", "feed4_stix.json"),
    },

    # ── Live OSINT feeds (uncomment to enable) ────────────────────────────────
    # URLhaus malicious URL database (plain text)
    # {
    #     "name": "URLhaus",
    #     "type": "url",
    #     "path": "https://urlhaus.abuse.ch/downloads/text/",
    # },

    # Feodo Tracker C2 IP blocklist
    # {
    #     "name": "FeodoTracker_IPs",
    #     "type": "url",
    #     "path": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    # },

    # Emerging Threats compromised IPs
    # {
    #     "name": "EmergingThreats_IPs",
    #     "type": "url",
    #     "path": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    # },

    # MISP OSINT feed (requires TAXII or JSON feed URL)
    # {
    #     "name": "MISP_OSINT",
    #     "type": "json",
    #     "path": "https://your-misp-instance/feeds/...",
    # },
]


# ═══════════════════════════════════════════════════════════════════════════════
#  PIPELINE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Minimum severity for blocklist inclusion: "Low" | "Medium" | "High"
BLOCKLIST_MIN_SEVERITY = "Low"

# Minimum severity for firewall ipset: recommended "Medium" or "High"
IPSET_MIN_SEVERITY = "Medium"


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print("\n" + "=" * 62)
    print("  THREAT INTELLIGENCE AGGREGATOR v1.0")
    print("  Blue Team | IOC Collection, Correlation & Blocklisting")
    print("=" * 62 + "\n")

    if not FEEDS:
        print("[!] No feeds configured. Add feeds to the FEEDS list in main.py")
        sys.exit(1)

    # ── STEP 1 & 2: Load feeds and extract IOCs ──────────────────────────────
    print("[*] STEP 1-2: Loading feeds and extracting IOCs...")
    all_raw = load_all_feeds(FEEDS)
    print(f"\n[*] Total raw IOCs collected: {len(all_raw)}\n")

    if not all_raw:
        print("[!] No IOCs extracted. Check feed paths and formats.")
        sys.exit(1)

    # ── STEP 3: Normalize ────────────────────────────────────────────────────
    print("[*] STEP 3: Normalizing indicators...")
    normalized = normalize_all(all_raw)
    print()

    # ── STEP 4: Correlate ────────────────────────────────────────────────────
    print("[*] STEP 4: Correlating indicators across feeds...")
    correlated, normalized = correlate(normalized)
    print()

    # ── STEP 5: Generate blocklists ──────────────────────────────────────────
    print("[*] STEP 5: Generating blocklists...")
    generate_blocklists(correlated, min_severity=BLOCKLIST_MIN_SEVERITY)
    generate_firewall_ipset(correlated, min_severity=IPSET_MIN_SEVERITY)
    print()

    # ── STEP 6: Generate report ──────────────────────────────────────────────
    print("[*] STEP 6: Generating threat intelligence report...")
    feed_names = [f["name"] for f in FEEDS]
    report_paths = generate_report(correlated, normalized, feed_names)

    # ── Done ─────────────────────────────────────────────────────────────────
    print("[*] Pipeline complete. Output files:")
    print(f"    Blocklists  -> output/blocklists/")
    print(f"    JSON report -> {report_paths['json_report']}")
    print(f"    CSV report  -> {report_paths['csv_report']}")
    print()


if __name__ == "__main__":
    main()
