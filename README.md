# Threat Intelligence Aggregator

A Python-based security automation toolkit that collects, parses, normalizes,
and correlates Indicators of Compromise (IOCs) from multiple threat feeds —
without AI or machine learning.

---

## Project Structure

```
ti_aggregator/
├── main.py                    # Pipeline orchestrator — run this
├── feed_parser.py             # IOC extraction from all feed formats
├── normalizer.py              # Schema normalization & deduplication
├── correlator.py              # Cross-feed correlation & severity rating
├── blocklist_generator.py     # Blocklist export (TXT / CSV / JSON)
├── reporter.py                # Threat report generation
├── requirements.txt           # Python dependencies
├── sample_feeds/
│   ├── feed1.csv              # Sample CSV feed
│   ├── feed2.json             # Sample JSON feed
│   ├── feed3.txt              # Sample plain-text feed
│   └── feed4_stix.json        # Sample STIX 2.x bundle
└── output/
    ├── blocklists/            # Generated blocklist files
    └── reports/               # Generated threat reports
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the pipeline
```bash
python main.py
```

### 3. Check output
```
output/
├── blocklists/
│   ├── ip_blocklist.txt          <- paste into firewall
│   ├── ip_blocklist.csv
│   ├── ip_blocklist.json
│   ├── domain_blocklist.txt      <- paste into DNS sinkhole
│   ├── url_blocklist.txt         <- import into web filter
│   ├── hash_blocklist.txt        <- import into EDR / AV
│   ├── email_blocklist.txt
│   └── firewall_ipset.txt        <- Linux ipset / iptables
└── reports/
    ├── ti_report_YYYYMMDD_HHMMSS.json
    └── ti_report_YYYYMMDD_HHMMSS.csv
```

---

## Adding Feeds

Edit the `FEEDS` list in `main.py`:

```python
FEEDS = [
    # Local CSV file
    {"name": "AbuseIPDB_Export", "type": "csv",  "path": "feeds/abuseipdb.csv"},

    # Local JSON file
    {"name": "Custom_Feed",      "type": "json", "path": "feeds/custom.json"},

    # Plain text file
    {"name": "Internal_IOCs",    "type": "txt",  "path": "feeds/internal.txt"},

    # STIX 2.x bundle
    {"name": "MISP_Feed",        "type": "stix", "path": "feeds/misp_bundle.json"},

    # Remote URL (fetched at runtime)
    {"name": "URLhaus",          "type": "url",
     "path": "https://urlhaus.abuse.ch/downloads/text/"},
]
```

---

## Supported IOC Types

| Type    | Category | Example                                                          |
|---------|----------|------------------------------------------------------------------|
| ip      | network  | 185.220.101.45                                                   |
| domain  | network  | malware.example.com                                              |
| url     | network  | https://evil.ru/payload.exe                                      |
| md5     | file     | 44d88612fea8a8f36de82e1278abb02f                                 |
| sha1    | file     | da39a3ee5e6b4b0d3255bfef95601890afd80709                         |
| sha256  | file     | aabbccdd...11223344 (64 hex chars)                               |
| email   | identity | phish@attacker-domain.xyz                                        |

---

## Severity Ratings

| Severity | Condition                      | Recommended Action                         |
|----------|--------------------------------|--------------------------------------------|
| High     | Seen in 3+ independent feeds   | Immediate blocking + SOC escalation        |
| Medium   | Seen in 2 feeds                | Blocklist + analyst review                 |
| Low      | Seen in 1 feed                 | Monitor / log only                         |

---

## Supported Feed Formats

| Format | Description                                              |
|--------|----------------------------------------------------------|
| TXT    | Plain text, one indicator per line                       |
| CSV    | Columnar; all columns scanned (schema-agnostic)          |
| JSON   | Any JSON structure; full document is searched            |
| STIX   | STIX 2.x bundles; indicator pattern fields are parsed    |
| URL    | Any remote HTTP/HTTPS feed returning text                |

---

## Pipeline Architecture

```
[Feed Files / URLs]
       |
       v
  feed_parser.py        <- Load + extract IOCs (regex)
       |
       v
  normalizer.py         <- Validate, deduplicate, add metadata
       |
       v
  correlator.py         <- Cross-feed grouping + severity rating
       |
       +---------> blocklist_generator.py  -> output/blocklists/
       |
       +---------> reporter.py             -> output/reports/
```

---

## Libraries Used

All standard library except `requests`:

- `re` — IOC extraction via compiled regex patterns
- `json` / `csv` — Feed parsing and structured output
- `requests` — Remote feed fetching
- `ipaddress` — IPv4 validation (filters private/reserved ranges)
- `collections` — Counter and defaultdict for correlation
- `datetime` — ISO 8601 UTC timestamping
- `os` / `sys` — File I/O and path management

---

## Example Console Output

```
==============================================================
  THREAT INTELLIGENCE AGGREGATOR — REPORT SUMMARY
==============================================================
  Generated  : 2026-05-27 10:30:00 UTC
  Feeds      : 4
               - SampleFeed_CSV
               - SampleFeed_JSON
               - SampleFeed_TXT
               - SampleFeed_STIX
--------------------------------------------------------------
  Total unique IOCs : 47
  High severity     : 8
  Medium severity   : 14
  Low severity      : 25
--------------------------------------------------------------
  IOC Type Breakdown:
    ip          :    12  ############
    domain      :     9  #########
    url         :     8  ########
    sha256      :     6  ######
    md5         :     4  ####
    sha1        :     3  ###
    email       :     5  #####
--------------------------------------------------------------
  Top High-Risk Indicators (showing up to 15):
    [ip    ] 185.220.101.45                                feeds=4
    [domain] malware.example.com                          feeds=4
    [sha256] aabbccdd11223344...                          feeds=3
    [ip    ] 91.108.4.0                                   feeds=3
==============================================================
```
