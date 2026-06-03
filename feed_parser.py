"""
feed_parser.py — IOC Feed Parser
=================================
Accepts multiple feed formats (CSV, TXT, JSON, STIX, URL).
Extracts IPs, URLs, domains, hashes, and email indicators.
Removes duplicates and invalid entries.
"""

import re
import json
import csv
import requests
import ipaddress
import os

# ── Compiled Regex Patterns ────────────────────────────────────────────────────
IP_PATTERN     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
URL_PATTERN    = re.compile(r'https?://[^\s\'"<>,]+')
MD5_PATTERN    = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN   = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
EMAIL_PATTERN  = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')


def validate_ip(ip_str):
    """
    Returns True only for routable public IPv4 addresses.
    Filters out private, loopback, link-local, and reserved ranges.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or
                    ip.is_reserved or ip.is_link_local or
                    ip.is_multicast)
    except ValueError:
        return False


def extract_iocs(text, source_name):
    """
    Run all regex patterns against raw text and return a list of
    raw IOC dicts: { type, value, source }.

    Extraction order matters:
      1. URLs first (contain domains — extract before domain pass)
      2. SHA256 before SHA1 before MD5 (longer patterns first)
      3. IPs before domains (avoid IP octets matching domain regex)
    """
    iocs = []
    seen_values = set()

    def add(ioc_type, value):
        key = (ioc_type, value)
        if key not in seen_values:
            seen_values.add(key)
            iocs.append({"type": ioc_type, "value": value, "source": source_name})

    # URLs
    for url in URL_PATTERN.findall(text):
        add("url", url.strip().rstrip(".,;)\"'"))

    # Hashes (longest first to avoid partial matches)
    for h in SHA256_PATTERN.findall(text):
        add("sha256", h.lower())
    for h in SHA1_PATTERN.findall(text):
        add("sha1", h.lower())
    for h in MD5_PATTERN.findall(text):
        add("md5", h.lower())

    # IPs
    for ip in IP_PATTERN.findall(text):
        if validate_ip(ip):
            add("ip", ip)

    # Emails (before domains so user@domain isn't split)
    for email in EMAIL_PATTERN.findall(text):
        add("email", email.lower())

    # Domains (exclude things already matched as IPs)
    for domain in DOMAIN_PATTERN.findall(text):
        if not IP_PATTERN.fullmatch(domain):
            add("domain", domain.lower())

    return iocs


# ── Format-specific parsers ────────────────────────────────────────────────────

def parse_txt(filepath, source_name):
    """Parse a plain-text file — one indicator per line or inline."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return extract_iocs(f.read(), source_name)


def parse_csv(filepath, source_name):
    """
    Parse a CSV feed. Scans ALL column values in every row so
    the parser is schema-agnostic (no fixed column names needed).
    """
    iocs = []
    with open(filepath, newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_text = ' '.join(str(v) for v in row.values())
            iocs.extend(extract_iocs(row_text, source_name))
    return iocs


def parse_json(filepath, source_name):
    """
    Parse a JSON feed. Serialises the entire document back to a string
    so regex extraction works regardless of nesting depth or key names.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return extract_iocs(json.dumps(data), source_name)


def parse_stix(filepath, source_name):
    """
    Basic STIX 2.x JSON bundle parser.
    Targets 'indicator' objects and extracts IOCs from their pattern fields.
    """
    iocs = []
    with open(filepath, 'r', encoding='utf-8') as f:
        bundle = json.load(f)
    for obj in bundle.get("objects", []):
        if obj.get("type") == "indicator":
            pattern = obj.get("pattern", "")
            name    = obj.get("name", "")
            iocs.extend(extract_iocs(pattern + " " + name, source_name))
    return iocs


def fetch_url_feed(url, source_name, timeout=15):
    """
    Download a remote threat feed over HTTP/HTTPS and parse
    the response body as plain text.
    """
    try:
        headers = {"User-Agent": "TI-Aggregator/1.0"}
        resp = requests.get(url, timeout=timeout, headers=headers)
        resp.raise_for_status()
        return extract_iocs(resp.text, source_name)
    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to fetch feed '{source_name}' from {url}: {e}")
        return []


def load_feed(source):
    """
    Dispatcher: load a single feed based on its configuration dict.

    Expected format:
        {
            "name": "AbuseIPDB",
            "type": "csv" | "txt" | "json" | "stix" | "url",
            "path": "/path/to/file"   OR   "https://example.com/feed"
        }
    """
    name     = source.get("name", "unknown")
    src_type = source.get("type", "").lower()
    path     = source.get("path", "")

    print(f"[+] Loading feed: {name} ({src_type.upper()})")

    try:
        if src_type == "url":
            return fetch_url_feed(path, name)
        elif src_type == "csv":
            return parse_csv(path, name)
        elif src_type == "txt":
            return parse_txt(path, name)
        elif src_type == "json":
            return parse_json(path, name)
        elif src_type == "stix":
            return parse_stix(path, name)
        else:
            print(f"[!] Unsupported feed type: '{src_type}' for feed '{name}'")
            return []
    except FileNotFoundError:
        print(f"[!] File not found for feed '{name}': {path}")
        return []
    except Exception as e:
        print(f"[!] Unexpected error loading feed '{name}': {e}")
        return []


def load_all_feeds(feed_configs):
    """
    Load and aggregate raw IOCs from all configured feeds.

    Args:
        feed_configs: list of feed configuration dicts

    Returns:
        list of raw IOC dicts
    """
    all_raw = []
    for feed in feed_configs:
        raw = load_feed(feed)
        count = len(raw)
        print(f"    -> {count} raw IOC(s) extracted from '{feed['name']}'")
        all_raw.extend(raw)
    return all_raw
