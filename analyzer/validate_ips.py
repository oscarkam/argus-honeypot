#!/usr/bin/env python3
"""
ARGUS three-feed IP validator.

Cross-references the top-N attacker source IPs from the T-Pot capture
against three complementary threat intelligence feeds:

    - AbuseIPDB      (community abuse reports, confidence percentage)
    - VirusTotal     (multi-vendor security-product classification)
    - GreyNoise CE   (internet-scan telemetry classification)

Reads IPs from a live Elasticsearch query (via es_client.TpotEsClient).
Writes one CSV row per IP to analyzer/validation_ips.csv.

API keys are read from environment variables. Never commit keys to git.

    export ABUSEIPDB_API_KEY="..."
    export VIRUSTOTAL_API_KEY="..."
    export GREYNOISE_API_KEY="..."

Usage:

    # Verify environment set up without making API calls
    python validate_ips.py --dry-run

    # Validate top 50 IPs from the last 7 days of ES data (default)
    python validate_ips.py --live

    # Validate top 100 IPs from the last 30 days
    python validate_ips.py --live --top-n 100 --hours 720

Rate-limiting is respected. VirusTotal free tier is the tightest bound
at 4 requests per minute, so a 15-second sleep between IPs keeps all
three feeds within their limits.

For 50 IPs, expected wall-clock time is approximately 13 minutes.

Exit codes:
    0   success
    1   missing API keys, no IPs, or Elasticsearch unreachable
    2   argument parse error (handled by argparse)
"""
# NETWORK: external HTTPS calls to AbuseIPDB, VirusTotal, GreyNoise APIs
# BLAST RADIUS: local CSV append; read-only ES query; no writes to any external service

from __future__ import annotations

import argparse
import csv
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo

import requests


# API endpoints
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"

# Rate-limit floor: VirusTotal free tier is 4 requests per minute.
# 15 seconds between iterations keeps all three feeds within their bounds.
_SLEEP_SECONDS_BETWEEN_IPS = 15

# Thresholds used by the summary output. Reported as exact counts, not
# ranges. Every claim in the printed summary and in the downstream
# report footer is an exact integer against one of these thresholds.
_ABUSEIPDB_HIGH_THRESHOLD = 80         # high confidence
_ABUSEIPDB_MEDIUM_THRESHOLD = 50       # medium confidence (report legacy threshold)
_ABUSEIPDB_MALICIOUS_THRESHOLD = _ABUSEIPDB_MEDIUM_THRESHOLD  # backward compat
_VIRUSTOTAL_MALICIOUS_THRESHOLD = 1    # 1 or more vendor detections

_VALIDATION_CSV_PATH = Path(__file__).parent / "validation_ips.csv"
_STRATIFIED_CSV_PATH = Path(__file__).parent / "validation_ips_stratified.csv"
_TIMEZONE = ZoneInfo("Asia/Kuala_Lumpur")

# ------------------------------------------------------------------ exclusions
# Addresses that do not represent external adversary activity and are
# therefore removed from the sample frame before any sampling occurs.
#
#   RFC 1918 private ranges   — internal VPC traffic, including the sensor
#                               host itself and the cloud resolver service
#   RFC 3927 link-local range — cloud platform services, including the
#                               instance metadata endpoint and time sync
#   Operator source address   — authorised administrative access
#
# The rule is declared here rather than applied ad hoc so that the filtered
# population can be reconstructed exactly by anyone repeating the study.
_EXCLUDED_PREFIXES = (
    "10.",          # RFC 1918
    "192.168.",     # RFC 1918
    "169.254.",     # RFC 3927 link-local
    "127.",         # loopback
)
_EXCLUDED_RFC1918_172 = tuple(f"172.{n}." for n in range(16, 32))  # RFC 1918 172.16/12

# Operator administrative source address. Override at runtime with
# --operator-ip if it changes; never hard-code additional operator hosts.
_DEFAULT_OPERATOR_IP = os.getenv("ARGUS_OPERATOR_IP", "")


def is_excluded_address(ip: str, operator_ip: str = _DEFAULT_OPERATOR_IP) -> bool:
    """Return True if the address is infrastructure rather than an external source.

    Applied to the population before sampling. See the exclusion rationale
    documented alongside _EXCLUDED_PREFIXES above.
    """
    if not ip:
        return True
    if operator_ip and ip == operator_ip:
        return True
    if ip.startswith(_EXCLUDED_PREFIXES):
        return True
    if ip.startswith(_EXCLUDED_RFC1918_172):
        return True
    return False


def classify_exclusion(ip: str, operator_ip: str = _DEFAULT_OPERATOR_IP) -> str:
    """Return a human-readable reason for exclusion, or empty string if included."""
    if operator_ip and ip == operator_ip:
        return "operator administrative source"
    if ip.startswith("169.254."):
        return "RFC 3927 link-local (cloud platform service)"
    if ip.startswith(("10.", "192.168.")) or ip.startswith(_EXCLUDED_RFC1918_172):
        return "RFC 1918 private (internal VPC traffic)"
    if ip.startswith("127."):
        return "loopback"
    return ""


_FIELDNAMES = [
    "timestamp",
    "ip",
    "session_count_in_capture",
    "country_captured",
    # AbuseIPDB
    "abuseipdb_confidence",
    "abuseipdb_reports",
    "abuseipdb_country",
    "abuseipdb_error",
    # VirusTotal
    "vt_malicious",
    "vt_suspicious",
    "vt_harmless",
    "vt_undetected",
    "vt_error",
    # GreyNoise Community
    "gn_classification",
    "gn_noise",
    "gn_riot",
    "gn_name",
    "gn_error",
]

# The stratified run writes to its own file with an additional stratum
# column. Kept separate from _FIELDNAMES so that appending to the existing
# validation_ips.csv never misaligns against its original header.
_FIELDNAMES_STRATIFIED = _FIELDNAMES[:4] + ["stratum"] + _FIELDNAMES[4:]


# ---------------------------------------------------------------- env
def _get_env_key(name: str) -> str:
    key = os.getenv(name)
    if not key:
        print(f"ERROR: environment variable {name} not set. Add to ~/.bashrc and source it.",
              file=sys.stderr)
        sys.exit(1)
    return key


# ---------------------------------------------------------------- feeds
def _query_abuseipdb(ip: str, key: str) -> dict:
    try:
        r = requests.get(
            _ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "abuseipdb_confidence": int(data.get("abuseConfidenceScore", -1)),
                "abuseipdb_reports": int(data.get("totalReports", 0)),
                "abuseipdb_country": str(data.get("countryCode", "") or ""),
                "abuseipdb_error": "",
            }
        return {
            "abuseipdb_confidence": -1,
            "abuseipdb_reports": -1,
            "abuseipdb_country": "",
            "abuseipdb_error": f"HTTP {r.status_code}",
        }
    except Exception as e:
        return {
            "abuseipdb_confidence": -1,
            "abuseipdb_reports": -1,
            "abuseipdb_country": "",
            "abuseipdb_error": f"{type(e).__name__}: {str(e)[:100]}",
        }


def _query_virustotal(ip: str, key: str) -> dict:
    try:
        r = requests.get(
            _VIRUSTOTAL_URL.format(ip=ip),
            headers={"x-apikey": key, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "vt_malicious": int(stats.get("malicious", 0)),
                "vt_suspicious": int(stats.get("suspicious", 0)),
                "vt_harmless": int(stats.get("harmless", 0)),
                "vt_undetected": int(stats.get("undetected", 0)),
                "vt_error": "",
            }
        if r.status_code == 404:
            return {
                "vt_malicious": 0,
                "vt_suspicious": 0,
                "vt_harmless": 0,
                "vt_undetected": 0,
                "vt_error": "not_found",
            }
        return {
            "vt_malicious": -1,
            "vt_suspicious": -1,
            "vt_harmless": -1,
            "vt_undetected": -1,
            "vt_error": f"HTTP {r.status_code}",
        }
    except Exception as e:
        return {
            "vt_malicious": -1,
            "vt_suspicious": -1,
            "vt_harmless": -1,
            "vt_undetected": -1,
            "vt_error": f"{type(e).__name__}: {str(e)[:100]}",
        }


def _query_greynoise(ip: str, key: str) -> dict:
    try:
        r = requests.get(
            _GREYNOISE_URL.format(ip=ip),
            headers={"key": key, "Accept": "application/json"},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "gn_classification": str(data.get("classification", "unknown") or "unknown"),
                "gn_noise": bool(data.get("noise", False)),
                "gn_riot": bool(data.get("riot", False)),
                "gn_name": str(data.get("name", "") or ""),
                "gn_error": "",
            }
        if r.status_code == 404:
            return {
                "gn_classification": "no_data",
                "gn_noise": False,
                "gn_riot": False,
                "gn_name": "",
                "gn_error": "",
            }
        return {
            "gn_classification": "",
            "gn_noise": False,
            "gn_riot": False,
            "gn_name": "",
            "gn_error": f"HTTP {r.status_code}",
        }
    except Exception as e:
        return {
            "gn_classification": "",
            "gn_noise": False,
            "gn_riot": False,
            "gn_name": "",
            "gn_error": f"{type(e).__name__}: {str(e)[:100]}",
        }


# ---------------------------------------------------------------- IP source
def _get_top_ips_live(top_n: int, hours: int) -> list:
    """Query Elasticsearch via es_client for top-N attacker IPs."""
    import yaml
    from es_client import TpotEsClient

    config_path = Path(__file__).parent / "config.yml"
    config = yaml.safe_load(config_path.read_text())
    es_cfg = config["elasticsearch"]

    client = TpotEsClient(
        hosts=es_cfg["hosts"],
        username=es_cfg.get("username", ""),
        password=es_cfg.get("password", ""),
        verify_certs=es_cfg.get("verify_certs", False),
        timeout=30,
    )
    if not client.ping():
        raise RuntimeError(
            f"Elasticsearch not reachable at {es_cfg['hosts']}. Is the SSH tunnel up?"
        )
    data = client.query_window(hours=hours)
    ips = data.get("top_source_ips", [])
    return ips[:top_n]


def _build_es_client():
    """Construct a TpotEsClient from config.yml and verify reachability."""
    import yaml
    from es_client import TpotEsClient

    config_path = Path(__file__).parent / "config.yml"
    config = yaml.safe_load(config_path.read_text())
    es_cfg = config["elasticsearch"]

    client = TpotEsClient(
        hosts=es_cfg["hosts"],
        username=es_cfg.get("username", ""),
        password=es_cfg.get("password", ""),
        verify_certs=es_cfg.get("verify_certs", False),
        timeout=60,
    )
    if not client.ping():
        raise RuntimeError(
            f"Elasticsearch not reachable at {es_cfg['hosts']}. Is the SSH tunnel up?"
        )
    return client


def _get_population(hours: int, max_terms: int = 5000) -> list:
    """Return every source address in the window with its session count.

    Uses a terms aggregation sized well above the known cardinality so that
    the full population is retrieved rather than a top-N slice. Returns a
    list of dicts ordered by descending session count.
    """
    client = _build_es_client()
    tf = {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}
    r = client.es.search(
        index="logstash-*", size=0, query=tf,
        aggs={
            "ips": {
                "terms": {"field": "src_ip.keyword", "size": max_terms},
                "aggs": {
                    "country": {
                        "terms": {"field": "geoip.country_name.keyword", "size": 1}
                    }
                },
            }
        },
    )
    out = []
    for b in r["aggregations"]["ips"]["buckets"]:
        cb = b["country"]["buckets"]
        out.append({
            "ip": b["key"],
            "count": b["doc_count"],
            "country": cb[0]["key"] if cb else "Unknown",
        })
    return out


def population_audit(hours: int, operator_ip: str = _DEFAULT_OPERATOR_IP) -> dict:
    """Measure how much of the capture is attributable to excluded addresses.

    This is the contamination check. Every headline figure in the results
    chapter depends on it, so it is implemented here rather than as an ad hoc
    query, making it reproducible and re-runnable.
    """
    population = _get_population(hours)

    included, excluded = [], []
    for entry in population:
        if is_excluded_address(entry["ip"], operator_ip):
            entry = dict(entry)
            entry["reason"] = classify_exclusion(entry["ip"], operator_ip)
            excluded.append(entry)
        else:
            included.append(entry)

    total_sessions = sum(e["count"] for e in population)
    excluded_sessions = sum(e["count"] for e in excluded)

    return {
        "window_hours": hours,
        "total_sessions_raw": total_sessions,
        "excluded_sessions": excluded_sessions,
        "external_sessions": total_sessions - excluded_sessions,
        "excluded_pct": round(100.0 * excluded_sessions / max(total_sessions, 1), 4),
        "total_unique_ips_raw": len(population),
        "excluded_unique_ips": len(excluded),
        "external_unique_ips": len(included),
        "excluded_detail": sorted(excluded, key=lambda e: -e["count"]),
    }


def _stratified_sample(population: list, top_n: int, tail_n: int,
                       seed: int, operator_ip: str) -> list:
    """Draw a two-stratum sample from the filtered population.

    Stratum A: the top_n addresses by session count. These account for the
               bulk of observed traffic, so validating them characterises the
               data that actually drives the analysis.
    Stratum B: tail_n addresses drawn at random, without replacement, from
               everything below the top_n cut. This characterises the long
               tail of low-volume sources.

    The random draw is seeded so the sample is reproducible.
    """
    import random

    filtered = [e for e in population
                if not is_excluded_address(e["ip"], operator_ip)]
    filtered.sort(key=lambda e: -e["count"])

    head = filtered[:top_n]
    tail_pool = filtered[top_n:]

    rng = random.Random(seed)
    if tail_n >= len(tail_pool):
        tail = list(tail_pool)
    else:
        tail = rng.sample(tail_pool, tail_n)

    for e in head:
        e["stratum"] = "A_top_volume"
    for e in tail:
        e["stratum"] = "B_random_tail"

    return head + tail


# ---------------------------------------------------------------- summary
def load_summary() -> Optional[dict]:
    """Return latest validation summary from validation_ips.csv.

    Returns None if the CSV is absent or empty. The summary uses exact
    counts (never "N+" or "N or more") against the fixed thresholds
    defined at the top of this module.
    """
    if not _VALIDATION_CSV_PATH.exists() or _VALIDATION_CSV_PATH.stat().st_size == 0:
        return None

    rows = list(csv.DictReader(_VALIDATION_CSV_PATH.open()))
    if not rows:
        return None

    rows.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
    latest_ts = rows[0].get("timestamp", "")
    latest_rows = [r for r in rows if r.get("timestamp") == latest_ts]
    total = len(latest_rows)

    def _int(row, key):
        try:
            return int(row.get(key, "") or 0)
        except (ValueError, TypeError):
            return 0

    # Three-band AbuseIPDB reporting for defensible academic distribution
    ab_high = sum(
        1 for r in latest_rows
        if _int(r, "abuseipdb_confidence") >= _ABUSEIPDB_HIGH_THRESHOLD
    )
    ab_medium = sum(
        1 for r in latest_rows
        if _ABUSEIPDB_MEDIUM_THRESHOLD <= _int(r, "abuseipdb_confidence") < _ABUSEIPDB_HIGH_THRESHOLD
    )
    ab_low = sum(
        1 for r in latest_rows
        if 0 <= _int(r, "abuseipdb_confidence") < _ABUSEIPDB_MEDIUM_THRESHOLD
    )
    # Backward-compatible aggregate (medium or higher = "flagged")
    ab_flagged = ab_high + ab_medium

    vt_flagged = sum(
        1 for r in latest_rows
        if _int(r, "vt_malicious") >= _VIRUSTOTAL_MALICIOUS_THRESHOLD
    )
    gn_flagged = sum(
        1 for r in latest_rows
        if (r.get("gn_classification") or "").lower() in {"malicious", "malicious_scanner"}
    )

    return {
        "timestamp": latest_ts,
        "total_ips": total,
        "abuseipdb_flagged": ab_flagged,
        "abuseipdb_threshold": _ABUSEIPDB_MEDIUM_THRESHOLD,
        "abuseipdb_high": ab_high,
        "abuseipdb_high_threshold": _ABUSEIPDB_HIGH_THRESHOLD,
        "abuseipdb_medium": ab_medium,
        "abuseipdb_medium_threshold": _ABUSEIPDB_MEDIUM_THRESHOLD,
        "abuseipdb_low": ab_low,
        "virustotal_flagged": vt_flagged,
        "virustotal_threshold": _VIRUSTOTAL_MALICIOUS_THRESHOLD,
        "greynoise_flagged": gn_flagged,
    }


# ---------------------------------------------------------------- main
def main() -> int:
    parser = argparse.ArgumentParser(
        description="ARGUS three-feed IP validator (AbuseIPDB + VirusTotal + GreyNoise)"
    )
    parser.add_argument("--live", action="store_true",
                        help="Query Elasticsearch for top attacker IPs")
    parser.add_argument("--top-n", type=int, default=50,
                        help="Number of top IPs to validate (default 50)")
    parser.add_argument("--hours", type=int, default=168,
                        help="Reporting window in hours for the ES query (default 168 = 7 days)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Verify API keys present without making calls")
    parser.add_argument("--stratified", action="store_true",
                        help="Two-stratum sample: top-N by volume plus a random tail sample")
    parser.add_argument("--tail-n", type=int, default=100,
                        help="Stratum B size, drawn at random from below the top-N cut (default 100)")
    parser.add_argument("--seed", type=int, default=22064430,
                        help="Random seed for the tail draw, so the sample is reproducible")
    parser.add_argument("--population-audit", action="store_true",
                        help="Report contamination from excluded addresses, then exit. Makes no API calls.")
    parser.add_argument("--operator-ip", type=str, default=_DEFAULT_OPERATOR_IP,
                        help="Operator administrative source address to exclude")
    args = parser.parse_args()

    # -------- population audit: no API keys needed, no external calls --------
    if args.population_audit:
        try:
            audit = population_audit(args.hours, args.operator_ip)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

        print("=" * 66)
        print(f"POPULATION AUDIT — capture window {audit['window_hours']}h")
        print("=" * 66)
        print()
        print("Sessions")
        print(f"  Raw total                 {audit['total_sessions_raw']:>12,}")
        print(f"  Attributable to excluded  {audit['excluded_sessions']:>12,}"
              f"   ({audit['excluded_pct']}%)")
        print(f"  External (corrected)      {audit['external_sessions']:>12,}")
        print()
        print("Unique source addresses")
        print(f"  Raw total                 {audit['total_unique_ips_raw']:>12,}")
        print(f"  Excluded                  {audit['excluded_unique_ips']:>12,}")
        print(f"  External (corrected)      {audit['external_unique_ips']:>12,}")
        print()
        if audit["excluded_detail"]:
            print("Excluded addresses")
            print(f"  {'address':<18}{'sessions':>12}   reason")
            print("  " + "-" * 62)
            for e in audit["excluded_detail"]:
                print(f"  {e['ip']:<18}{e['count']:>12,}   {e['reason']}")
        else:
            print("No excluded addresses present in this window.")
        print()
        print("Use the corrected figures in the results chapter.")
        return 0

    abuse_key = _get_env_key("ABUSEIPDB_API_KEY")
    vt_key = _get_env_key("VIRUSTOTAL_API_KEY")
    gn_key = _get_env_key("GREYNOISE_API_KEY")

    if args.dry_run:
        print("✓ Dry run OK: all three API keys present in environment.")
        return 0

    if not args.live:
        print("ERROR: --live required. Specify --live to query Elasticsearch.",
              file=sys.stderr)
        return 1

    stratified = args.stratified
    try:
        if stratified:
            population = _get_population(args.hours)
            n_before = len(population)
            ips = _stratified_sample(
                population, args.top_n, args.tail_n, args.seed, args.operator_ip
            )
            n_excluded = sum(
                1 for e in population
                if is_excluded_address(e["ip"], args.operator_ip)
            )
            print(f"→ Population: {n_before} unique addresses in the last {args.hours}h")
            print(f"  Excluded by filter rule: {n_excluded}")
            print(f"  Sample frame: {n_before - n_excluded}")
            print(f"  Stratum A (top by volume): {min(args.top_n, n_before - n_excluded)}")
            print(f"  Stratum B (random tail, seed {args.seed}): "
                  f"{len(ips) - min(args.top_n, n_before - n_excluded)}")
            print()
        else:
            ips = _get_top_ips_live(args.top_n, args.hours)
            ips = [e for e in ips
                   if not is_excluded_address(
                       e["ip"] if isinstance(e, dict) else str(e), args.operator_ip)]
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if not ips:
        print("No IPs returned from Elasticsearch. Instance may be stopped or no capture yet.",
              file=sys.stderr)
        return 1

    est_minutes = round(len(ips) * _SLEEP_SECONDS_BETWEEN_IPS / 60.0, 1)
    print(f"→ Validating {len(ips)} IPs against 3 threat intelligence feeds")
    print(f"  Rate limit floor: VirusTotal 4/min (respected via {_SLEEP_SECONDS_BETWEEN_IPS}s inter-IP sleep)")
    print(f"  Estimated wall-clock: {est_minutes} minutes")
    print()

    now = datetime.now(_TIMEZONE).isoformat(timespec="seconds")
    rows = []

    for i, ip_entry in enumerate(ips, 1):
        if isinstance(ip_entry, dict):
            ip = str(ip_entry.get("ip", ""))
            session_count = int(ip_entry.get("count", 0) or 0)
            country = str(ip_entry.get("country", "") or "")
            stratum = str(ip_entry.get("stratum", "") or "")
        else:
            ip = str(ip_entry)
            session_count = 0
            country = ""
            stratum = ""

        if not ip:
            continue

        print(f"  [{i}/{len(ips)}] {ip:16s} ... ", end="", flush=True)

        abuse = _query_abuseipdb(ip, abuse_key)
        vt = _query_virustotal(ip, vt_key)
        gn = _query_greynoise(ip, gn_key)

        row = {
            "timestamp": now,
            "ip": ip,
            "session_count_in_capture": session_count,
            "country_captured": country,
            **abuse,
            **vt,
            **gn,
        }
        if stratified:
            row["stratum"] = stratum
        rows.append(row)

        ab_conf = abuse.get("abuseipdb_confidence", -1)
        vt_mal = vt.get("vt_malicious", -1)
        gn_class = gn.get("gn_classification", "?")
        print(f"AbuseIPDB={ab_conf:>3}  VT_malicious={vt_mal:>2}  GN={gn_class}")

        if i < len(ips):
            time.sleep(_SLEEP_SECONDS_BETWEEN_IPS)

    out_path = _STRATIFIED_CSV_PATH if stratified else _VALIDATION_CSV_PATH
    fieldnames = _FIELDNAMES_STRATIFIED if stratified else _FIELDNAMES

    write_header = (not out_path.exists() or out_path.stat().st_size == 0)
    with open(out_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print()
    print(f"✓ Wrote {len(rows)} rows to {out_path}")
    print()

    def _counts(subset):
        return (
            sum(1 for r in subset
                if r.get("abuseipdb_confidence", -1) >= _ABUSEIPDB_HIGH_THRESHOLD),
            sum(1 for r in subset
                if _ABUSEIPDB_MEDIUM_THRESHOLD <= r.get("abuseipdb_confidence", -1)
                < _ABUSEIPDB_HIGH_THRESHOLD),
            sum(1 for r in subset
                if r.get("vt_malicious", -1) >= _VIRUSTOTAL_MALICIOUS_THRESHOLD),
            sum(1 for r in subset
                if r.get("gn_classification", "") in ("malicious", "malicious_scanner")),
        )

    def _report(label, subset):
        if not subset:
            return
        n = len(subset)
        hi, med, vt_f, gn_f = _counts(subset)
        pct = lambda k: round(100.0 * k / n, 1)
        print(f"{label}  (N = {n})")
        print(f"  AbuseIPDB confidence at or above {_ABUSEIPDB_HIGH_THRESHOLD}: "
              f"{hi} of {n}  ({pct(hi)}%)")
        print(f"  AbuseIPDB confidence {_ABUSEIPDB_MEDIUM_THRESHOLD} to "
              f"{_ABUSEIPDB_HIGH_THRESHOLD - 1}: {med} of {n}  ({pct(med)}%)")
        print(f"  VirusTotal {_VIRUSTOTAL_MALICIOUS_THRESHOLD} or more vendor detections: "
              f"{vt_f} of {n}  ({pct(vt_f)}%)")
        print(f"  GreyNoise malicious or malicious_scanner: "
              f"{gn_f} of {n}  ({pct(gn_f)}%)")
        print()

    print("Summary (exact counts):")
    print()
    _report("OVERALL", rows)

    if stratified:
        head = [r for r in rows if r.get("stratum") == "A_top_volume"]
        tail = [r for r in rows if r.get("stratum") == "B_random_tail"]
        _report("STRATUM A — top by session volume", head)
        _report("STRATUM B — random tail sample", tail)
        print("Compare the two strata. A materially higher flag rate in "
              "Stratum A indicates that high-volume sources are more likely "
              "to be externally recognised as malicious infrastructure.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
