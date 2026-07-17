"""
Threat intelligence enrichment.

For every alert, looks up the source IP against:
  - AbuseIPDB (IP reputation / abuse confidence score)
  - VirusTotal (IP reputation, if a file hash were present this would also
    check file reputation)

Real lookups require free API keys set as environment variables:
    ABUSEIPDB_API_KEY
    VIRUSTOTAL_API_KEY

If no keys are set, the module falls back to a local mock IOC list so the
pipeline still runs end-to-end for a demo/offline environment. This mirrors
a real deployment pattern: you'd swap the mock for MISP or a paid feed
without changing anything else downstream.

Results are cached in-memory per run to avoid repeat lookups (and to respect
free-tier rate limits) for IPs that appear in multiple alerts.
"""

import json
import os
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
ALERTS_PATH = ROOT / "data" / "alerts.json"
ENRICHED_PATH = ROOT / "data" / "alerts_enriched.json"
MOCK_IOC_PATH = Path(__file__).parent / "mock_iocs.json"

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

_cache = {}


def _load_mock_iocs():
    if MOCK_IOC_PATH.exists():
        with open(MOCK_IOC_PATH) as f:
            return json.load(f)
    return {}


_MOCK_IOCS = _load_mock_iocs()


def lookup_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country": data.get("countryCode"),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def lookup_virustotal_ip(ip: str) -> dict:
    if not VT_KEY:
        return {}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_KEY},
            timeout=5,
        )
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def lookup_mock(ip: str) -> dict:
    return _MOCK_IOCS.get(ip, {})


def enrich_ip(ip: str) -> dict:
    if ip in _cache:
        return _cache[ip]

    if ABUSEIPDB_KEY or VT_KEY:
        result = {}
        if ABUSEIPDB_KEY:
            result["abuseipdb"] = lookup_abuseipdb(ip)
        if VT_KEY:
            result["virustotal"] = lookup_virustotal_ip(ip)
        source = "live"
    else:
        result = {"mock": lookup_mock(ip)}
        source = "mock"

    is_known_bad = False
    reputation_score = 0
    if source == "mock":
        mock = result.get("mock", {})
        is_known_bad = mock.get("malicious", False)
        reputation_score = mock.get("abuse_score", 0)
    else:
        abuse = result.get("abuseipdb", {})
        vt = result.get("virustotal", {})
        reputation_score = abuse.get("abuse_confidence_score", 0) or 0
        is_known_bad = reputation_score > 50 or vt.get("malicious_votes", 0) > 0

    enriched = {
        "ip": ip,
        "source": source,
        "is_known_bad": is_known_bad,
        "reputation_score": reputation_score,
        "raw": result,
    }
    _cache[ip] = enriched
    return enriched


def enrich_alerts(alerts: list) -> list:
    enriched = []
    for alert in alerts:
        intel = enrich_ip(alert["src_ip"])
        alert = dict(alert)
        alert["threat_intel"] = intel

        # boost severity if an anomalous/attack-scored window ALSO matches
        # a known-bad IP -- this is the "corroboration" step described in
        # the project write-up: AI score + external IOC match together are
        # much stronger evidence than either alone.
        if intel["is_known_bad"] and alert["severity"] != "high":
            alert["severity"] = "high"
            alert["severity_reason"] = "IOC match escalated severity"

        enriched.append(alert)
        time.sleep(0)  # placeholder for rate-limit pacing if using live APIs
    return enriched


def main():
    with open(ALERTS_PATH) as f:
        alerts = json.load(f)

    enriched = enrich_alerts(alerts)

    with open(ENRICHED_PATH, "w") as f:
        json.dump(enriched, f, indent=2)

    n_bad = sum(1 for a in enriched if a["threat_intel"]["is_known_bad"])
    mode = "live API" if (ABUSEIPDB_KEY or VT_KEY) else "offline mock IOC list"
    print(f"Enriched {len(enriched)} alerts using {mode}.")
    print(f"{n_bad} alerts matched a known-bad indicator -> escalated.")
    print(f"Wrote {ENRICHED_PATH}")


if __name__ == "__main__":
    main()
