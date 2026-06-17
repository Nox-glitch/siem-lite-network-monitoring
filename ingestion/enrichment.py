
import os
import json
import time
import logging
import urllib.request
import urllib.error
from functools import lru_cache
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
IPINFO_TOKEN      = os.getenv("IPINFO_TOKEN", "")

_cache: dict[str, tuple[dict, datetime]] = {}
CACHE_TTL_HOURS = 6


def _cached_get(ip: str) -> Optional[dict]:
    entry = _cache.get(ip)
    if entry and entry[1] > datetime.utcnow():
        return entry[0]
    return None


def _cache_set(ip: str, data: dict):
    _cache[ip] = (data, datetime.utcnow() + timedelta(hours=CACHE_TTL_HOURS))


def _is_private(ip: str) -> bool:
    if not ip:
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    return (
        a == 10
        or a == 127
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
    )


def _fetch_geo_ipapi(ip: str) -> dict:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
        req = urllib.request.Request(url, headers={"User-Agent": "SIEM-Lite/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            return {
                "country":      data.get("country"),
                "country_code": data.get("countryCode"),
                "city":         data.get("city"),
                "isp":          data.get("isp"),
                "org":          data.get("org"),
                "asn":          data.get("as"),
            }
    except Exception as e:
        logger.debug(f"ip-api.com failed for {ip}: {e}")
    return {}


def _fetch_abuse_score(ip: str) -> dict:

    if not ABUSEIPDB_API_KEY:
        return {}
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30"
        req = urllib.request.Request(url, headers={
            "Key":    ABUSEIPDB_API_KEY,
            "Accept": "application/json",
            "User-Agent": "SIEM-Lite/1.0",
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read()).get("data", {})
        return {
            "abuse_score":    data.get("abuseConfidenceScore", 0),
            "is_tor":         data.get("isTor", False),
            "total_reports":  data.get("totalReports", 0),
            "last_reported":  data.get("lastReportedAt"),
            "domain":         data.get("domain"),
            "isp":            data.get("isp"),
        }
    except urllib.error.HTTPError as e:
        if e.code == 429:
            logger.warning("AbuseIPDB rate limit reached")
        else:
            logger.debug(f"AbuseIPDB error for {ip}: {e}")
    except Exception as e:
        logger.debug(f"AbuseIPDB failed for {ip}: {e}")
    return {}


def lookup_ip(ip: str) -> dict:

    if not ip or _is_private(ip):
        return {}

    cached = _cached_get(ip)
    if cached is not None:
        return cached

    result = {}

    geo = _fetch_geo_ipapi(ip)
    result.update(geo)

    abuse = _fetch_abuse_score(ip)
    result.update(abuse)

    score = abuse.get("abuse_score", 0)
    if abuse.get("is_tor"):
        score = max(score, 60)
    result["threat_score"] = score

    if score >= 80:
        result["threat_level"] = "malicious"
    elif score >= 40:
        result["threat_level"] = "suspicious"
    elif score >= 10:
        result["threat_level"] = "low_risk"
    else:
        result["threat_level"] = "clean"

    _cache_set(ip, result)
    logger.debug(f"Enriched {ip}: score={score}, country={result.get('country')}")
    return result


def enrich_event(event: dict) -> dict:

    ip = event.get("source_ip")
    if not ip:
        return event

    try:
        intel = lookup_ip(ip)
        if intel:
            event["country"]      = intel.get("country")
            event["city"]         = intel.get("city")
            event["threat_score"] = intel.get("threat_score", 0.0)
            event.setdefault("extra", {})
            event["extra"].update({
                k: v for k, v in intel.items()
                if k not in ("country", "city", "threat_score")
                and v is not None
            })

            if intel.get("threat_score", 0) >= 80:
                if event.get("severity") in ("low", "medium"):
                    event["severity"] = "high"
                    event["extra"]["severity_escalated"] = "AbuseIPDB score ≥ 80"

    except Exception as e:
        logger.warning(f"Enrichment failed for {ip}: {e}")

    return event


def bulk_enrich(events: list[dict]) -> list[dict]:
    for event in events:
        enrich_event(event)
        time.sleep(0.1)
    return events
