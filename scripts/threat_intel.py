#!/usr/bin/env python3
"""
Threat Intelligence Enrichment Module
======================================
Enrichissement optionnel via APIs externes :
- ipapi.co       : Geolocalisation IP (gratuit, sans cle)
- AbuseIPDB      : Reputation IP (cle gratuite, 1000 req/jour)
- VirusTotal     : Reputation URL/hash/IP (cle gratuite, 4 req/min)
- URLhaus        : Base de donnees URLs malveillantes (gratuit, sans cle)

Toutes les APIs sont optionnelles. Si une cle est absente ou une API
indisponible, le module retourne gracieusement des resultats vides.
Les cles se configurent dans .env :
    ABUSEIPDB_API_KEY=xxx
    VIRUSTOTAL_API_KEY=xxx
"""

import os
import time
import json
import logging
from typing import Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

# ── Rate limiting ──
_request_times: dict[str, list[float]] = {}


def _rate_limit(api_name: str, max_per_minute: int):
    """Simple rate limiter per API."""
    now = time.time()
    if api_name not in _request_times:
        _request_times[api_name] = []
    # Clean old entries
    _request_times[api_name] = [t for t in _request_times[api_name] if now - t < 60]
    if len(_request_times[api_name]) >= max_per_minute:
        return False
    _request_times[api_name].append(now)
    return True


def _safe_request(url: str, headers: dict = None, timeout: int = 5) -> Optional[dict]:
    """HTTP GET with error handling. Returns parsed JSON or None."""
    try:
        import requests
        resp = requests.get(url, headers=headers or {}, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        logger.warning(f"API {url[:60]}... returned {resp.status_code}")
    except ImportError:
        logger.debug("requests not installed — skipping API call")
    except Exception as e:
        logger.debug(f"API call failed: {e}")
    return None


# ══════════════════════════════════════════════════════════
# 1. ipapi.co — Geolocalisation IP (gratuit, sans cle)
# ══════════════════════════════════════════════════════════

def geolocate_ip(ip: str) -> dict:
    """
    Geolocalise une IP via ipapi.co (gratuit, 1000 req/jour, sans cle).
    Retourne: country, city, org, asn, etc.
    """
    if not _rate_limit("ipapi", 45):  # ~45/min safe margin
        return {}
    data = _safe_request(f"https://ipapi.co/{ip}/json/")
    if not data or data.get("error"):
        return {}
    return {
        "country": data.get("country_name", ""),
        "country_code": data.get("country_code", ""),
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "org": data.get("org", ""),
        "asn": data.get("asn", ""),
        "isp": data.get("org", ""),
    }


# ══════════════════════════════════════════════════════════
# 2. AbuseIPDB — Reputation IP (cle gratuite)
# ══════════════════════════════════════════════════════════

def check_abuseipdb(ip: str, api_key: str = None) -> dict:
    """
    Verifie la reputation d'une IP via AbuseIPDB.
    Cle gratuite : https://www.abuseipdb.com/account/api
    Retourne: abuse_score (0-100), total_reports, usage_type, isp, domain.
    """
    key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
    if not key:
        return {}
    if not _rate_limit("abuseipdb", 60):
        return {}

    try:
        import requests
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            timeout=5
        )
        if resp.status_code != 200:
            return {}
        d = resp.json().get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "usage_type": d.get("usageType", ""),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "country_code": d.get("countryCode", ""),
            "is_tor": d.get("isTor", False),
            "is_whitelisted": d.get("isWhitelisted", False),
            "last_reported": d.get("lastReportedAt", ""),
        }
    except Exception as e:
        logger.debug(f"AbuseIPDB error: {e}")
        return {}


# ══════════════════════════════════════════════════════════
# 3. VirusTotal — Reputation URL / Hash / IP (cle gratuite)
# ══════════════════════════════════════════════════════════

def _vt_headers(api_key: str = None) -> dict:
    key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        return {}
    return {"x-apikey": key}


def check_vt_ip(ip: str, api_key: str = None) -> dict:
    """Reputation IP via VirusTotal v3."""
    headers = _vt_headers(api_key)
    if not headers:
        return {}
    if not _rate_limit("virustotal", 4):
        return {}
    data = _safe_request(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
    if not data:
        return {}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "country": attrs.get("country", ""),
        "as_owner": attrs.get("as_owner", ""),
        "asn": attrs.get("asn", 0),
    }


def check_vt_url(url: str, api_key: str = None) -> dict:
    """Reputation URL via VirusTotal v3."""
    headers = _vt_headers(api_key)
    if not headers:
        return {}
    if not _rate_limit("virustotal", 4):
        return {}
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    data = _safe_request(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    if not data:
        return {}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "categories": attrs.get("categories", {}),
    }


def check_vt_hash(file_hash: str, api_key: str = None) -> dict:
    """Reputation hash (MD5/SHA256) via VirusTotal v3."""
    headers = _vt_headers(api_key)
    if not headers:
        return {}
    if not _rate_limit("virustotal", 4):
        return {}
    data = _safe_request(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
    if not data:
        return {}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "type_description": attrs.get("type_description", ""),
        "popular_threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
    }


# ══════════════════════════════════════════════════════════
# 4. URLhaus — Base de donnees URLs malveillantes (gratuit)
# ══════════════════════════════════════════════════════════

def check_urlhaus(url: str) -> dict:
    """
    Verifie si une URL est dans la base URLhaus (abuse.ch).
    Gratuit, sans cle API, illimite.
    """
    try:
        import requests
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=5
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
        if data.get("query_status") == "no_results":
            return {"listed": False}
        return {
            "listed": True,
            "threat": data.get("threat", ""),
            "url_status": data.get("url_status", ""),
            "date_added": data.get("date_added", ""),
            "tags": data.get("tags", []),
        }
    except Exception as e:
        logger.debug(f"URLhaus error: {e}")
        return {}


def check_urlhaus_hash(md5_hash: str) -> dict:
    """Verifie si un hash de fichier est dans URLhaus."""
    try:
        import requests
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/payload/",
            data={"md5_hash": md5_hash},
            timeout=5
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
        if data.get("query_status") == "no_results":
            return {"listed": False}
        return {
            "listed": True,
            "file_type": data.get("file_type", ""),
            "signature": data.get("signature", ""),
            "url_count": data.get("url_count", 0),
        }
    except Exception as e:
        logger.debug(f"URLhaus hash error: {e}")
        return {}


# ══════════════════════════════════════════════════════════
# Enrichissement complet — orchestrateur
# ══════════════════════════════════════════════════════════

def enrich_ip(ip: str, is_private: bool = False) -> dict:
    """
    Enrichissement complet d'une IP via toutes les APIs disponibles.
    Retourne un dict unifie avec toutes les donnees disponibles.
    """
    if is_private:
        return {"geo": {}, "abuse": {}, "vt": {}, "source": "private"}

    result = {"geo": {}, "abuse": {}, "vt": {}}

    # Geoloc (toujours dispo, sans cle)
    result["geo"] = geolocate_ip(ip)

    # AbuseIPDB (si cle dispo)
    result["abuse"] = check_abuseipdb(ip)

    # VirusTotal (si cle dispo)
    result["vt"] = check_vt_ip(ip)

    return result


def enrich_url(url: str) -> dict:
    """Enrichissement complet d'une URL."""
    result = {"urlhaus": {}, "vt": {}}

    # URLhaus (toujours dispo, sans cle)
    result["urlhaus"] = check_urlhaus(url)

    # VirusTotal (si cle dispo)
    result["vt"] = check_vt_url(url)

    return result


def enrich_hash(file_hash: str, hash_type: str = "sha256") -> dict:
    """Enrichissement d'un hash de fichier."""
    result = {"urlhaus": {}, "vt": {}}

    if hash_type == "md5":
        result["urlhaus"] = check_urlhaus_hash(file_hash)

    result["vt"] = check_vt_hash(file_hash)

    return result


def get_available_apis() -> dict:
    """Retourne les APIs disponibles (avec/sans cle)."""
    return {
        "ipapi": {"available": True, "needs_key": False, "description": "Geolocalisation IP"},
        "abuseipdb": {
            "available": bool(os.environ.get("ABUSEIPDB_API_KEY")),
            "needs_key": True,
            "description": "Reputation IP"
        },
        "virustotal": {
            "available": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
            "needs_key": True,
            "description": "Reputation URL/Hash/IP"
        },
        "urlhaus": {"available": True, "needs_key": False, "description": "Base URLs malveillantes"},
    }
