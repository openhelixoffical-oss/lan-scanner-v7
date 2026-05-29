"""
abuseipdb.py
checks device IPs and your WAN IP against the AbuseIPDB threat intelligence database
flags IPs that have been reported for malicious activity
free API key at abuseipdb.com -- 1000 checks/day on free tier
"""

import urllib.request
import urllib.parse
import json
import socket
from typing import Dict, List, Optional
from datetime import datetime


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def get_wan_ip() -> Optional[str]:
    """Get our public/WAN IP address."""
    try:
        req = urllib.request.Request(
            "https://api.ipify.org?format=json",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        resp = urllib.request.urlopen(req, timeout=5)
        data = json.loads(resp.read())
        return data.get("ip")
    except Exception:
        return None


def check_ip(ip: str, api_key: str, max_age_days: int = 90) -> Dict:
    """
    Check a single IP against AbuseIPDB.
    Returns dict with abuse score, reports, country, ISP etc.
    """
    if not api_key:
        return {"error": "no api key provided"}

    # skip private IPs -- abuseipdb only knows about public IPs
    if _is_private(ip):
        return {"ip": ip, "is_private": True, "skipped": True}

    try:
        params = urllib.parse.urlencode({
            "ipAddress": ip,
            "maxAgeInDays": max_age_days,
            "verbose": "",
        })

        req = urllib.request.Request(
            f"{ABUSEIPDB_URL}?{params}",
            headers={
                "Key": api_key,
                "Accept": "application/json",
            }
        )

        resp = urllib.request.urlopen(req, timeout=8)
        data = json.loads(resp.read())
        raw = data.get("data", {})

        result = {
            "ip": ip,
            "abuse_score": raw.get("abuseConfidenceScore", 0),
            "total_reports": raw.get("totalReports", 0),
            "last_reported": raw.get("lastReportedAt", None),
            "country": raw.get("countryCode", ""),
            "isp": raw.get("isp", ""),
            "domain": raw.get("domain", ""),
            "is_tor": raw.get("isTor", False),
            "is_whitelisted": raw.get("isWhitelisted", False),
            "usage_type": raw.get("usageType", ""),
            "checked_at": datetime.now().isoformat(),
        }

        # assign risk level
        score = result["abuse_score"]
        if score >= 80:
            result["risk"] = "critical"
        elif score >= 50:
            result["risk"] = "high"
        elif score >= 25:
            result["risk"] = "medium"
        elif score > 0:
            result["risk"] = "low"
        else:
            result["risk"] = "clean"

        return result

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {"ip": ip, "error": "invalid api key"}
        elif e.code == 429:
            return {"ip": ip, "error": "rate limit hit -- try again tomorrow"}
        return {"ip": ip, "error": f"http {e.code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)[:60]}


def check_devices(devices: List[Dict], api_key: str) -> List[Dict]:
    """
    Check all device IPs against AbuseIPDB.
    Skips private IPs automatically.
    Also checks your WAN IP.
    Returns list of results sorted by abuse score.
    """
    results = []

    # check WAN IP first
    wan_ip = get_wan_ip()
    if wan_ip:
        result = check_ip(wan_ip, api_key)
        result["label"] = "your WAN IP"
        results.append(result)

    # check device IPs
    for device in devices:
        ip = device.get("ip", "")
        if not ip or _is_private(ip):
            continue
        result = check_ip(ip, api_key)
        result["label"] = device.get("hostname") or device.get("label") or ip
        results.append(result)

    # sort by abuse score, flagged first
    results.sort(key=lambda r: r.get("abuse_score", 0), reverse=True)
    return results


def _is_private(ip: str) -> bool:
    """Check if an IP is in a private range."""
    try:
        parts = list(map(int, ip.split(".")))
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 169 and parts[1] == 254:
            return True
        return False
    except Exception:
        return True
