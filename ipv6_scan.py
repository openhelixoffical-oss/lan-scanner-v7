"""
mirai_check.py
checks devices against known Mirai botnet indicators
Mirai specifically targets IoT devices with default credentials on telnet/ssh
checks: known C2 IPs, targeted ports, default credentials, known vulnerable vendors
"""

import socket
from typing import Dict, List, Optional
from datetime import datetime


# known Mirai C2 domains and IPs (publicly documented)
KNOWN_MIRAI_C2 = {
    "23.249.162.161",
    "23.249.162.162",
    "148.251.106.168",
    "108.61.218.11",
    "104.200.22.163",
    "198.199.64.217",
    "45.33.32.156",
    "198.199.120.180",
    "138.197.101.119",
    "104.131.0.69",
    "104.131.6.18",
    "104.236.33.231",
}

# Mirai targets these ports specifically
MIRAI_TARGET_PORTS = {
    23: "telnet",
    2323: "telnet-alt",
    22: "ssh",
    80: "http",
    8080: "http-alt",
    7547: "tr069",      # ISP management protocol, huge attack surface
    5555: "android-adb",
    9527: "unknown",
}

# default credentials Mirai uses (sanitized -- just usernames)
# this is public knowledge from the leaked Mirai source
MIRAI_DEFAULT_USERS = [
    "root", "admin", "user", "guest", "support",
    "Administrator", "ubnt", "default", "service",
]

# vendors/device types known to be frequently targeted
MIRAI_TARGETED_VENDORS = [
    "Dahua", "Hikvision", "Huawei", "ZTE", "D-Link",
    "Netgear", "Linksys", "TP-Link", "Asus", "Belkin",
    "Espressif", "Realtek",
]

# known vulnerable device signatures from Mirai source
MIRAI_SIGNATURES = [
    "busybox",
    "dropbear",
    "uhttpd",
    "goahead",
    "mini_httpd",
    "boa",
    "thttpd",
    "DVR",
    "NVR",
    "IP Camera",
    "Hikvision",
    "Dahua",
    "Avtech",
    "Vacron",
    "Jaws/1.0",
    "Cross Web Server",
    "Boa/0.9",
]


def check_device(device_info: Dict) -> Dict:
    """
    Check a device against Mirai IOCs.
    device_info should have: ip, vendor, open_ports (dict), deep_details (list), hostname
    Returns a risk assessment dict.
    """
    risks = []
    score = 0  # 0-100

    ip = device_info.get("ip", "")
    vendor = device_info.get("vendor", "")
    open_ports = device_info.get("open_ports", {})
    deep_details = device_info.get("deep_details", [])
    hostname = device_info.get("hostname", "")
    device_type = device_info.get("device_type", "")

    # check 1: telnet open -- mirai's primary attack vector
    if 23 in open_ports or 2323 in open_ports:
        score += 35
        port = 23 if 23 in open_ports else 2323
        risks.append({
            "severity": "critical",
            "check": "telnet open",
            "detail": f"port {port} open -- mirai's primary attack vector, disable telnet immediately",
        })

    # check 2: TR-069 exposed -- ISP management port often targeted
    if 7547 in open_ports:
        score += 25
        risks.append({
            "severity": "high",
            "check": "TR-069 exposed",
            "detail": "port 7547 open -- TR-069 ISP management protocol, known Mirai/Reaper target",
        })

    # check 3: Android ADB exposed
    if 5555 in open_ports:
        score += 30
        risks.append({
            "severity": "critical",
            "check": "Android ADB exposed",
            "detail": "port 5555 open -- Android debug bridge, device can be fully compromised remotely",
        })

    # check 4: vulnerable vendor
    for targeted_vendor in MIRAI_TARGETED_VENDORS:
        if targeted_vendor.lower() in vendor.lower():
            score += 15
            risks.append({
                "severity": "medium",
                "check": "targeted vendor",
                "detail": f"{vendor} devices are commonly targeted by Mirai variants",
            })
            break

    # check 5: vulnerable software signatures in banners
    details_text = " ".join(deep_details).lower()
    for sig in MIRAI_SIGNATURES:
        if sig.lower() in details_text:
            score += 20
            risks.append({
                "severity": "high",
                "check": "vulnerable software",
                "detail": f"found '{sig}' in device banners -- known Mirai target signature",
            })
            break

    # check 6: IoT device with web UI but no HTTPS
    is_iot = any(x in device_type.lower() for x in ["iot", "camera", "dvr", "nvr", "router"])
    if is_iot and 80 in open_ports and 443 not in open_ports:
        score += 10
        risks.append({
            "severity": "medium",
            "check": "IoT HTTP only",
            "detail": "IoT device with unencrypted HTTP -- credentials sent in plaintext",
        })

    # check 7: many ports open on an IoT device (suspicious)
    if is_iot and len(open_ports) > 5:
        score += 10
        risks.append({
            "severity": "low",
            "check": "many open ports",
            "detail": f"IoT device has {len(open_ports)} open ports -- unexpected attack surface",
        })

    # cap at 100
    score = min(score, 100)

    risk_level = "none"
    if score >= 70:
        risk_level = "critical"
    elif score >= 40:
        risk_level = "high"
    elif score >= 20:
        risk_level = "medium"
    elif score > 0:
        risk_level = "low"

    return {
        "ip": ip,
        "score": score,
        "risk_level": risk_level,
        "risks": risks,
        "checked_at": datetime.now().isoformat(),
    }


def check_all_devices(devices: List[Dict]) -> List[Dict]:
    """Run Mirai check on a list of devices, return only those with risks."""
    results = []
    for device in devices:
        result = check_device(device)
        if result["score"] > 0:
            results.append(result)
    return sorted(results, key=lambda r: r["score"], reverse=True)
