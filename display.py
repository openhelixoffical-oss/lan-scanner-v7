"""
ipv6_scanner.py
discovers devices via IPv6 neighbor discovery (ICMPv6)
most devices have IPv6 addresses that are never scanned
uses multicast to find all link-local devices
"""

import socket
import struct
import time
from typing import List, Dict, Optional

try:
    from scapy.all import (
        IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr,
        ICMPv6ND_RS, ICMPv6ND_RA, Ether, sendp, sniff, conf,
        ICMPv6EchoRequest, ICMPv6EchoReply, sr1
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# all-nodes multicast address
ALL_NODES = "ff02::1"
# solicited-node multicast prefix
SOLICITED_PREFIX = "ff02::1:ff"


def _mac_to_ipv6_link_local(mac: str) -> str:
    """Convert a MAC address to its IPv6 link-local address (EUI-64)."""
    parts = mac.split(":")
    parts[0] = format(int(parts[0], 16) ^ 0x02, "02x")
    eui64 = parts[:3] + ["ff", "fe"] + parts[3:]
    groups = [
        eui64[0] + eui64[1],
        eui64[2] + eui64[3],
        eui64[4] + eui64[5],
        eui64[6] + eui64[7],
    ]
    return f"fe80::{':'.join(groups)}"


def _ping6(ip: str, iface: Optional[str] = None, timeout: float = 1.0) -> bool:
    """Send ICMPv6 echo request, return True if response received."""
    if not SCAPY_AVAILABLE:
        return False
    try:
        pkt = IPv6(dst=ip) / ICMPv6EchoRequest()
        resp = sr1(pkt, timeout=timeout, verbose=False, iface=iface)
        return resp is not None and resp.haslayer(ICMPv6EchoReply)
    except Exception:
        return False


def scan_ipv6(iface: Optional[str] = None, timeout: float = 3.0) -> List[Dict]:
    """
    Send ICMPv6 neighbor solicitation to all-nodes multicast.
    Listen for neighbor advertisements and collect link-local addresses.
    """
    if not SCAPY_AVAILABLE:
        print("  error: scapy required for ipv6 scanning")
        return []

    conf.verb = 0
    discovered = {}

    def handle_packet(pkt):
        # neighbor advertisement = device is announcing itself
        if pkt.haslayer(ICMPv6ND_NA):
            src_ip = pkt[IPv6].src
            # grab MAC from the options if present
            mac = "unknown"
            if pkt.haslayer(ICMPv6NDOptDstLLAddr):
                mac = pkt[ICMPv6NDOptDstLLAddr].lladdr
            if src_ip not in discovered and src_ip.startswith("fe80"):
                discovered[src_ip] = {"ip6": src_ip, "mac": mac}

        # also catch echo replies
        elif pkt.haslayer(ICMPv6EchoReply):
            src_ip = pkt[IPv6].src
            if src_ip not in discovered:
                discovered[src_ip] = {"ip6": src_ip, "mac": "unknown"}

    # send neighbor solicitation to all-nodes multicast
    try:
        pkt = Ether(dst="33:33:00:00:00:01") / \
              IPv6(dst=ALL_NODES) / \
              ICMPv6ND_NS(tgt=ALL_NODES)
        sendp(pkt, iface=iface, verbose=False)
    except Exception:
        pass

    # send router solicitation to find routers
    try:
        pkt = Ether(dst="33:33:00:00:00:02") / \
              IPv6(dst="ff02::2") / \
              ICMPv6ND_RS()
        sendp(pkt, iface=iface, verbose=False)
    except Exception:
        pass

    # listen for responses
    try:
        sniff(
            iface=iface,
            prn=handle_packet,
            timeout=timeout,
            store=False,
            filter="ip6",
        )
    except Exception:
        pass

    # also try pinging all-nodes
    try:
        pkt = IPv6(dst=ALL_NODES) / ICMPv6EchoRequest()
        from scapy.all import sr
        answered, _ = sr(pkt, timeout=timeout, verbose=False, iface=iface)
        for _, resp in answered:
            src = resp[IPv6].src
            if src not in discovered:
                discovered[src] = {"ip6": src, "mac": "unknown"}
    except Exception:
        pass

    return list(discovered.values())


def get_ipv6_hostname(ip6: str) -> str:
    """Try reverse DNS for an IPv6 address."""
    try:
        return socket.gethostbyaddr(ip6)[0]
    except Exception:
        return "unknown"


def run_ipv6_scan(iface=None) -> List[Dict]:
    """Run IPv6 scan and enrich results."""
    print("  scanning for ipv6 devices on the local network...")
    print("  looking for link-local addresses (fe80::)\n")

    devices = scan_ipv6(iface=iface)

    for device in devices:
        device["hostname"] = get_ipv6_hostname(device["ip6"])
        # try to figure out if its an Apple device from EUI-64
        mac = device.get("mac", "unknown")
        if mac != "unknown":
            try:
                from .vendor import VendorLookup
                v = VendorLookup()
                device["vendor"] = v.lookup(mac)
            except Exception:
                device["vendor"] = "unknown"
        else:
            device["vendor"] = "unknown"

    return sorted(devices, key=lambda d: d["ip6"])
