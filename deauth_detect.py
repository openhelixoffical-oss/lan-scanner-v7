"""
frag_scanner.py
sends fragmented packets to probe ports
some older firewalls/routers dont reassemble fragments properly
so a port that looks closed on a normal scan might respond to fragmented probes
also useful for fingerprinting firewall behavior
"""

import socket
import time
from typing import List, Dict, Optional

try:
    from scapy.all import (
        IP, TCP, UDP, fragment, sr, sr1, conf, ICMP, Raw
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ports to probe with fragmented packets
FRAG_PROBE_PORTS = [
    22, 23, 25, 53, 80, 110, 139, 143, 443,
    445, 3389, 8080, 8443, 9100
]


def _frag_tcp_syn(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """
    Send a fragmented TCP SYN to a port.
    Returns 'open', 'closed', 'filtered', or None.
    """
    if not SCAPY_AVAILABLE:
        return None

    conf.verb = 0
    try:
        # build TCP SYN packet with some padding so it fragments
        pkt = IP(dst=ip) / TCP(dport=port, flags="S") / Raw(b"X" * 24)

        # fragment into small pieces
        frags = fragment(pkt, fragsize=8)

        # send fragments and listen for reply
        answered, _ = sr(frags, timeout=timeout, verbose=False, retry=0)

        for _, resp in answered:
            if resp.haslayer(TCP):
                flags = resp[TCP].flags
                if flags & 0x12:  # SYN-ACK = open
                    return "open"
                elif flags & 0x04:  # RST = closed
                    return "closed"
            elif resp.haslayer(ICMP):
                icmp_type = resp[ICMP].type
                if icmp_type == 3:  # unreachable = filtered
                    return "filtered"

        return "filtered"  # no response = probably filtered

    except Exception:
        return None


def frag_scan(ip: str, ports: Optional[List[int]] = None) -> Dict[int, str]:
    """
    Run fragmented port scan on a device.
    Returns dict of {port: status} for ports that responded differently
    than expected (i.e. open via frag but not via normal scan).
    """
    if not SCAPY_AVAILABLE:
        return {}

    ports = ports or FRAG_PROBE_PORTS
    results = {}

    for port in ports:
        status = _frag_tcp_syn(ip, port)
        if status == "open":
            results[port] = status

    return results


def compare_with_normal(ip: str, normal_open_ports: Dict) -> Dict:
    """
    Compare fragmented scan results against normal scan.
    Returns ports that are ONLY visible via fragmented packets --
    these are hidden behind a firewall that doesnt handle fragments properly.
    """
    frag_results = frag_scan(ip)
    hidden_ports = {}

    for port, status in frag_results.items():
        if status == "open" and port not in normal_open_ports:
            from .deep_scan import PORTS
            service = PORTS.get(port, "unknown")
            hidden_ports[port] = service

    return hidden_ports
