"""
decoy_scan.py
sends ARP probes spoofed from multiple fake source IPs
makes the scan look like it came from several different hosts
harder for IDS to attribute to you specifically
only use on networks you own
"""

import socket
import random
import ipaddress
from typing import List, Optional

try:
    from scapy.all import ARP, Ether, srp, IP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.100"


def _generate_decoy_ips(real_ip: str, count: int = 4) -> List[str]:
    """Generate fake IPs in the same subnet as the real IP."""
    parts = real_ip.rsplit(".", 1)
    base = parts[0]
    real_last = int(parts[1])

    decoys = []
    used = {real_last, 0, 1, 254, 255}
    while len(decoys) < count:
        last = random.randint(2, 253)
        if last not in used:
            used.add(last)
            decoys.append(f"{base}.{last}")

    return decoys


def decoy_scan(ip_range: str, num_decoys: int = 4) -> List[tuple]:
    """
    Scan the network using decoy source IPs mixed with the real one.
    Returns list of (ip, mac) tuples for discovered devices.
    """
    if not SCAPY_AVAILABLE:
        print("  error: scapy required for decoy scanning")
        return []

    conf.verb = 0
    real_ip = _get_local_ip()
    decoys = _generate_decoy_ips(real_ip, num_decoys)

    print(f"  real ip:   {real_ip}")
    print(f"  decoys:    {', '.join(decoys)}")
    print(f"  scanning:  {ip_range}\n")

    # build list of all target IPs
    try:
        network = ipaddress.IPv4Network(ip_range, strict=False)
        targets = [str(h) for h in network.hosts()]
    except Exception:
        return []

    discovered = {}

    # for each target, send probes from decoy IPs and the real one
    # interleave them so its not obvious which is real
    all_sources = decoys + [real_ip]
    random.shuffle(all_sources)

    for src_ip in all_sources:
        is_real = src_ip == real_ip

        # build ARP packets from this source
        pkts = [
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target, psrc=src_ip)
            for target in targets
        ]

        try:
            answered, _ = srp(pkts, timeout=1, retry=0, verbose=False)
            if is_real:
                for _, received in answered:
                    ip = received.psrc
                    mac = received.hwsrc
                    if ip not in discovered:
                        discovered[ip] = mac
        except Exception:
            pass

    return [(ip, mac) for ip, mac in discovered.items()]
