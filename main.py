"""
ipv6_scan.py
scans for IPv6 devices on the local network using ICMPv6 neighbor discovery
most devices have IPv6 addresses even if you dont use IPv6
these are often completely unfiltered compared to IPv4
"""

import socket
import struct
import threading
import time
from typing import List, Dict, Optional
from dataclasses import dataclass

try:
    from scapy.all import (
        IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr,
        ICMPv6ND_RS, ICMPv6ND_RA, Ether, sendp, sniff, conf,
        ICMPv6EchoRequest, ICMPv6EchoReply, sr1
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# multicast address for all nodes on link
ALL_NODES_MULTICAST = "ff02::1"
ALL_ROUTERS_MULTICAST = "ff02::2"


@dataclass
class IPv6Device:
    ipv6: str
    mac: str = ""
    ipv4: str = ""      # matched from ARP table if available
    hostname: str = ""
    link_local: bool = False
    global_addr: bool = False


def _resolve_hostname_v6(ipv6: str) -> str:
    try:
        return socket.gethostbyaddr(ipv6)[0]
    except Exception:
        return ""


def scan_ipv6_link_local(iface: Optional[str] = None, timeout: float = 3.0) -> List[IPv6Device]:
    """
    Send ICMPv6 echo request to all-nodes multicast and collect responses.
    Finds all IPv6-capable devices on the local link.
    """
    if not SCAPY_AVAILABLE:
        return _scan_ipv6_fallback()

    conf.verb = 0
    devices = []
    found_ips = set()
    lock = threading.Lock()

    def handle_response(pkt):
        if pkt.haslayer(ICMPv6EchoReply):
            src = pkt[IPv6].src
            with lock:
                if src not in found_ips and src != "::1":
                    found_ips.add(src)
                    mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
                    is_link_local = src.startswith("fe80:")
                    is_global = not is_link_local and not src.startswith("fc") and not src.startswith("fd")
                    hostname = _resolve_hostname_v6(src)
                    devices.append(IPv6Device(
                        ipv6=src,
                        mac=mac,
                        hostname=hostname,
                        link_local=is_link_local,
                        global_addr=is_global,
                    ))

    # start sniffer in background
    sniffer = threading.Thread(
        target=lambda: sniff(
            iface=iface,
            filter="icmp6",
            prn=handle_response,
            timeout=timeout,
            store=False,
        ),
        daemon=True
    )
    sniffer.start()

    # ping all-nodes multicast
    try:
        pkt = Ether(dst="33:33:00:00:00:01") / IPv6(dst=ALL_NODES_MULTICAST) / ICMPv6EchoRequest()
        sendp(pkt, iface=iface, verbose=False)
    except Exception as e:
        print(f"  warning: could not send IPv6 ping -- {e}")

    sniffer.join(timeout + 0.5)
    return devices


def _scan_ipv6_fallback() -> List[IPv6Device]:
    """
    Fallback: read the OS neighbor cache (works without scapy).
    Windows: netsh interface ipv6 show neighbors
    Linux: ip -6 neigh show
    """
    import subprocess
    import platform
    import re

    devices = []
    system = platform.system().lower()

    try:
        if system == "windows":
            result = subprocess.run(
                ["netsh", "interface", "ipv6", "show", "neighbors"],
                capture_output=True, text=True, timeout=5
            )
            # parse: fe80::1%12   00-11-22-33-44-55  Reachable
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    ipv6 = parts[0].split("%")[0]  # strip interface suffix
                    mac = parts[1].replace("-", ":").lower()
                    if ":" in ipv6 and len(mac) == 17:
                        hostname = _resolve_hostname_v6(ipv6)
                        is_link_local = ipv6.startswith("fe80")
                        devices.append(IPv6Device(
                            ipv6=ipv6, mac=mac, hostname=hostname, link_local=is_link_local
                        ))
        else:
            result = subprocess.run(
                ["ip", "-6", "neigh", "show"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 5 and parts[2] == "lladdr":
                    ipv6 = parts[0]
                    mac = parts[3]
                    hostname = _resolve_hostname_v6(ipv6)
                    is_link_local = ipv6.startswith("fe80")
                    devices.append(IPv6Device(
                        ipv6=ipv6, mac=mac, hostname=hostname, link_local=is_link_local
                    ))
    except Exception as e:
        print(f"  ipv6 fallback error: {e}")

    return devices


def scan_ipv6(iface: Optional[str] = None) -> List[IPv6Device]:
    """Main entry point. Tries active scan first, falls back to neighbor cache."""
    if SCAPY_AVAILABLE:
        devices = scan_ipv6_link_local(iface=iface)
        if devices:
            return devices
    return _scan_ipv6_fallback()


def print_ipv6_results(devices: List[IPv6Device], console=None):
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
        if console is None:
            console = Console()

        if not devices:
            console.print("  [dim]no IPv6 devices found[/dim]")
            return

        table = Table(
            title=f"[dim]{len(devices)} IPv6 devices[/dim]",
            title_justify="left",
            box=box.SIMPLE_HEAD,
            header_style="bold",
            border_style="dim",
            expand=True,
            padding=(0, 1),
        )
        table.add_column("ipv6 address", min_width=30)
        table.add_column("mac", style="dim", min_width=18)
        table.add_column("hostname", min_width=20)
        table.add_column("type", min_width=12)

        for d in devices:
            addr_type = "link-local" if d.link_local else "global" if d.global_addr else "other"
            color = "dim" if d.link_local else "cyan"
            table.add_row(
                f"[{color}]{d.ipv6}[/{color}]",
                d.mac or "[dim]--[/dim]",
                d.hostname or "[dim]--[/dim]",
                addr_type,
            )

        console.print(table)
    except ImportError:
        for d in devices:
            print(f"  {d.ipv6}  {d.mac}  {d.hostname}")
