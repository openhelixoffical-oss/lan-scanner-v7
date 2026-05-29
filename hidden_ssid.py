"""
frag_scan.py
sends fragmented IP packets to bypass simple packet filters and firewalls
some firewalls only inspect the first fragment and miss the TCP header in later ones
can reveal ports that are hidden from normal scans
requires scapy + admin
"""

from typing import List, Optional

try:
    from scapy.all import IP, TCP, fragment, sr, conf, RandShort
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ports to check in frag scan -- focus on ones firewalls commonly block
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 137, 138, 139,
    143, 443, 445, 993, 995, 1433, 1723, 3306, 3389,
    5900, 8080, 8443
]


def frag_port_scan(target_ip: str, ports: Optional[List[int]] = None,
                   frag_size: int = 8, timeout: float = 2.0) -> List[int]:
    """
    SYN scan using fragmented packets.
    frag_size: bytes per fragment (smaller = more fragments = harder to reassemble for simple filters)
    Returns list of open ports.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy required for fragmented scanning")

    if ports is None:
        ports = DEFAULT_PORTS

    conf.verb = 0
    open_ports = []

    for port in ports:
        try:
            sport = int(RandShort())
            # build a SYN packet
            pkt = IP(dst=target_ip) / TCP(sport=sport, dport=port, flags="S", seq=1000)
            # fragment it
            frags = fragment(pkt, fragsize=frag_size)
            # send all fragments and collect responses
            answered, _ = sr(frags, timeout=timeout, verbose=False, retry=0)

            for _, resp in answered:
                if resp.haslayer(TCP):
                    if resp[TCP].flags & 0x12 == 0x12:  # SYN-ACK
                        open_ports.append(port)
                        # send RST
                        rst = IP(dst=target_ip) / TCP(
                            sport=sport, dport=port, flags="R", seq=1001
                        )
                        conf.L3socket().send(rst)
                        break

        except Exception:
            continue

    return open_ports


def compare_with_normal(target_ip: str, ports: Optional[List[int]] = None) -> dict:
    """
    Run both a normal SYN scan and a fragmented scan and compare results.
    Ports only found in frag scan = hidden behind a simple filter.
    Returns {
        "normal_open": [...],
        "frag_open": [...],
        "hidden": [...],   # only in frag scan
        "filtered": [...], # only in normal scan (weird, but possible)
    }
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy required")

    if ports is None:
        ports = DEFAULT_PORTS

    conf.verb = 0

    # normal scan
    normal_open = []
    for port in ports:
        try:
            sport = int(RandShort())
            pkt = IP(dst=target_ip) / TCP(sport=sport, dport=port, flags="S")
            resp = conf.L3socket().sr1(pkt, timeout=1, verbose=False)
            if resp and resp.haslayer(TCP) and resp[TCP].flags & 0x12 == 0x12:
                normal_open.append(port)
                rst = IP(dst=target_ip) / TCP(sport=sport, dport=port, flags="R")
                conf.L3socket().send(rst)
        except Exception:
            continue

    # fragmented scan
    frag_open = frag_port_scan(target_ip, ports)

    normal_set = set(normal_open)
    frag_set = set(frag_open)

    return {
        "normal_open": sorted(normal_open),
        "frag_open": sorted(frag_open),
        "hidden": sorted(frag_set - normal_set),
        "filtered": sorted(normal_set - frag_set),
    }


def print_frag_results(results: dict, console=None):
    try:
        from rich.console import Console
        if console is None:
            console = Console()

        console.print(f"\n  [bold]fragmented scan results[/bold]")
        console.print(f"  normal open ports:  {results['normal_open'] or 'none'}")
        console.print(f"  frag open ports:    {results['frag_open'] or 'none'}")

        if results["hidden"]:
            console.print(
                f"\n  [bold yellow]!! hidden ports found (only visible via frag scan):[/bold yellow]"
                f"  {results['hidden']}"
                f"\n  [dim]these ports are filtered by a simple firewall that only inspects the first fragment[/dim]"
            )
        else:
            console.print("  [dim]no hidden ports found -- firewall either reassembles fragments or nothing is hidden[/dim]")

    except ImportError:
        print(f"normal: {results['normal_open']}")
        print(f"frag:   {results['frag_open']}")
        print(f"hidden: {results['hidden']}")
