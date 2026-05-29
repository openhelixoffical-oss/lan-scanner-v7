"""
mDNS resolver — finds custom device names like "John's MacBook" or "Living Room TV"
that devices broadcast on the local network via multicast DNS (port 5353).

Works for: Apple devices, Android, Linux, smart TVs, printers, Chromecasts, etc.
"""

import socket
import struct
import time
import threading
from typing import Dict, Optional


MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353


def _build_ptr_query(ip: str) -> bytes:
    """
    Build an mDNS PTR query packet for reverse lookup.
    e.g. 192.168.1.5 -> queries 5.1.168.192.in-addr.arpa
    """
    # Reverse the IP for PTR record
    reversed_ip = ".".join(reversed(ip.split(".")))
    name = f"{reversed_ip}.in-addr.arpa"

    # DNS header: ID=0, flags=0 (standard query), 1 question
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)

    # Encode the domain name
    question = b""
    for part in name.split("."):
        encoded = part.encode()
        question += bytes([len(encoded)]) + encoded
    question += b"\x00"

    # Type PTR (12), Class IN (1)
    question += struct.pack(">HH", 12, 1)

    return header + question


def _build_any_query(hostname: str) -> bytes:
    """
    Build an mDNS ANY query for a .local hostname.
    e.g. queries "johns-macbook.local" to get its IP/name record back.
    """
    if not hostname.endswith(".local"):
        hostname += ".local"

    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)

    question = b""
    for part in hostname.rstrip(".").split("."):
        encoded = part.encode()
        question += bytes([len(encoded)]) + encoded
    question += b"\x00"

    # Type ANY (255), Class IN (1)
    question += struct.pack(">HH", 255, 1)

    return header + question


def _parse_mdns_name(data: bytes, offset: int):
    """Parse a DNS name from a packet, following pointer compression."""
    labels = []
    visited = set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Pointer compression
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            sub_name, _ = _parse_mdns_name(data, ptr)
            labels.append(sub_name)
            offset += 2
            break
        else:
            offset += 1
            label = data[offset:offset + length].decode("utf-8", errors="ignore")
            labels.append(label)
            offset += length
    return ".".join(labels), offset


def _parse_response(data: bytes) -> Optional[str]:
    """
    Parse an mDNS response and extract a PTR or A record name.
    Returns the friendly hostname if found.
    """
    try:
        if len(data) < 12:
            return None

        qdcount = struct.unpack(">H", data[4:6])[0]
        ancount = struct.unpack(">H", data[6:8])[0]

        if ancount == 0:
            return None

        offset = 12

        # Skip questions
        for _ in range(qdcount):
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1 + length
            offset += 4  # skip type + class

        # Parse answers
        for _ in range(ancount):
            if offset >= len(data):
                break

            _, offset = _parse_mdns_name(data, offset)

            if offset + 10 > len(data):
                break

            rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10

            if offset + rdlength > len(data):
                break

            rdata = data[offset:offset + rdlength]

            # PTR record — contains target hostname
            if rtype == 12:
                name, _ = _parse_mdns_name(data, offset)
                # Strip .local suffix for display
                if name.endswith(".local"):
                    name = name[:-6]
                if name:
                    return name

            # A record — the name in the question is the hostname
            elif rtype == 1 and rdlength == 4:
                pass  # handled via question name

            offset += rdlength

    except Exception:
        pass

    return None


def mdns_lookup(ip: str, timeout: float = 1.5) -> Optional[str]:
    """
    Query mDNS for the friendly name of a device at the given IP.
    Returns the name (e.g. "Johns-MacBook-Pro") or None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.settimeout(timeout)
        sock.bind(("", 0))

        query = _build_ptr_query(ip)
        sock.sendto(query, (MDNS_ADDR, MDNS_PORT))

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                if addr[0] == ip:
                    name = _parse_response(data)
                    if name:
                        sock.close()
                        return name
            except socket.timeout:
                break
            except Exception:
                break

        sock.close()
    except Exception:
        pass

    return None


def mdns_lookup_bulk(ips: list, timeout: float = 2.0) -> Dict[str, str]:
    """
    Look up mDNS names for multiple IPs in parallel.
    Returns dict of {ip: name}.
    """
    results: Dict[str, str] = {}
    lock = threading.Lock()

    def lookup_one(ip):
        name = mdns_lookup(ip, timeout=timeout)
        if name:
            with lock:
                results[ip] = name

    threads = [threading.Thread(target=lookup_one, args=(ip,), daemon=True) for ip in ips]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 0.5)

    return results
