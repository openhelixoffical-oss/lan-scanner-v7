"""
deep_scan.py - actually grabs info from open ports instead of just checking if theyre open
does banner grabbing, http probing, upnp discovery, ssh version, snmp, smb info
"""

import socket
import struct
import urllib.request
import urllib.error
import ssl
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple


# ports to check -- expanded list
PORTS = {
    # web
    80:    "http",
    443:   "https",
    8080:  "http-alt",
    8443:  "https-alt",
    8888:  "http-alt",
    8081:  "http-alt",
    8181:  "http-alt",
    3000:  "http-dev",
    4000:  "http-dev",
    5000:  "http-dev",
    7080:  "http-alt",
    # remote access
    22:    "ssh",
    23:    "telnet",
    3389:  "rdp",
    5900:  "vnc",
    5901:  "vnc",
    # file sharing
    21:    "ftp",
    445:   "smb",
    139:   "netbios-ssn",
    2049:  "nfs",
    548:   "afp",
    # network services
    53:    "dns",
    67:    "dhcp",
    68:    "dhcp",
    161:   "snmp",
    # printing
    9100:  "printer-raw",
    515:   "printer-lpd",
    631:   "ipp",
    # iot / smart home
    1883:  "mqtt",
    8883:  "mqtt-ssl",
    1900:  "upnp",
    5353:  "mdns",
    # media / casting
    7000:  "airplay",
    7100:  "airplay-alt",
    554:   "rtsp",
    8060:  "roku",
    8008:  "chromecast",
    8009:  "chromecast-alt",
    # databases (might be a server)
    3306:  "mysql",
    5432:  "postgres",
    6379:  "redis",
    27017: "mongodb",
    # misc
    25:    "smtp",
    110:   "pop3",
    143:   "imap",
    993:   "imaps",
    6881:  "bittorrent",
    32400: "plex",
    8096:  "jellyfin",
    9090:  "prometheus",
    9091:  "transmission",
}


def scan_ports(ip: str, timeout: float = 0.4) -> Dict[int, str]:
    """Returns dict of {port: service_name} for open ports."""
    open_ports = {}

    def check(port: int) -> Tuple[int, bool]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            return port, result == 0
        except Exception:
            return port, False

    with ThreadPoolExecutor(max_workers=50) as ex:
        for port, is_open in ex.map(lambda p: check(p), PORTS.keys()):
            if is_open:
                open_ports[port] = PORTS[port]

    return open_ports


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Connect to a port and read whatever it sends back."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # some services need a nudge
        if port in (21, 22, 23, 25, 110, 143):
            pass  # they send banner on connect
        else:
            s.send(b"\r\n")
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        # clean up
        banner = " ".join(banner.splitlines()[:2])[:120]
        return banner if banner else None
    except Exception:
        return None


def probe_http(ip: str, port: int, https: bool = False) -> Dict:
    """Make an HTTP request and pull out useful info."""
    result = {}
    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}:{port}/"

    try:
        ctx = ssl.create_default_context() if https else None
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=3, context=ctx)
        html = resp.read(8192).decode("utf-8", errors="ignore")

        # server header
        server = resp.headers.get("Server", "")
        if server:
            result["server"] = server[:60]

        # page title
        match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()[:80]
            title = re.sub(r"\s+", " ", title)
            if title:
                result["title"] = title

        # powered-by header
        powered = resp.headers.get("X-Powered-By", "")
        if powered:
            result["powered_by"] = powered[:40]

        # sniff for common admin panels / devices from html
        html_lower = html.lower()
        hints = []
        panels = {
            "luci": "OpenWrt router",
            "openwrt": "OpenWrt router",
            "dd-wrt": "DD-WRT router",
            "tomato": "Tomato router",
            "synology": "Synology NAS",
            "qnap": "QNAP NAS",
            "plex": "Plex Media Server",
            "jellyfin": "Jellyfin",
            "pihole": "Pi-hole",
            "homeassistant": "Home Assistant",
            "home assistant": "Home Assistant",
            "proxmox": "Proxmox VE",
            "truenas": "TrueNAS",
            "freenas": "FreeNAS",
            "unifi": "Ubiquiti UniFi",
            "mikrotik": "MikroTik",
            "esphome": "ESPHome IoT",
            "tasmota": "Tasmota IoT",
            "transmission": "Transmission torrent",
            "qbittorrent": "qBittorrent",
            "nextcloud": "Nextcloud",
            "grafana": "Grafana",
            "portainer": "Portainer (Docker)",
            "nginx": "Nginx",
            "apache": "Apache",
            "iis": "IIS (Windows Server)",
            "camera": "IP Camera",
            "hikvision": "Hikvision Camera",
            "dahua": "Dahua Camera",
            "router": "Router admin panel",
            "gateway": "Gateway admin panel",
        }
        for keyword, label in panels.items():
            if keyword in html_lower:
                hints.append(label)
                break  # one is enough

        if hints:
            result["detected"] = hints[0]

    except urllib.error.HTTPError as e:
        result["http_status"] = e.code
    except Exception:
        pass

    return result


def probe_upnp(ip: str, timeout: float = 2.0) -> Dict:
    """
    Send UPnP/SSDP discovery and fetch device description XML.
    Gets manufacturer, model name, friendly name etc.
    """
    result = {}

    # Send M-SEARCH to the device directly
    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {ip}:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 1\r\n"
        "ST: upnp:rootdevice\r\n"
        "\r\n"
    ).encode()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(ssdp_request, (ip, 1900))
        data, _ = s.recvfrom(4096)
        s.close()
        response = data.decode("utf-8", errors="ignore")

        # Extract LOCATION header (points to XML description)
        loc_match = re.search(r"LOCATION:\s*(\S+)", response, re.IGNORECASE)
        if loc_match:
            location = loc_match.group(1).strip()
            result["upnp_location"] = location

            # Fetch the XML description
            try:
                req = urllib.request.Request(location, headers={"User-Agent": "Mozilla/5.0"})
                xml_resp = urllib.request.urlopen(req, timeout=3)
                xml = xml_resp.read(8192).decode("utf-8", errors="ignore")

                for tag, key in [
                    ("friendlyName", "friendly_name"),
                    ("manufacturer", "manufacturer"),
                    ("modelName", "model_name"),
                    ("modelNumber", "model_number"),
                    ("modelDescription", "model_desc"),
                ]:
                    match = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.IGNORECASE)
                    if match:
                        val = match.group(1).strip()[:80]
                        if val:
                            result[key] = val
            except Exception:
                pass

    except Exception:
        pass

    return result


def probe_snmp(ip: str, timeout: float = 1.5) -> Optional[str]:
    """
    Send SNMPv1 GetRequest for sysDescr (OID 1.3.6.1.2.1.1.1.0).
    Returns system description string if device responds.
    Most routers, switches, and network gear respond to this.
    """
    try:
        # Build SNMPv1 GetRequest packet for sysDescr
        def encode_oid(oid_str):
            parts = list(map(int, oid_str.split(".")))
            encoded = bytes([40 * parts[0] + parts[1]])
            for part in parts[2:]:
                if part < 128:
                    encoded += bytes([part])
                else:
                    # multi-byte encoding
                    b = []
                    while part > 0:
                        b.append(part & 0x7F)
                        part >>= 7
                    b.reverse()
                    for i, byte in enumerate(b):
                        if i < len(b) - 1:
                            encoded += bytes([byte | 0x80])
                        else:
                            encoded += bytes([byte])
            return encoded

        def tlv(tag, value):
            if len(value) < 128:
                return bytes([tag, len(value)]) + value
            else:
                length_bytes = len(value).to_bytes(2, "big")
                return bytes([tag, 0x82]) + length_bytes + value

        community = b"public"
        oid = encode_oid("1.3.6.1.2.1.1.1.0")
        oid_tlv = tlv(0x06, oid)
        null = bytes([0x05, 0x00])
        varbind = tlv(0x30, oid_tlv + null)
        varbind_list = tlv(0x30, varbind)
        request_id = bytes([0x02, 0x04, 0x00, 0x00, 0x00, 0x01])
        error_status = bytes([0x02, 0x01, 0x00])
        error_index = bytes([0x02, 0x01, 0x00])
        pdu = tlv(0xA0, request_id + error_status + error_index + varbind_list)
        version = bytes([0x02, 0x01, 0x00])
        community_tlv = tlv(0x04, community)
        packet = tlv(0x30, version + community_tlv + pdu)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(packet, (ip, 161))
        data, _ = s.recvfrom(4096)
        s.close()

        # Find the OctetString value in the response (tag 0x04)
        i = 0
        while i < len(data) - 1:
            if data[i] == 0x04 and data[i+1] > 0:
                length = data[i+1]
                if i + 2 + length <= len(data):
                    desc = data[i+2:i+2+length].decode("utf-8", errors="ignore").strip()
                    if len(desc) > 5:
                        return desc[:200]
            i += 1

    except Exception:
        pass
    return None


def probe_mdns_services(ip: str, timeout: float = 2.0) -> List[str]:
    """
    Query mDNS to discover what services a device is advertising.
    e.g. _airplay._tcp, _homekit._tcp, _smb._tcp, _ssh._tcp
    """
    services = []
    service_types = [
        "_airplay._tcp.local.",
        "_homekit._tcp.local.",
        "_raop._tcp.local.",
        "_smb._tcp.local.",
        "_ssh._tcp.local.",
        "_http._tcp.local.",
        "_printer._tcp.local.",
        "_ipp._tcp.local.",
        "_afpovertcp._tcp.local.",
        "_companion-link._tcp.local.",
        "_sleep-proxy._udp.local.",
        "_googlecast._tcp.local.",
        "_spotify-connect._tcp.local.",
        "_plex._tcp.local.",
        "_home-sharing._tcp.local.",
    ]

    friendly_names = {
        "_airplay._tcp.local.": "AirPlay",
        "_homekit._tcp.local.": "HomeKit",
        "_raop._tcp.local.": "AirPlay Audio",
        "_smb._tcp.local.": "SMB/Files",
        "_ssh._tcp.local.": "SSH",
        "_http._tcp.local.": "HTTP",
        "_printer._tcp.local.": "Printer",
        "_ipp._tcp.local.": "IPP Printer",
        "_afpovertcp._tcp.local.": "AFP/Files",
        "_companion-link._tcp.local.": "Apple Companion",
        "_googlecast._tcp.local.": "Chromecast",
        "_spotify-connect._tcp.local.": "Spotify Connect",
        "_plex._tcp.local.": "Plex",
        "_home-sharing._tcp.local.": "iTunes Sharing",
    }

    def query_service(service_type: str) -> Optional[str]:
        try:
            # Build mDNS PTR query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            sock.settimeout(0.8)
            sock.bind(("", 0))

            # DNS query packet
            header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
            question = b""
            for part in service_type.rstrip(".").split("."):
                encoded = part.encode()
                question += bytes([len(encoded)]) + encoded
            question += b"\x00"
            question += struct.pack(">HH", 12, 1)  # PTR, IN
            packet = header + question

            sock.sendto(packet, ("224.0.0.251", 5353))

            deadline = __import__("time").time() + 0.8
            while __import__("time").time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    if addr[0] == ip:
                        sock.close()
                        return friendly_names.get(service_type)
                except socket.timeout:
                    break
                except Exception:
                    break
            sock.close()
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        for result in ex.map(query_service, service_types):
            if result:
                services.append(result)

    return services


def deep_scan(ip: str) -> Dict:
    """
    Run a full deep scan on a device.
    Returns a dict with all gathered info.
    """
    info = {}

    # 1. Port scan
    open_ports = scan_ports(ip)
    info["open_ports"] = open_ports

    # 2. Banner grab common ports
    banners = {}
    banner_ports = [p for p in open_ports if p in (21, 22, 23, 25, 80, 110, 143, 443, 8080)]
    for port in banner_ports:
        banner = grab_banner(ip, port)
        if banner:
            banners[port] = banner
    if banners:
        info["banners"] = banners

    # 3. HTTP probe any web ports
    http_info = {}
    for port, service in open_ports.items():
        if service in ("http", "http-alt", "http-dev", "roku", "chromecast"):
            result = probe_http(ip, port, https=False)
            if result:
                http_info[port] = result
        elif service in ("https", "https-alt"):
            result = probe_http(ip, port, https=True)
            if result:
                http_info[port] = result
    if http_info:
        info["http"] = http_info

    # 4. UPnP probe
    if 1900 in open_ports:
        upnp = probe_upnp(ip)
        if upnp:
            info["upnp"] = upnp

    # 5. SNMP probe
    snmp_desc = probe_snmp(ip)
    if snmp_desc:
        info["snmp_desc"] = snmp_desc

    # 6. mDNS service discovery
    mdns_services = probe_mdns_services(ip)
    if mdns_services:
        info["mdns_services"] = mdns_services

    return info


def summarize_deep_scan(info: Dict) -> Tuple[str, List[str]]:
    """
    Returns (device_type_guess, list_of_detail_strings) from deep scan results.
    """
    details = []
    device_type = None
    open_ports = info.get("open_ports", {})

    # banners
    banners = info.get("banners", {})
    for port, banner in banners.items():
        service = open_ports.get(port, str(port))
        if banner:
            details.append(f"port {port} ({service}): {banner}")

    # http info
    http = info.get("http", {})
    for port, hinfo in http.items():
        parts = []
        if "detected" in hinfo:
            parts.append(hinfo["detected"])
            if not device_type:
                device_type = hinfo["detected"]
        if "title" in hinfo:
            parts.append(f'title: "{hinfo["title"]}"')
        if "server" in hinfo:
            parts.append(f'server: {hinfo["server"]}')
        if parts:
            details.append(f"port {port} (http): " + "  |  ".join(parts))

    # upnp
    upnp = info.get("upnp", {})
    if upnp:
        upnp_parts = []
        if "friendly_name" in upnp:
            upnp_parts.append(upnp["friendly_name"])
            if not device_type:
                device_type = upnp["friendly_name"]
        if "model_name" in upnp:
            upnp_parts.append(f'model: {upnp["model_name"]}')
        if "manufacturer" in upnp:
            upnp_parts.append(f'by {upnp["manufacturer"]}')
        if upnp_parts:
            details.append("upnp: " + "  |  ".join(upnp_parts))

    # snmp
    snmp = info.get("snmp_desc", "")
    if snmp:
        details.append(f"snmp: {snmp[:120]}")
        if not device_type:
            device_type = snmp.split("\n")[0][:60]

    # mdns services
    mdns_services = info.get("mdns_services", [])
    if mdns_services:
        details.append("services: " + ", ".join(mdns_services))

    # open port summary
    if open_ports:
        port_list = ", ".join(
            f"{p}({s})" for p, s in sorted(open_ports.items())[:12]
        )
        details.append(f"open ports: {port_list}")

    return device_type or "", details
