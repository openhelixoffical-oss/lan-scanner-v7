import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict


PORT_SIGNATURES: Dict[int, str] = {
    80:    "http",
    443:   "https",
    8080:  "http-alt",
    8443:  "https-alt",
    22:    "ssh",
    23:    "telnet",
    21:    "ftp",
    25:    "smtp",
    53:    "dns",
    67:    "dhcp",
    445:   "smb",
    139:   "netbios",
    3389:  "rdp",
    5900:  "vnc",
    9100:  "printer",
    515:   "printer-lpd",
    631:   "ipp-printer",
    1883:  "mqtt",
    8883:  "mqtt-ssl",
    5353:  "mdns",
    1900:  "upnp",
    7000:  "airplay",
    7100:  "airplay",
    554:   "rtsp",
    3000:  "dev-server",
    4000:  "dev-server",
    5000:  "dev-server",
    8000:  "dev-server",
}

DEVICE_RULES = [
    (["dns", "dhcp", "http"],   "Router"),
    (["dns", "http"],            "Router"),
    (["telnet", "http"],         "Router"),
    (["printer"],                "Printer"),
    (["printer-lpd"],            "Printer"),
    (["ipp-printer"],            "Printer"),
    (["smb", "rdp"],             "Windows PC"),
    (["smb", "netbios"],         "Windows PC"),
    (["rdp"],                    "Windows PC"),
    (["smb"],                    "Windows PC"),
    (["rtsp", "upnp"],           "Smart TV"),
    (["upnp", "http"],           "Smart TV"),
    (["rtsp"],                   "Media Device"),
    (["airplay"],                "Apple Device"),
    (["mqtt"],                   "IoT Device"),
    (["mqtt-ssl"],               "IoT Device"),
    (["ssh", "http"],            "Linux Server"),
    (["ssh"],                    "Linux/Pi"),
    (["smb", "ftp"],             "NAS/Server"),
    (["ftp"],                    "File Server"),
    (["dev-server"],             "Dev Server"),
    (["https"],                  "Web Server"),
    (["http"],                   "Web Server"),
]

VENDOR_TYPES = {
    "Apple":           "Apple Device",
    "Samsung":         "Android/Samsung",
    "Xiaomi":          "Android/Xiaomi",
    "Google":          "Google Device",
    "Amazon":          "Amazon Device",
    "Raspberry Pi":    "Raspberry Pi",
    "Espressif (IoT)": "IoT Device",
    "Shelly (IoT)":    "IoT Device",
    "Philips Hue":     "Smart Light",
    "Nintendo":        "Game Console",
    "Sony":            "Sony Device",
    "TP-Link":         "Router/AP",
    "Netgear":         "Router/AP",
    "Cisco":           "Network Device",
    "Ubiquiti":        "Network Device",
    "D-Link":          "Router/AP",
    "HP":              "HP Device",
    "Dell":            "Dell PC",
    "Lenovo":          "Lenovo PC",
    "ASUS":            "ASUS Device",
    "Microsoft":       "Microsoft Device",
    "VMware":          "VM",
    "VirtualBox":      "VM",
}


def scan_ports(ip: str, timeout: float = 0.5) -> List[str]:
    open_services = []

    def check_port(port: int) -> Tuple[int, bool]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            return port, result == 0
        except Exception:
            return port, False

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_port, port): port for port in PORT_SIGNATURES}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_services.append(PORT_SIGNATURES[port])

    return open_services


def guess_device_type(open_services: List[str], vendor: str, os_guess: str, hostname: str) -> str:
    service_set = set(open_services)
    for required_services, device_type in DEVICE_RULES:
        if all(s in service_set for s in required_services):
            return device_type

    for vendor_key, device_type in VENDOR_TYPES.items():
        if vendor_key.lower() in vendor.lower():
            return device_type

    hostname_lower = hostname.lower()
    if "router" in hostname_lower or "gateway" in hostname_lower:
        return "Router"
    if "iphone" in hostname_lower:
        return "iPhone"
    if "ipad" in hostname_lower:
        return "iPad"
    if "android" in hostname_lower:
        return "Android"
    if "macbook" in hostname_lower:
        return "MacBook"
    if "imac" in hostname_lower:
        return "iMac"
    if "printer" in hostname_lower:
        return "Printer"
    if "tv" in hostname_lower or "roku" in hostname_lower:
        return "Smart TV"
    if "nas" in hostname_lower or "synology" in hostname_lower:
        return "NAS"
    if "pi" in hostname_lower or "raspberry" in hostname_lower:
        return "Raspberry Pi"

    if os_guess == "Windows":
        return "Windows PC"
    if os_guess == "macOS / iOS":
        return "Apple Device"
    if os_guess == "Linux / Android":
        return "Linux/Android"

    return "unknown"


def get_open_ports_summary(open_services: List[str]) -> str:
    if not open_services:
        return "none"
    seen = []
    for s in open_services:
        if s not in seen:
            seen.append(s)
    return ", ".join(seen[:5]) + ("..." if len(seen) > 5 else "")
