import socket
import time
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set, Dict

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .vendor import VendorLookup
from .fingerprint import guess_device_type
from .mdns import mdns_lookup_bulk
from .deep_scan import deep_scan, summarize_deep_scan


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str = "unknown"
    mdns_name: str = ""
    netbios_name: str = ""
    vendor: str = "unknown"
    label: str = ""
    device_type: str = "unknown"
    open_ports: Dict = field(default_factory=dict)
    deep_details: List[str] = field(default_factory=list)
    mdns_services: List[str] = field(default_factory=list)
    last_seen: datetime = field(default_factory=datetime.now)
    first_seen: datetime = field(default_factory=datetime.now)
    ttl: Optional[int] = None
    seen_count: int = 1

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "mdns_name": self.mdns_name,
            "netbios_name": self.netbios_name,
            "vendor": self.vendor,
            "label": self.label,
            "device_type": self.device_type,
            "open_ports": {str(k): v for k, v in self.open_ports.items()},
            "deep_details": self.deep_details,
            "mdns_services": self.mdns_services,
            "last_seen": self.last_seen.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "ttl": self.ttl,
            "seen_count": self.seen_count,
        }

    def os_guess(self) -> str:
        if self.ttl is None:
            return "unknown"
        if self.ttl <= 64:
            return "linux/android"
        elif self.ttl <= 128:
            return "windows"
        elif self.ttl <= 255:
            return "macos/ios"
        return "unknown"

    def best_name(self) -> str:
        if self.label:
            return self.label
        if self.mdns_name:
            return self.mdns_name.replace("-", " ").replace(".local", "").strip()
        if self.netbios_name:
            return self.netbios_name
        if self.hostname and self.hostname != "unknown":
            return self.hostname
        return ""


class Scanner:
    def __init__(self, ip_range: Optional[str] = None, deep: bool = False):
        self.ip_range = ip_range or self._detect_ip_range()
        self.vendor_lookup = VendorLookup()
        self.deep = deep

    def _detect_ip_range(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.rsplit(".", 1)
            return f"{parts[0]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def scan(self) -> List[Device]:
        if SCAPY_AVAILABLE:
            return self._scan_scapy()
        return self._scan_fallback()

    def _scan_scapy(self) -> List[Device]:
        conf.verb = 0
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip_range),
            timeout=3, retry=1
        )

        raw_devices = [(r.psrc, r.hwsrc) for _, r in answered]
        all_ips = [ip for ip, _ in raw_devices]
        mdns_names = mdns_lookup_bulk(all_ips, timeout=2.0)

        devices = []
        for ip, mac in raw_devices:
            hostname = self._resolve_hostname(ip)
            netbios_name = self._netbios_lookup(ip) or ""
            mdns_name = mdns_names.get(ip, "")
            vendor = self.vendor_lookup.lookup(mac)
            ttl = self._get_ttl(ip)
            os_g = self._ttl_to_os(ttl)
            best_hostname = mdns_name or netbios_name or hostname

            open_ports = {}
            deep_details = []
            mdns_services = []
            device_type = guess_device_type([], vendor, os_g, best_hostname)

            if self.deep:
                info = deep_scan(ip)
                open_ports = info.get("open_ports", {})
                mdns_services = info.get("mdns_services", [])
                deep_type, deep_details = summarize_deep_scan(info)
                # deep scan type overrides basic guess if it found something
                if deep_type:
                    device_type = deep_type
                else:
                    # re-guess with port info
                    services = list(open_ports.values())
                    device_type = guess_device_type(services, vendor, os_g, best_hostname)

            devices.append(Device(
                ip=ip, mac=mac,
                hostname=hostname,
                mdns_name=mdns_name,
                netbios_name=netbios_name,
                vendor=vendor,
                device_type=device_type,
                open_ports=open_ports,
                deep_details=deep_details,
                mdns_services=mdns_services,
                ttl=ttl,
            ))

        return sorted(devices, key=lambda d: list(map(int, d.ip.split("."))))

    def _scan_fallback(self) -> List[Device]:
        import subprocess, platform
        devices = []
        network = ipaddress.IPv4Network(self.ip_range, strict=False)
        for host in network.hosts():
            ip = str(host)
            param = "-n" if platform.system().lower() == "windows" else "-c"
            try:
                result = subprocess.run(
                    ["ping", param, "1", "-w", "500", ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1
                )
                if result.returncode == 0:
                    hostname = self._resolve_hostname(ip)
                    mdns_name = mdns_lookup_bulk([ip]).get(ip, "")
                    best = mdns_name or hostname
                    device_type = guess_device_type([], "unknown", "?", best)
                    devices.append(Device(ip=ip, mac="N/A", hostname=hostname,
                                          mdns_name=mdns_name, device_type=device_type))
            except Exception:
                continue
        return devices

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "unknown"

    def _netbios_lookup(self, ip: str) -> Optional[str]:
        try:
            import subprocess
            result = subprocess.run(["nbtstat", "-A", ip],
                capture_output=True, text=True, timeout=3)
            for line in result.stdout.splitlines():
                if "<00>" in line and "UNIQUE" in line:
                    name = line.strip().split()[0]
                    if name and name != ip:
                        return name
        except Exception:
            pass
        return None

    def _ttl_to_os(self, ttl: Optional[int]) -> str:
        if ttl is None:
            return "unknown"
        if ttl <= 64:
            return "linux/android"
        elif ttl <= 128:
            return "windows"
        elif ttl <= 255:
            return "macos/ios"
        return "unknown"

    def _get_ttl(self, ip: str) -> Optional[int]:
        import subprocess, platform, re
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            result = subprocess.run(["ping", param, "1", ip],
                capture_output=True, text=True, timeout=2)
            match = re.search(r"[Tt][Tt][Ll]=(\d+)", result.stdout)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None

    def watch(self, interval: int = 30, on_scan=None, on_new_device=None):
        first = True
        known_macs: Set[str] = set()
        while True:
            devices = self.scan()
            new_devices = []
            for device in devices:
                if device.mac == "N/A":
                    continue
                if device.mac not in known_macs:
                    if not first:
                        new_devices.append(device)
                        if on_new_device:
                            on_new_device(device)
                    known_macs.add(device.mac)
            first = False
            if on_scan:
                on_scan(devices, new_devices)
            time.sleep(interval)
