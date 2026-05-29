import urllib.request
import json
import os


CACHE_FILE = os.path.join(os.path.dirname(__file__), "oui_cache.json")


class VendorLookup:
    def __init__(self):
        self._cache: dict = {}
        self._oui_map: dict = self._load_builtin()

    def _load_builtin(self):
        """Large built-in OUI table."""
        return {
            # Routers / Networking
            "C0:4A:00": "TP-Link", "54:E6:FC": "TP-Link", "18:D6:C7": "TP-Link",
            "E8:DE:27": "TP-Link", "50:C7:BF": "TP-Link", "B0:BE:76": "TP-Link",
            "00:1C:F0": "Netgear", "20:0C:C8": "Netgear", "00:14:6C": "Netgear",
            "00:18:E7": "Netgear", "A0:40:A0": "Netgear", "9C:3D:CF": "Netgear",
            "00:23:EB": "Cisco", "00:1B:D4": "Cisco", "00:0F:66": "Cisco",
            "FC:FB:FB": "Cisco", "00:17:0F": "Cisco", "58:BC:27": "Cisco",
            "00:26:18": "D-Link", "1C:7E:E5": "D-Link", "B0:C5:54": "D-Link",
            "5C:96:9D": "Netgear", "00:1A:2B": "Ubiquiti", "04:18:D6": "Ubiquiti",
            "24:A4:3C": "Ubiquiti", "78:8A:20": "Ubiquiti",
            # Apple
            "00:17:F2": "Apple", "00:1C:B3": "Apple", "00:1D:4F": "Apple",
            "00:21:E9": "Apple", "00:25:4B": "Apple", "3C:07:54": "Apple",
            "AC:BC:32": "Apple", "F8:1E:DF": "Apple", "A4:C3:F0": "Apple",
            "1C:36:BB": "Apple", "8C:85:90": "Apple", "DC:2B:2A": "Apple",
            "00:3E:E1": "Apple", "04:52:F3": "Apple", "0C:74:C2": "Apple",
            "10:40:F3": "Apple", "14:8F:C6": "Apple", "18:65:90": "Apple",
            "20:78:F0": "Apple", "28:CF:E9": "Apple", "34:12:98": "Apple",
            "38:F9:D3": "Apple", "40:6C:8F": "Apple", "44:2A:60": "Apple",
            "48:43:7C": "Apple", "54:26:96": "Apple", "58:B0:35": "Apple",
            "60:C5:47": "Apple", "64:A3:CB": "Apple", "6C:40:08": "Apple",
            "70:EC:E4": "Apple", "74:E1:B6": "Apple", "78:7B:8A": "Apple",
            "7C:6D:62": "Apple", "80:92:9F": "Apple", "84:38:35": "Apple",
            "88:19:08": "Apple", "90:3C:92": "Apple", "94:BF:2D": "Apple",
            "98:FE:94": "Apple", "9C:F4:8E": "Apple", "A8:20:66": "Apple",
            "B8:53:AC": "Apple", "BC:52:B7": "Apple", "C0:CE:CD": "Apple",
            "C8:2A:14": "Apple", "CC:08:8D": "Apple", "D0:23:DB": "Apple",
            # Samsung
            "00:25:86": "Samsung", "94:35:0A": "Samsung", "78:52:1A": "Samsung",
            "80:57:19": "Samsung", "00:15:99": "Samsung", "30:19:66": "Samsung",
            "8C:71:F8": "Samsung", "A0:07:98": "Samsung", "CC:07:AB": "Samsung",
            "F0:25:B7": "Samsung", "1C:62:B8": "Samsung", "50:85:69": "Samsung",
            "70:F9:27": "Samsung", "84:25:DB": "Samsung", "BC:20:A4": "Samsung",
            # Google
            "00:1A:11": "Google", "54:60:09": "Google", "F4:F5:D8": "Google",
            "3C:5A:B4": "Google", "A4:77:33": "Google", "48:D6:D5": "Google",
            # Amazon
            "00:BB:3A": "Amazon", "44:65:0D": "Amazon", "74:75:48": "Amazon",
            "A0:02:DC": "Amazon", "34:D2:70": "Amazon", "F0:D2:F1": "Amazon",
            "FC:65:DE": "Amazon", "00:FC:8B": "Amazon",
            # Raspberry Pi
            "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
            "28:CD:C1": "Raspberry Pi",
            # Microsoft
            "00:50:F2": "Microsoft", "28:18:78": "Microsoft", "7C:1E:52": "Microsoft",
            "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft",
            # Sony
            "00:1B:63": "Sony", "00:13:A9": "Sony", "00:04:1F": "Sony",
            "30:17:C8": "Sony", "AC:9B:0A": "Sony",
            # ASUS
            "00:1D:0F": "ASUS", "04:92:26": "ASUS", "10:02:B5": "ASUS",
            "2C:FD:A1": "ASUS", "50:46:5D": "ASUS", "AC:22:0B": "ASUS",
            # Espressif (IoT)
            "18:FE:34": "Espressif (IoT)", "24:6F:28": "Espressif (IoT)",
            "30:AE:A4": "Espressif (IoT)", "3C:61:05": "Espressif (IoT)",
            "48:3F:DA": "Espressif (IoT)", "68:C6:3A": "Espressif (IoT)",
            "84:0D:8E": "Espressif (IoT)", "A4:CF:12": "Espressif (IoT)",
            "B4:E6:2D": "Espressif (IoT)", "CC:50:E3": "Espressif (IoT)",
            # VMware / VirtualBox
            "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
            "08:00:27": "VirtualBox",
            # HP
            "D8:80:83": "HP", "3C:D9:2B": "HP", "9C:8E:99": "HP",
            "94:57:A5": "HP", "00:1F:29": "HP", "00:21:5A": "HP",
            # Dell
            "00:14:22": "Dell", "18:03:73": "Dell", "B0:83:FE": "Dell",
            "F8:DB:88": "Dell", "00:1E:4F": "Dell",
            # Lenovo
            "00:AA:70": "Lenovo", "04:7D:7B": "Lenovo", "28:D2:44": "Lenovo",
            "54:05:DB": "Lenovo", "60:02:92": "Lenovo",
            # Xiaomi
            "00:9E:C8": "Xiaomi", "10:2A:B3": "Xiaomi", "28:6C:07": "Xiaomi",
            "34:CE:00": "Xiaomi", "50:8F:4C": "Xiaomi", "58:44:98": "Xiaomi",
            "64:09:80": "Xiaomi", "74:23:44": "Xiaomi", "8C:BE:BE": "Xiaomi",
            # Nintendo
            "00:09:BF": "Nintendo", "00:17:AB": "Nintendo", "00:19:FD": "Nintendo",
            "00:1B:EA": "Nintendo", "00:1E:35": "Nintendo", "00:1F:32": "Nintendo",
            # Philips Hue / Smart home
            "00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue",
            "AC:67:B2": "Shelly (IoT)", "E8:DB:84": "Shelly (IoT)",
            "D8:F1:5B": "Belkin/Wemo", "00:1A:80": "Belkin",
        }

    def lookup(self, mac: str) -> str:
        if not mac or mac == "N/A":
            return "Unknown"

        mac_upper = mac.upper().replace("-", ":")
        oui = ":".join(mac_upper.split(":")[:3])

        if oui in self._cache:
            return self._cache[oui]

        vendor = self._oui_map.get(oui, "Unknown")
        self._cache[oui] = vendor
        return vendor
