"""
hidden_ssid.py
sniffs 802.11 beacon frames and probe responses to find hidden SSIDs
hidden networks still broadcast beacon frames, just with an empty SSID field
but devices that connect to them reveal the name in probe requests/responses
requires wifi adapter in monitor mode
"""

import time
import threading
from typing import Dict, Set, Optional, Callable
from datetime import datetime

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, Dot11Elt
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class HiddenSSIDDetector:
    def __init__(self, on_found: Optional[Callable] = None, iface: Optional[str] = None):
        self.on_found = on_found
        self.iface = iface
        self._hidden_bssids: Dict[str, dict] = {}  # bssid -> info
        self._known_ssids: Dict[str, str] = {}     # bssid -> ssid (once revealed)
        self._running = False
        self._lock = threading.Lock()

    def _handle_packet(self, pkt):
        if not pkt.haslayer(Dot11):
            return

        # beacon frame -- check if SSID is hidden (empty or null bytes)
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr3
            if not bssid:
                return

            ssid = ""
            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 0:  # SSID element
                        try:
                            ssid = elt.info.decode("utf-8", errors="ignore").strip()
                        except Exception:
                            ssid = ""
                        break
                    elt = elt.payload if hasattr(elt, 'payload') and elt.payload else None

            if not ssid or all(c == '\x00' for c in ssid):
                # hidden network -- record the BSSID
                with self._lock:
                    if bssid not in self._hidden_bssids:
                        self._hidden_bssids[bssid] = {
                            "bssid": bssid,
                            "ssid": None,
                            "first_seen": datetime.now().isoformat(),
                            "channel": None,
                        }
                        # try to get channel
                        try:
                            ch_elt = pkt[Dot11Elt]
                            while ch_elt:
                                if ch_elt.ID == 3:
                                    self._hidden_bssids[bssid]["channel"] = ord(ch_elt.info)
                                    break
                                ch_elt = ch_elt.payload if hasattr(ch_elt, 'payload') else None
                        except Exception:
                            pass

        # probe response -- device is responding to a connection, reveals SSID
        elif pkt.haslayer(Dot11ProbeResp):
            bssid = pkt[Dot11].addr3
            if not bssid:
                return

            if pkt.haslayer(Dot11Elt):
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 0:
                        try:
                            ssid = elt.info.decode("utf-8", errors="ignore").strip()
                            if ssid and bssid in self._hidden_bssids:
                                with self._lock:
                                    if self._hidden_bssids[bssid]["ssid"] is None:
                                        self._hidden_bssids[bssid]["ssid"] = ssid
                                        if self.on_found:
                                            self.on_found(self._hidden_bssids[bssid].copy())
                        except Exception:
                            pass
                        break
                    elt = elt.payload if hasattr(elt, 'payload') else None

        # probe request -- client device asking for a specific network by name
        elif pkt.haslayer(Dot11ProbeReq):
            if pkt.haslayer(Dot11Elt):
                try:
                    ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore").strip()
                    src = pkt[Dot11].addr2
                    if ssid and len(ssid) > 0:
                        # this device is looking for a hidden network
                        pass  # could log probe requests here
                except Exception:
                    pass

    def start(self, duration: Optional[int] = None):
        if not SCAPY_AVAILABLE:
            print("  error: scapy not installed")
            return

        self._running = True
        print("  sniffing for hidden SSIDs...")
        print("  requires wifi adapter in monitor mode")
        print("  hidden networks will be revealed when a device connects to them\n")

        try:
            sniff(
                iface=self.iface,
                prn=self._handle_packet,
                store=False,
                timeout=duration,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            print(f"  error: {e}")
            print("  tip: enable 802.11 raw packet capture in npcap settings")

    def stop(self):
        self._running = False

    def get_results(self) -> Dict:
        with self._lock:
            hidden = list(self._hidden_bssids.values())
        revealed = [h for h in hidden if h["ssid"]]
        unrevealed = [h for h in hidden if not h["ssid"]]
        return {
            "total_hidden": len(hidden),
            "revealed": revealed,
            "still_hidden": unrevealed,
        }


def run_hidden_ssid_scan(duration: int = 60, iface=None):
    """Run interactively for a given duration."""

    def on_found(info):
        print(f"\n  !! hidden SSID revealed")
        print(f"  bssid:   {info['bssid']}")
        print(f"  ssid:    {info['ssid']}")
        if info.get('channel'):
            print(f"  channel: {info['channel']}")
        print(f"  time:    {datetime.now().strftime('%H:%M:%S')}\n")

    detector = HiddenSSIDDetector(on_found=on_found, iface=iface)
    try:
        detector.start(duration=duration)
    except KeyboardInterrupt:
        detector.stop()

    results = detector.get_results()
    print(f"\n  scan complete")
    print(f"  hidden networks found: {results['total_hidden']}")
    print(f"  SSIDs revealed:        {len(results['revealed'])}")
    print(f"  still hidden:          {len(results['still_hidden'])}")

    if results["still_hidden"]:
        print("\n  unresolved hidden networks:")
        for h in results["still_hidden"]:
            ch = f"  ch{h['channel']}" if h.get("channel") else ""
            print(f"    {h['bssid']}{ch}")

    return results
