"""
deauth_detector.py
listens for 802.11 deauthentication frames on the network
deauth floods are used in wifi jamming / evil twin attacks
requires scapy and a wifi adapter that supports monitor mode
on windows you may need npcap with raw 802.11 support enabled
"""

import time
import threading
from collections import defaultdict
from datetime import datetime
from typing import Callable, Optional

try:
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disassoc, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# if we see more than this many deauths from one source in the time window, its an attack
DEAUTH_THRESHOLD = 5
TIME_WINDOW = 10  # seconds


class DeauthDetector:
    def __init__(self, on_alert: Optional[Callable] = None, iface: Optional[str] = None):
        self.on_alert = on_alert
        self.iface = iface
        self._counts = defaultdict(list)  # mac -> list of timestamps
        self._lock = threading.Lock()
        self._running = False
        self._alerted = set()  # dont spam the same source

    def _handle_packet(self, pkt):
        # look for deauth (type=0, subtype=12) and disassoc (type=0, subtype=10)
        if not (pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disassoc)):
            return

        src = pkt[Dot11].addr2 if pkt.haslayer(Dot11) else "unknown"
        dst = pkt[Dot11].addr1 if pkt.haslayer(Dot11) else "unknown"
        reason = None

        if pkt.haslayer(Dot11Deauth):
            reason = pkt[Dot11Deauth].reason

        now = time.time()

        with self._lock:
            # clean old timestamps outside the window
            self._counts[src] = [t for t in self._counts[src] if now - t < TIME_WINDOW]
            self._counts[src].append(now)
            count = len(self._counts[src])

        if count >= DEAUTH_THRESHOLD and src not in self._alerted:
            self._alerted.add(src)
            event = {
                "type": "deauth_flood",
                "source_mac": src,
                "target_mac": dst,
                "count": count,
                "window_seconds": TIME_WINDOW,
                "reason_code": reason,
                "timestamp": datetime.now().isoformat(),
                "severity": "high" if count > 20 else "medium",
            }
            if self.on_alert:
                self.on_alert(event)

        # reset alert if it calms down
        elif count < 2 and src in self._alerted:
            self._alerted.discard(src)

    def start(self, timeout: Optional[int] = None):
        if not SCAPY_AVAILABLE:
            print("  error: scapy not installed")
            return

        self._running = True
        print(f"  listening for deauth frames... (ctrl+c to stop)")
        print(f"  note: requires wifi adapter in monitor mode\n")

        try:
            sniff(
                iface=self.iface,
                prn=self._handle_packet,
                store=False,
                timeout=timeout,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            print(f"  error sniffing: {e}")
            print("  tip: on windows, enable '802.11 raw wifi packet capture' in npcap installer")

    def stop(self):
        self._running = False


def run_deauth_detector(iface=None):
    """Run interactively, print alerts to console."""
    def on_alert(event):
        print(f"\n  !! DEAUTH FLOOD DETECTED")
        print(f"  source:   {event['source_mac']}")
        print(f"  target:   {event['target_mac']}")
        print(f"  packets:  {event['count']} in {event['window_seconds']}s")
        print(f"  severity: {event['severity']}")
        if event['reason_code']:
            print(f"  reason code: {event['reason_code']}")
        print(f"  time: {event['timestamp']}\n")

    detector = DeauthDetector(on_alert=on_alert, iface=iface)
    try:
        detector.start()
    except KeyboardInterrupt:
        detector.stop()
        print("\n  stopped.")
