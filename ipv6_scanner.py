"""
deauth_detect.py
listens for 802.11 deauthentication frames on the network
these are used in wifi jamming / evil twin attacks
requires scapy and a wifi adapter that supports monitor mode
on windows you need npcap and a compatible adapter
"""

import time
import threading
from datetime import datetime
from typing import Callable, Optional
from collections import defaultdict

try:
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disassoc, RadioTap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class DeauthEvent:
    def __init__(self, src: str, dst: str, reason: int, frame_type: str):
        self.src = src
        self.dst = dst
        self.reason = reason
        self.frame_type = frame_type  # deauth or disassoc
        self.timestamp = datetime.now()
        self.count = 1

    def reason_text(self) -> str:
        reasons = {
            1:  "unspecified",
            2:  "prev auth no longer valid",
            3:  "deauthenticated - leaving",
            4:  "inactivity",
            5:  "too many associated stations",
            6:  "class 2 frame from non-auth station",
            7:  "class 3 frame from non-assoc station",
            8:  "disassociated - leaving",
            9:  "station requesting assoc is not authenticated",
        }
        return reasons.get(self.reason, f"reason code {self.reason}")


BROADCAST = "ff:ff:ff:ff:ff:ff"
DEAUTH_THRESHOLD = 5   # frames per window before its flagged as an attack
WINDOW_SECONDS = 3     # time window to count frames in


class DeauthDetector:
    def __init__(self, iface: Optional[str] = None, on_attack: Optional[Callable] = None,
                 on_frame: Optional[Callable] = None):
        self.iface = iface
        self.on_attack = on_attack    # called when attack threshold hit
        self.on_frame = on_frame      # called on every deauth frame
        self._running = False
        self._counts = defaultdict(list)  # src -> list of timestamps
        self._lock = threading.Lock()

    def _handle_packet(self, pkt):
        if not (pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disassoc)):
            return

        src = pkt.addr2 or "unknown"
        dst = pkt.addr1 or "unknown"

        if pkt.haslayer(Dot11Deauth):
            reason = pkt[Dot11Deauth].reason
            frame_type = "deauth"
        else:
            reason = pkt[Dot11Disassoc].reason
            frame_type = "disassoc"

        event = DeauthEvent(src=src, dst=dst, reason=reason, frame_type=frame_type)

        if self.on_frame:
            self.on_frame(event)

        # count frames per source in sliding window
        now = time.time()
        with self._lock:
            self._counts[src] = [t for t in self._counts[src] if now - t < WINDOW_SECONDS]
            self._counts[src].append(now)
            count = len(self._counts[src])

        if count >= DEAUTH_THRESHOLD and self.on_attack:
            event.count = count
            self.on_attack(event)

    def start(self):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy not installed")
        self._running = True
        print(f"  listening for deauth frames on {self.iface or 'default interface'}")
        print("  note: requires monitor mode adapter. ctrl+c to stop.\n")
        try:
            sniff(
                iface=self.iface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            print(f"  error: {e}")
            print("  tip: make sure your wifi adapter supports monitor mode")

    def stop(self):
        self._running = False


def watch_for_deauth(iface: Optional[str] = None):
    """
    Simple blocking deauth watcher that prints to terminal.
    """
    from rich.console import Console
    console = Console()

    seen_attacks = set()

    def on_frame(event: DeauthEvent):
        ts = event.timestamp.strftime("%H:%M:%S")
        target = "broadcast" if event.dst == BROADCAST else event.dst
        console.print(
            f"  [dim]{ts}[/dim]  {event.frame_type}  "
            f"src=[cyan]{event.src}[/cyan]  dst={target}  "
            f"reason: {event.reason_text()}"
        )

    def on_attack(event: DeauthEvent):
        key = event.src
        if key not in seen_attacks:
            seen_attacks.add(key)
            console.print(
                f"\n  [bold red]!! deauth attack detected[/bold red]\n"
                f"  source mac: [red]{event.src}[/red]\n"
                f"  target: {event.dst}\n"
                f"  {event.count} frames in {WINDOW_SECONDS}s  --  reason: {event.reason_text()}\n"
                f"  this could be a wifi jammer or evil twin attack\n"
            )

    detector = DeauthDetector(iface=iface, on_attack=on_attack, on_frame=on_frame)
    detector.start()
