"""
honeypot.py
runs fake services on unused ports and alerts when anything connects
if something on your network is scanning or probing, it'll hit the honeypot
useful for detecting malware, worms, scanners, or unexpected behavior
completely passive/defensive -- just listens and reports
"""

import socket
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional


# fake service banners to make the honeypot look real
FAKE_BANNERS = {
    21:   b"220 FTP Server ready\r\n",
    22:   b"SSH-2.0-OpenSSH_8.2p1\r\n",
    23:   b"\r\nWelcome\r\nlogin: ",
    25:   b"220 SMTP Service ready\r\n",
    80:   b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Length: 0\r\n\r\n",
    110:  b"+OK POP3 server ready\r\n",
    143:  b"* OK IMAP4 server ready\r\n",
    443:  b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
    445:  b"\x00\x00\x00\x2f\xff\x53\x4d\x42",  # fake SMB header
    3306: b"\x4a\x00\x00\x00\x0a\x38\x2e\x30",  # fake MySQL greeting
    3389: b"\x03\x00\x00\x13\x0e\xd0\x00\x00",  # fake RDP
    5900: b"RFB 003.008\n",                        # fake VNC
    8080: b"HTTP/1.1 200 OK\r\nServer: Jetty/9.4\r\n\r\n",
}

# ports to listen on -- pick ones that look like real services but arent yours
DEFAULT_HONEYPOT_PORTS = [21, 22, 23, 25, 110, 143, 445, 3306, 5900]


class HoneypotListener:
    def __init__(
        self,
        ports: Optional[List[int]] = None,
        on_connection: Optional[Callable] = None,
        read_data: bool = True,
    ):
        self.ports = ports or DEFAULT_HONEYPOT_PORTS
        self.on_connection = on_connection
        self.read_data = read_data
        self._servers: Dict[int, socket.socket] = {}
        self._threads: List[threading.Thread] = []
        self._running = False
        self._connections: List[Dict] = []
        self._lock = threading.Lock()

    def _handle_connection(self, conn: socket.socket, addr: tuple, port: int):
        """Handle a single connection to a honeypot port."""
        remote_ip, remote_port = addr

        # read whatever the client sends (could be a scanner fingerprint)
        data_received = ""
        if self.read_data:
            try:
                conn.settimeout(2.0)
                raw = conn.recv(1024)
                data_received = raw.decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                pass

        # send fake banner
        banner = FAKE_BANNERS.get(port, b"")
        if banner:
            try:
                conn.send(banner)
            except Exception:
                pass

        conn.close()

        # log the connection
        event = {
            "timestamp": datetime.now().isoformat(),
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "honeypot_port": port,
            "service": self._port_service(port),
            "data_sent": data_received,
            "severity": self._assess_severity(remote_ip, port, data_received),
        }

        with self._lock:
            self._connections.append(event)

        if self.on_connection:
            self.on_connection(event)

    def _assess_severity(self, ip: str, port: int, data: str) -> str:
        """Guess how concerning a connection is."""
        data_lower = data.lower()

        # automated scanner signatures
        if any(x in data_lower for x in ["masscan", "nmap", "zgrab", "zmap", "shodan"]):
            return "high"

        # credential stuffing attempt
        if any(x in data_lower for x in ["root", "admin", "password", "passwd", "login"]):
            return "high"

        # shell commands -- malware trying to execute
        if any(x in data_lower for x in ["wget", "curl", "chmod", "busybox", "/bin/sh", "cmd.exe"]):
            return "critical"

        # exploit payloads
        if any(x in data_lower for x in ["../", "%2e%2e", "union select", "<script", "etc/passwd"]):
            return "critical"

        # just a port probe
        return "medium" if data else "low"

    def _port_service(self, port: int) -> str:
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            80: "http", 110: "pop3", 143: "imap", 443: "https",
            445: "smb", 3306: "mysql", 3389: "rdp", 5900: "vnc",
            8080: "http-alt",
        }
        return services.get(port, str(port))

    def _listen_on_port(self, port: int):
        """Listen on a single port."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", port))
            server.listen(5)
            server.settimeout(1.0)
            self._servers[port] = server

            while self._running:
                try:
                    conn, addr = server.accept()
                    t = threading.Thread(
                        target=self._handle_connection,
                        args=(conn, addr, port),
                        daemon=True,
                    )
                    t.start()
                except socket.timeout:
                    continue
                except Exception:
                    break

            server.close()
        except OSError as e:
            print(f"  could not bind port {port}: {e}")

    def start(self):
        """Start all honeypot listeners."""
        self._running = True

        for port in self.ports:
            t = threading.Thread(target=self._listen_on_port, args=(port,), daemon=True)
            t.start()
            self._threads.append(t)

        print(f"  honeypot listening on {len(self.ports)} ports: {', '.join(map(str, self.ports))}")
        print(f"  any connection will be logged and alerted")
        print(f"  ctrl+c to stop\n")

    def stop(self):
        self._running = False
        for server in self._servers.values():
            try:
                server.close()
            except Exception:
                pass

    def get_connections(self) -> List[Dict]:
        with self._lock:
            return list(self._connections)


def run_honeypot(ports=None, duration=None):
    """Run honeypot interactively."""

    def on_connection(event):
        sev_colors = {
            "critical": "!!",
            "high":     "! ",
            "medium":   "~ ",
            "low":      "  ",
        }
        prefix = sev_colors.get(event["severity"], "  ")
        print(f"\n  {prefix} HONEYPOT HIT [{event['severity'].upper()}]")
        print(f"     from:    {event['remote_ip']}:{event['remote_port']}")
        print(f"     port:    {event['honeypot_port']} ({event['service']})")
        print(f"     time:    {event['timestamp'][:19]}")
        if event["data_sent"]:
            print(f"     data:    {event['data_sent'][:80]}")

    honeypot = HoneypotListener(ports=ports, on_connection=on_connection)
    honeypot.start()

    try:
        if duration:
            time.sleep(duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass

    honeypot.stop()
    connections = honeypot.get_connections()
    print(f"\n  honeypot stopped. total connections: {len(connections)}")
    return connections
