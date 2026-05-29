# 🔍 LAN Device Scanner

Scan your local network, identify every device, and get alerted when unknown ones appear.

![Python](https://img.shields.io/badge/python-3.8+-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

## Features

- **ARP scanning** — fast, accurate device discovery via Scapy
- **Vendor identification** — resolves MAC address → manufacturer (Apple, Samsung, TP-Link, etc.)
- **OS fingerprinting** — guesses OS from TTL values (Windows / Linux / macOS)
- **Hostname resolution** — reverse DNS lookup for each device
- **Device history** — SQLite database tracks when devices first/last appeared
- **Watch mode** — continuously scans and alerts when a new device joins
- **Export** — save results to JSON

## Installation

```bash
pip install -r requirements.txt
```

> **Windows:** Run as Administrator (required for ARP scanning)  
> **Linux/macOS:** Run with `sudo`

## Usage

### Basic scan
```bash
python main.py
```

### Scan a specific range
```bash
python main.py --range 192.168.0.0/24
```

### Watch mode (alert on new devices)
```bash
python main.py --watch --interval 20
```

### View device history
```bash
python main.py --history
```

### Export results to JSON
```bash
python main.py --export results.json
```

## Example Output

```
╭──────────────────────────────────────────────────────────────────────╮
│                        LAN Device Scanner                            │
│              Discover and monitor devices on your network            │
╰──────────────────────────────────────────────────────────────────────╯

╭─ Found 6 device(s)  14:32:01 ──────────────────────────────────────╮
│ IP Address      MAC Address         Hostname       Vendor           │
│─────────────────────────────────────────────────────────────────── │
│ 192.168.1.1     C0:4A:00:XX:XX:XX   router.local   TP-Link          │
│ 192.168.1.5     DC:A6:32:XX:XX:XX   raspberrypi    Raspberry Pi     │
│ 192.168.1.10    AC:BC:32:XX:XX:XX   MacBook.local  Apple            │
│ 192.168.1.15    94:35:0A:XX:XX:XX   Galaxy-S23     Samsung          │
│ 192.168.1.20    00:0C:29:XX:XX:XX   DESKTOP-ABC    VMware           │
│ 192.168.1.25    18:FE:34:XX:XX:XX   Unknown        Espressif (IoT)  │
╰────────────────────────────────────────────────────────────────────╯
```

## How it works

1. Sends ARP broadcast packets to all IPs in your subnet
2. Listens for replies — each reply = an active device
3. Resolves MAC prefix → vendor using OUI lookup table
4. Reverse DNS lookups for hostnames
5. Pings each device and reads TTL to guess OS
6. Stores everything in `~/.lan_scanner.db`

## Project Structure

```
lan-scanner/
├── main.py                  # Entry point + CLI
├── requirements.txt
├── lan_scanner/
│   ├── scanner.py           # ARP scanning + Device dataclass
│   ├── vendor.py            # MAC → vendor lookup
│   ├── history.py           # SQLite persistence
│   └── display.py           # Rich terminal UI
```

## Stretch Goals / Ideas

- [ ] TUI dashboard with live updates (using `textual`)
- [ ] System tray icon with notifications
- [ ] Port scanning per device
- [ ] Webhook/Discord alerts on new device
- [ ] Web UI for history and live view
- [ ] Nmap integration for deeper OS fingerprinting

## Requirements

- Python 3.8+
- Scapy (ARP scanning)
- Rich (terminal UI)
- Admin/root privileges for ARP scanning

## License

MIT
