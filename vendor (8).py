from datetime import datetime
from typing import List, Set
import time

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.align import Align
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def _get_name_and_source(device):
    hostname = device.hostname if device.hostname != "unknown" else ""
    mdns = device.mdns_name.replace("-", " ").replace(".local", "").strip() if device.mdns_name else ""
    netbios = device.netbios_name or ""
    label = device.label or ""

    if label:
        sub = hostname or mdns or netbios or ""
        name = f"[yellow]{label}[/yellow]" + (f"\n[dim]{sub}[/dim]" if sub else "")
        source = "label"
    elif mdns:
        name = f"[green]{mdns}[/green]" + (f"\n[dim]{hostname}[/dim]" if hostname and hostname != mdns else "")
        source = "mdns"
    elif netbios:
        name = f"[cyan]{netbios}[/cyan]" + (f"\n[dim]{hostname}[/dim]" if hostname and hostname != netbios else "")
        source = "netbios"
    elif hostname:
        name = hostname
        source = "dns"
    else:
        name = "[dim]no name found[/dim]"
        source = ""

    return name, source


class Display:
    def __init__(self):
        if RICH_AVAILABLE:
            self.console = Console()

    def banner(self):
        if RICH_AVAILABLE:
            self.console.print()
            self.console.print("  [bold white]lan-device-scanner[/bold white]  [dim]// made by brad[/dim]")
            self.console.print("  [dim]scans your network and shows whats on it[/dim]")
            self.console.print()
        else:
            print()
            print("  lan-device-scanner  // made by brad")
            print("  scans your network and shows whats on it")
            print()

    def print_info(self, msg: str):
        if RICH_AVAILABLE:
            self.console.print(msg)
        else:
            print(msg)

    def _build_table(self, devices, new_macs: Set[str], show_deep: bool = False):
        ts = datetime.now().strftime("%H:%M:%S")
        table = Table(
            title=f"[dim]{len(devices)} devices found  --  {ts}[/dim]",
            title_justify="left",
            box=box.SIMPLE_HEAD,
            header_style="bold",
            border_style="dim",
            show_lines=show_deep,  # show lines in deep mode so details are readable
            expand=True,
            padding=(0, 1),
        )

        table.add_column("no.", style="dim", width=4, justify="right")
        table.add_column("ip", style="cyan", min_width=15)
        table.add_column("name / hostname", min_width=26)
        table.add_column("type", min_width=18)
        table.add_column("vendor", min_width=16)
        table.add_column("mac", style="dim", min_width=18)
        table.add_column("os", min_width=13)
        if show_deep:
            table.add_column("deep scan info", min_width=40)
        table.add_column("seen", justify="right", width=5)
        table.add_column("", width=4)

        for i, device in enumerate(devices, 1):
            is_new = device.mac in new_macs
            badge = "[green]new[/green]" if is_new else ""
            row_style = "on dark_green" if is_new else ""

            name, _ = _get_name_and_source(device)
            vendor = device.vendor if device.vendor != "unknown" else "[dim]?[/dim]"
            dtype = device.device_type if device.device_type != "unknown" else "[dim]?[/dim]"

            row = [
                str(i),
                device.ip,
                name,
                dtype,
                vendor,
                device.mac,
                device.os_guess(),
            ]

            if show_deep:
                details = device.deep_details
                if device.mdns_services:
                    details = details + [f"advertised: {', '.join(device.mdns_services)}"]
                deep_text = "\n".join(details) if details else "[dim]nothing extra found[/dim]"
                row.append(deep_text)

            row += [str(getattr(device, "seen_count", 1)), badge]
            table.add_row(*row, style=row_style)

        return table

    def show_devices(self, devices, new_devices=None, show_deep=False):
        new_macs = {d.mac for d in (new_devices or [])}
        if RICH_AVAILABLE:
            table = self._build_table(devices, new_macs, show_deep=show_deep)
            self.console.print(table)
            self.console.print(
                "  [dim]name sources:  "
                "[green]green[/green] = mdns (device's actual name)  "
                "[cyan]cyan[/cyan] = netbios  "
                "white = dns  "
                "[yellow]yellow[/yellow] = your label[/dim]"
            )
            self.console.print()
        else:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n{len(devices)} devices found  --  {ts}\n")
            print(f"{'#':<4} {'ip':<18} {'name':<26} {'type':<18} {'vendor':<18} {'mac':<20} os")
            print("-" * 110)
            for i, d in enumerate(devices, 1):
                name = d.best_name() or "?"
                flag = " [new]" if d.mac in new_macs else ""
                print(f"{i:<4} {d.ip:<18} {name:<26} {d.device_type:<18} {d.vendor:<18} {d.mac:<20} {d.os_guess()}{flag}")
                if show_deep and d.deep_details:
                    for detail in d.deep_details:
                        print(f"       >> {detail}")

    def live_watch(self, scanner, history, interval: int, on_new_device=None):
        if not RICH_AVAILABLE:
            raise RuntimeError("rich is required for live mode")

        devices = []
        new_macs: Set[str] = set()
        status = "starting..."
        next_scan_at = time.time()
        first_scan = True

        def make_renderable():
            from rich.console import Group
            secs_left = max(0, int(next_scan_at - time.time()))
            header = Text.from_markup(
                f"  [bold white]lan-device-scanner[/bold white]  [dim]// made by brad[/dim]\n"
                f"  [dim]watch mode  --  next scan in {secs_left}s  --  {status}[/dim]"
            )
            if not devices:
                return Group(header, Text("  waiting for first scan...", style="dim"))
            show_deep = any(d.deep_details for d in devices)
            table = self._build_table(devices, new_macs, show_deep=show_deep)
            return Group(header, table)

        with Live(make_renderable(), console=self.console, refresh_per_second=2) as live:
            while True:
                now = time.time()
                if now >= next_scan_at:
                    status = "scanning..."
                    live.update(make_renderable())

                    scanned = scanner.scan()
                    new_this_round = history.update(scanned)

                    if first_scan:
                        new_macs = set()
                        first_scan = False
                    else:
                        new_macs = {d.mac for d in new_this_round}

                    devices = scanned
                    next_scan_at = time.time() + interval

                    if new_macs:
                        names = ", ".join(d.best_name() or d.ip for d in new_this_round)
                        status = f"!! new device: {names}"
                    else:
                        status = "all clear"

                live.update(make_renderable())
                time.sleep(0.5)

    def alert_new_device(self, device):
        name = device.best_name() or device.ip
        if RICH_AVAILABLE:
            self.console.print(f"\n  [bold yellow]!! new device detected[/bold yellow]")
            self.console.print(f"  ip: [cyan]{device.ip}[/cyan]  mac: [dim]{device.mac}[/dim]")
            self.console.print(f"  name: {name}  type: {device.device_type}  vendor: {device.vendor}\n")
        else:
            print(f"\n!! new device: {device.ip} ({device.mac}) -- {name} -- {device.vendor}\n")

    def show_history(self, records):
        if not records:
            self.print_info("[dim]no history yet. run a scan first.[/dim]")
            return
        if RICH_AVAILABLE:
            table = Table(
                title=f"[dim]device history  --  {len(records)} devices total[/dim]",
                title_justify="left",
                box=box.SIMPLE_HEAD,
                header_style="bold",
                border_style="dim",
                show_lines=False,
                expand=True,
                padding=(0, 1),
            )
            table.add_column("label", min_width=16)
            table.add_column("hostname", min_width=24)
            table.add_column("type", min_width=16)
            table.add_column("ip", style="cyan", min_width=15)
            table.add_column("mac", style="dim", min_width=18)
            table.add_column("vendor", min_width=16)
            table.add_column("first seen", min_width=16)
            table.add_column("last seen", min_width=16)
            table.add_column("times", justify="right")

            for r in records:
                label = f"[yellow]{r['label']}[/yellow]" if r["label"] else "[dim]--[/dim]"
                hostname = r.get("hostname") or "[dim]unknown[/dim]"
                dtype = r.get("device_type") or "unknown"
                table.add_row(
                    label, hostname, dtype, r["ip"], r["mac"],
                    r["vendor"] or "unknown",
                    r["first_seen"][:16], r["last_seen"][:16], str(r["seen_count"])
                )
            self.console.print(table)
        else:
            for r in records:
                label = r["label"] or r.get("hostname") or "?"
                print(f"{r['ip']:<18} {r['mac']:<20} {label:<22} {r['vendor']:<20} seen {r['seen_count']}x")
