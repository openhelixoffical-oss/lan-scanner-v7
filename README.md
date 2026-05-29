#!/usr/bin/env python3
# lan-device-scanner -- made by brad

import argparse
import json
from lan_scanner.scanner import Scanner
from lan_scanner.display import Display
from lan_scanner.history import DeviceHistory


def main():
    parser = argparse.ArgumentParser(description="lan-device-scanner -- made by brad")
    parser.add_argument("--range", "-r", default=None,
        help="ip range to scan (e.g. 192.168.1.0/24). auto-detected if not set")
    parser.add_argument("--watch", "-w", action="store_true",
        help="live dashboard, refreshes every interval seconds")
    parser.add_argument("--interval", "-i", type=int, default=30,
        help="seconds between scans in watch mode (default: 30)")
    parser.add_argument("--deep", "-d", action="store_true",
        help="deep scan: grab banners, probe http, upnp, snmp, mdns services. slower but way more info")
    parser.add_argument("--history", action="store_true",
        help="show every device ever seen")
    parser.add_argument("--label", nargs=2, metavar=("MAC", "NAME"),
        help='give a device a name: --label aa:bb:cc:dd:ee:ff "dads phone"')
    parser.add_argument("--export", metavar="FILE",
        help="save results to json file")
    args = parser.parse_args()

    display = Display()
    history = DeviceHistory()
    scanner = Scanner(ip_range=args.range, deep=args.deep)

    if args.label:
        mac, name = args.label
        history.set_label(mac.lower(), name)
        display.print_info(f'  labeled {mac} as "{name}"')
        return

    if args.history:
        display.show_history(history.get_all())
        return

    display.banner()

    if args.deep:
        display.print_info(
            "  [dim]deep scan mode -- grabbing banners, probing http/upnp/snmp/mdns\n"
            "  this takes 20-40 seconds depending on how many devices are found[/dim]\n"
        )

    if args.watch:
        display.print_info(f"  [dim]watch mode -- scanning every {args.interval}s  ctrl+c to stop[/dim]\n")
        try:
            display.live_watch(scanner=scanner, history=history, interval=args.interval)
        except KeyboardInterrupt:
            display.print_info("\n  stopped.")
        return

    display.print_info("  [dim]scanning...[/dim]\n")
    devices = scanner.scan()
    new_devices = history.update(devices)
    display.show_devices(devices, new_devices, show_deep=args.deep)

    if args.export:
        with open(args.export, "w") as f:
            json.dump([d.to_dict() for d in devices], f, indent=2, default=str)
        display.print_info(f"  saved to {args.export}")


if __name__ == "__main__":
    main()
