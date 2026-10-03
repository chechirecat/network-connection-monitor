"""Command line entry point."""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
from pathlib import Path

from . import geo
from .classify import Classifier
from .model import TrafficModel
from .resolver import Resolver
from .sources import DemoSource, LiveSource, PcapSource, SourceError


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="netmon",
        description="Show network traffic as boxes per server (containing its clients), "
        "split into intranet (left) and internet (right).",
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("-i", "--interface", help="capture on this interface only (default: all)")
    src.add_argument("--pcap", metavar="FILE", help="read a pcap file, or '-' for stdin (e.g. from tcpdump -w -)")
    src.add_argument("--demo", action="store_true", help="show synthetic traffic (no root needed)")
    ap.add_argument("--fast", action="store_true", help="with --pcap FILE: load as fast as possible instead of replaying")
    ap.add_argument("--no-dns", action="store_true", help="disable reverse DNS lookups")
    ap.add_argument("--geoip", metavar="FILE",
                    help="country range CSV (start,end,CC; .gz ok). Default: $NETMON_GEOIP or ~/.cache/netmon/")
    ap.add_argument("--update-geoip", action="store_true",
                    help="download the free DB-IP country database (CC BY 4.0, db-ip.com) and exit")
    ap.add_argument("--local-net", action="append", default=[], metavar="CIDR",
                    help="additional network to treat as intranet (repeatable)")
    ap.add_argument("--expire", type=float, default=60.0, metavar="SEC",
                    help="forget pairs idle for this long (default 60)")
    ap.add_argument("--interval", type=float, default=1.0, metavar="SEC", help="refresh interval (default 1)")
    args = ap.parse_args(argv)
    for net in args.local_net:
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError as e:
            ap.error(f"--local-net: {e}")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.update_geoip:
        try:
            path = geo.download(Path(args.geoip) if args.geoip else None)
        except OSError as e:
            print(f"netmon: {e}", file=sys.stderr)
            return 1
        print(f"saved {path}\nIP to Country Lite by DB-IP (https://db-ip.com), licensed CC BY 4.0")
        return 0
    try:
        if args.demo:
            source = DemoSource()
        elif args.pcap:
            source = PcapSource(args.pcap, realtime=not args.fast)
        else:
            source = LiveSource(args.interface)
    except (SourceError, OSError) as e:
        print(f"netmon: {e}", file=sys.stderr)
        return 1

    if args.pcap == "-":
        # The capture now reads from its own dup of stdin; Textual reads keys from fd 0,
        # so point fd 0 back at the terminal.
        try:
            tty = os.open("/dev/tty", os.O_RDWR)
        except OSError:
            print("netmon: --pcap - needs a terminal (/dev/tty) for the UI", file=sys.stderr)
            return 1
        os.dup2(tty, 0)
        os.close(tty)

    from .app import NetMonApp  # imported late so --help stays fast

    geodb = load_geo(args)
    model = TrafficModel(Classifier(args.local_net), geo=geodb.lookup if geodb else None, expire=args.expire)
    resolver = Resolver(enabled=not args.no_dns and not args.demo)
    NetMonApp(source, model, resolver, geo=geodb, interval=args.interval).run()
    return 0


def load_geo(args) -> geo.GeoDB | None:
    path = Path(args.geoip) if args.geoip else geo.default_db_path()
    if path is None:
        return geo.GeoDB.from_rows(DemoSource.GEO_ROWS) if args.demo else None
    db = geo.GeoDB()
    db.load_async(path)
    return db


if __name__ == "__main__":
    sys.exit(main())
