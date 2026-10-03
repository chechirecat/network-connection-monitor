"""IP -> country -> distance region, from an offline range CSV.

The default database is DB-IP "IP to Country Lite" (CC BY 4.0,
https://db-ip.com), rows of ``start_ip,end_ip,CC``. ``netmon --update-geoip``
downloads it into the cache directory.
"""

from __future__ import annotations

import csv
import datetime
import gzip
import os
import pwd
import socket
import threading
import urllib.request
from array import array
from bisect import bisect_right
from functools import lru_cache
from pathlib import Path

GERMANY = "germany"
EUROPE = "europe"
WESTERN = "western"
EASTERN = "eastern"
REST = "rest"
LOCAL = "local"
UNKNOWN = "unknown"

REGION_LABELS = {
    GERMANY: "Germany",
    EUROPE: "Europe",
    WESTERN: "Western",
    EASTERN: "Eastern",
    REST: "Rest of world",
    LOCAL: "local",
    UNKNOWN: "unknown",
}

EUROPE_CCS = set(
    "AD AL AT AX BA BE BG CH CY CZ DK EE ES EU FI FO FR GB GG GI GR HR HU IE IM IS IT JE LI LT LU LV "
    "MC MD ME MK MT NL NO PL PT RO RS SE SI SJ SK SM UA VA XK".split()
)
WESTERN_CCS = set("US CA AU NZ JP KR TW IL SG PR GU VI".split())
EASTERN_CCS = set("RU BY CN HK MO KP IR KZ UZ TM KG TJ SY CU VE MN".split())

DBIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{:%Y-%m}.csv.gz"
DB_FILENAME = "dbip-country-lite.csv.gz"


def region_of(cc: str | None) -> str:
    if not cc or cc == "ZZ":
        return UNKNOWN
    if cc == "DE":
        return GERMANY
    if cc in EUROPE_CCS:
        return EUROPE
    if cc in WESTERN_CCS:
        return WESTERN
    if cc in EASTERN_CCS:
        return EASTERN
    return REST


def cache_dirs() -> list[Path]:
    """Cache directories to search, the invoking user's first when run via sudo."""
    dirs = []
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            dirs.append(Path(pwd.getpwnam(sudo_user).pw_dir) / ".cache" / "netmon")
        except KeyError:
            pass
    xdg = os.environ.get("XDG_CACHE_HOME")
    dirs.append((Path(xdg) if xdg else Path.home() / ".cache") / "netmon")
    return dirs


def default_db_path() -> Path | None:
    env = os.environ.get("NETMON_GEOIP")
    if env:
        return Path(env)
    for d in cache_dirs():
        if (d / DB_FILENAME).exists():
            return d / DB_FILENAME
    return None


def download(dest: Path | None = None) -> Path:
    """Download the current (or previous) month's DB-IP country lite CSV."""
    dest = dest or cache_dirs()[0] / DB_FILENAME
    dest.parent.mkdir(parents=True, exist_ok=True)
    today = datetime.date.today().replace(day=1)
    last_error = None
    for month in (today, (today - datetime.timedelta(days=1)).replace(day=1)):
        url = DBIP_URL.format(month)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "netmon/0.1"})  # default UA gets 403
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
        except OSError as e:
            last_error = e
            continue
        tmp = dest.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(dest)
        if os.environ.get("SUDO_UID"):  # keep the file usable by the invoking user
            uid, gid = int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", -1))
            for path in (dest.parent, dest):
                os.chown(path, uid, gid)
        return dest
    raise OSError(f"download failed: {last_error}")


def _ip_int(ip: str) -> tuple[int, int]:
    """IPv4 as a 32-bit int; IPv6 reduced to its /64 prefix so both fit in uint64 arrays
    (country ranges are never more specific than /64)."""
    if ":" in ip:
        return 6, int.from_bytes(socket.inet_pton(socket.AF_INET6, ip)[:8], "big")
    return 4, int.from_bytes(socket.inet_aton(ip), "big")


class GeoDB:
    """Sorted range table with binary search. Load in the background with ``load_async``."""

    def __init__(self) -> None:
        self._starts = {4: array("Q"), 6: array("Q")}
        self._ends = {4: array("Q"), 6: array("Q")}
        self._ccs = {4: b"", 6: b""}  # two ASCII bytes per range
        self.ready = False
        self.error: str | None = None
        self.path: Path | None = None
        self.country = lru_cache(maxsize=65536)(self._country)

    @classmethod
    def from_rows(cls, rows) -> GeoDB:
        db = cls()
        db._load_rows(rows)
        return db

    def load(self, path: Path) -> None:
        self.path = path
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", newline="") as fh:
            self._load_rows(csv.reader(fh))

    def load_async(self, path: Path) -> None:
        def run():
            try:
                self.load(path)
            except (OSError, ValueError, csv.Error) as e:
                self.error = f"geoip: {e}"

        threading.Thread(target=run, daemon=True, name="geoip").start()

    def _load_rows(self, rows) -> None:
        tables = {4: [], 6: []}
        for row in rows:
            if len(row) < 3:
                continue
            v, start = _ip_int(row[0])
            _, end = _ip_int(row[1])
            tables[v].append((start, end, row[2]))
        for v, t in tables.items():
            t.sort()
            self._starts[v] = array("Q", (r[0] for r in t))
            self._ends[v] = array("Q", (r[1] for r in t))
            self._ccs[v] = b"".join(r[2].encode("ascii")[:2].ljust(2) for r in t)
        self.country.cache_clear()
        self.ready = True

    def _country(self, ip: str) -> str | None:
        if not self.ready:
            return None
        try:
            v, n = _ip_int(ip)
        except OSError:
            return None
        i = bisect_right(self._starts[v], n) - 1
        if i >= 0 and n <= self._ends[v][i]:
            cc = self._ccs[v][2 * i : 2 * i + 2].decode("ascii")
            return None if cc == "ZZ" else cc
        return None

    def lookup(self, ip: str) -> str | None:
        # the lru cache must not remember misses from before the table finished loading
        return self.country(ip) if self.ready else None

