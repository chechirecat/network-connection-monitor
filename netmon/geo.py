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
import time
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
MAX_AGE_DAYS = 31  # DB-IP publishes a new database every month


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


def default_db_path() -> Path:
    """Where the database is (or will be downloaded to)."""
    for d in cache_dirs():
        if (d / DB_FILENAME).exists():
            return d / DB_FILENAME
    return cache_dirs()[0] / DB_FILENAME


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
        if not data.startswith(b"\x1f\x8b"):
            last_error = f"{url} did not return a gzip file"
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


def file_age_days(path: Path) -> float | None:
    try:
        return (time.time() - path.stat().st_mtime) / 86400
    except OSError:
        return None


def _ip_int(ip: str) -> tuple[int, int]:
    """IPv4 as a 32-bit int; IPv6 reduced to its /64 prefix so both fit in uint64 arrays
    (country ranges are never more specific than /64)."""
    if ":" in ip:
        return 6, int.from_bytes(socket.inet_pton(socket.AF_INET6, ip)[:8], "big")
    return 4, int.from_bytes(socket.inet_aton(ip), "big")


class GeoDB:
    """Sorted range table with binary search. Load in the background with ``start``."""

    def __init__(self) -> None:
        empty = (array("Q"), array("Q"), b"")
        # per IP version: (starts, ends, two ASCII bytes of country code per range);
        # replaced as a whole so a reload never exposes mismatched arrays
        self._tables = {4: empty, 6: empty}
        self.ready = False
        self.path: Path | None = None
        self.age_days: float | None = None  # age of the file at startup
        self.error: str | None = None
        self.state = "idle"  # idle | loading | downloading | updated | update-failed
        self.will_update = False
        self.country = lru_cache(maxsize=65536)(self._country)

    @classmethod
    def from_rows(cls, rows) -> GeoDB:
        db = cls()
        db._load_rows(rows)
        return db

    def load(self, path: Path) -> None:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", newline="") as fh:
            self._load_rows(csv.reader(fh))
        self.path = path

    def start(self, path: Path, update_to: Path | None = None, max_age_days: float = MAX_AGE_DAYS) -> None:
        """Load ``path`` in a background thread. With ``update_to``, download a fresh
        database there first if ``path`` is missing or older than ``max_age_days``."""
        self.age_days = file_age_days(path)
        stale = self.age_days is None or self.age_days > max_age_days
        self.will_update = update_to is not None and stale
        # set before the thread starts so callers never observe a stale "idle"
        self.state = "loading" if self.age_days is not None else "downloading" if self.will_update else "idle"

        def run():
            if self.age_days is not None:
                try:
                    self.load(path)
                except (OSError, ValueError, csv.Error) as e:
                    self.error = f"geoip: {e}"
            if self.will_update:
                self.state = "downloading"
                try:
                    self.load(download(update_to))
                    self.error = None
                    self.state = "updated"
                    return
                except (OSError, ValueError, csv.Error) as e:
                    self.error = f"GeoIP download failed: {e}"
                    self.state = "update-failed"
                    return
            self.state = "idle"

        threading.Thread(target=run, daemon=True, name="geoip").start()

    @property
    def stale(self) -> bool:
        return self.age_days is not None and self.age_days > MAX_AGE_DAYS and self.state != "updated"

    def status(self) -> tuple[str, str] | None:
        """(severity, message) for the status bar, or None when all is well."""
        age = f"{self.age_days:.0f} days old" if self.age_days is not None else ""
        if self.state == "downloading":
            return "warning", f"GeoIP db {age}, updating…" if age else "downloading GeoIP db…"
        if self.state == "loading":
            return "warning", "loading GeoIP…"
        if self.error:
            hint = f" (db {age})" if self.ready and age else ""
            return "error", f"{self.error}{hint} — run netmon --update-geoip"
        if self.stale:
            return "warning", f"GeoIP db is {age}: run netmon --update-geoip"
        return None

    def _load_rows(self, rows) -> None:
        rows_by_version = {4: [], 6: []}
        for row in rows:
            if len(row) < 3:
                continue
            v, start = _ip_int(row[0])
            _, end = _ip_int(row[1])
            rows_by_version[v].append((start, end, row[2]))
        tables = {}
        for v, t in rows_by_version.items():
            t.sort()
            tables[v] = (
                array("Q", (r[0] for r in t)),
                array("Q", (r[1] for r in t)),
                b"".join(r[2].encode("ascii")[:2].ljust(2) for r in t),
            )
        if not tables[4][0] and not tables[6][0]:
            raise ValueError("no IP ranges in database")
        self._tables = tables
        self.country.cache_clear()
        self.ready = True

    def _country(self, ip: str) -> str | None:
        try:
            v, n = _ip_int(ip)
        except OSError:
            return None
        starts, ends, ccs = self._tables[v]
        i = bisect_right(starts, n) - 1
        if i >= 0 and n <= ends[i]:
            cc = ccs[2 * i : 2 * i + 2].decode("ascii")
            return None if cc == "ZZ" else cc
        return None

    def lookup(self, ip: str) -> str | None:
        # the lru cache must not remember misses from before the table finished loading
        return self.country(ip) if self.ready else None
