# netmon

Terminal network traffic monitor. Traffic is grouped into **boxes per server**, each holding **one inner box per client** talking to it. Box size = traffic (current rate or total bytes, square-root scaled by default so small boxes stay readable), color = distance of the remote end (default), rate heat, protocol or service. The screen is split by position: **intranet on the left, internet on the right**.

A client↔server pair is *intranet* when both ends are local (RFC1918, loopback, link-local, CGNAT `100.64/10`, ULA, multicast, plus any `--local-net`); otherwise *internet*. A LAN server reached from the internet therefore appears in the internet pane with its external clients.

Boxes have a minimum size (server 18×4, client 14×2 cells); whatever doesn't fit is merged into a "+N more" box. If only one client fits, it shows a "+N more clients" line instead.

## Distance colors (GeoIP)

The remote end of each connection is looked up offline by country:

| Color | Region |
|---|---|
| green | Germany |
| blue | rest of Europe (EU/EEA, CH, GB, Balkans, UA, MD) |
| yellow | "western": US, CA, AU, NZ, JP, KR, TW, IL, SG |
| orange | "eastern": RU, BY, CN, HK, IR, KP, Central Asia, … |
| red | rest of the world |
| gray | local / unknown |

Brightness of a client box shows its traffic. The country lists are in `netmon/geo.py`.

The database is [IP to Country Lite by DB-IP](https://db-ip.com), licensed CC BY 4.0, published monthly. netmon keeps it in `~/.cache/netmon/` (under `sudo`, the invoking user's cache) and **downloads it in the background on start when it is missing or older than 31 days**; the UI keeps running with the old data meanwhile. A file older than a month triggers a warning on startup and stays flagged in the status bar until it is refreshed.

```sh
.venv/bin/netmon --update-geoip      # download now and exit
.venv/bin/netmon --no-geoip-update   # never download automatically (still warns when outdated)
```

`--geoip FILE` or `$NETMON_GEOIP` points at any `start,end,CC` CSV (optionally gzipped); such files are never auto-downloaded, only checked for age. `--demo` never downloads.

## Setup

```sh
python3 -m venv .venv          # needs python3-venv; or: python3 -m venv --without-pip .venv + get-pip.py
.venv/bin/pip install -e '.[dev]'
```

## Run

```sh
.venv/bin/netmon --demo                                      # synthetic traffic, no root
sudo .venv/bin/netmon                                         # live, all interfaces
sudo .venv/bin/netmon -i wlan0                                # live, one interface
sudo tcpdump -i any -U -w - | .venv/bin/netmon --pcap -       # UI unprivileged
.venv/bin/netmon --pcap capture.pcap [--fast]                 # replay a file (pcap, not pcapng)
```

Options: `--no-dns`, `--geoip FILE`, `--update-geoip`, `--no-geoip-update`, `--local-net CIDR` (repeatable), `--expire SEC`, `--interval SEC`.

## Keys

| Key | Action |
|---|---|
| `/` | filter (Enter apply, Esc close; Esc again clears) |
| `s` / `r` | cycle sort (size, name, clients, port) / reverse |
| `m` | size by current rate ↔ total bytes |
| `l` | size scale: sqrt → log → linear |
| `c` | color by distance → rate heat → protocol → service |
| `g` | one box per server host ↔ per host+port+protocol |
| `v` | panes: both → intranet → internet |
| `t` | table view |
| `p` / `z` / `q` | pause / reset totals / quit |

Hover a box with the mouse for details.

## Filter syntax

Terms are AND-ed, `or` separates alternatives, `!`/`not` negates:
`host|server|client X`, `net CIDR`, `port N`, `proto tcp|udp|icmp`, `min 10k` (rate), `country de`, `region germany|europe|western|eastern|rest|local|unknown`, `internet`, `intranet`, `tcp`, `udp`, or free text (IP / hostname / service substring).

```
port 443 !host 10.0.0.1
internet min 100k
ssh or domain
!region germany !region local
```

## License

MIT, see [LICENSE](LICENSE). GeoIP data (downloaded separately) is IP to Country Lite by [DB-IP](https://db-ip.com), CC BY 4.0.
