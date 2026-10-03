# netmon

Terminal network traffic monitor: see who talks to whom, zoom from the whole network down to one connection's packets and reassembled payload. Traffic is grouped into **boxes per server**, each holding **one inner box per client** talking to it. Box size = traffic (current rate or total bytes, square-root scaled by default so small boxes stay readable), color = distance of the remote end (default), rate heat, protocol or service. The screen is split by position: **intranet on the left, internet on the right**.

A client↔server pair is *intranet* when both ends are local (RFC1918, loopback, link-local, CGNAT `100.64/10`, ULA, multicast, plus any `--local-net`); otherwise *internet*. A LAN server reached from the internet therefore appears in the internet pane with its external clients.

Boxes have a minimum size (server 18×4, client 14×2 cells); whatever doesn't fit is merged into a "+N more" box. If only one client fits, it shows a "+N more clients" line instead.

## Hostnames from traffic

Shared addresses (CDNs like Cloudflare, Akamai, CloudFront) say little about the service behind them, so netmon learns names from the traffic itself:

- **TLS SNI**: every encrypted TCP connection starts with a ClientHello that names the site in plain text, also when it spans several packets.
- **DNS answers**: plain DNS responses map addresses to the names that were looked up.

Learned names replace reverse DNS in box labels (`discord.com +2` = three sites seen on that address). The connections view (`2`) shows the exact SNI per connection, and the client detail page lists every name with its source. Only those handshake/DNS bytes are read for this; they are not shown in the dump unless payload capture (`x`) is on. `--no-hostnames` turns it off.

Not visible: QUIC/HTTP3 (UDP 443) encrypts its hello; DNS over HTTPS/TLS; and Encrypted Client Hello (ECH, used by browsers for Cloudflare sites) sends the decoy `cloudflare-ech.com`. It is recorded as such, but a DNS name for the same address wins. Names appear for **new** connections, so restart an app to see its existing ones named.

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

The country is where an address is *registered*, which can differ from where the server is. CDN and cloud addresses (Cloudflare, Google, AWS, …) are served from many locations at once, so e.g. a Cloudflare address shown as `CA` (Canada) is most likely answered from a data center near you. Check the learned hostname to see which service it is.

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

Options: `--payload`, `--no-hostnames`, `--no-dns`, `--geoip FILE`, `--update-geoip`, `--no-geoip-update`, `--local-net CIDR` (repeatable), `--expire SEC`, `--interval SEC`.

## Zooming

The view is a zoom stack, shown as a breadcrumb at the top: **All › Internet › DE 46.4.0.10 › 192.168.1.10**.

| Level | Shows |
|---|---|
| All | intranet and internet side by side |
| Pane | one of them, full screen |
| Server | one server; each client box also lists its connection ports |
| Client | details for one client ↔ server pair: names, location, rates, totals, per-service connections and client ports |

- `Space` puts letters on every box at the current level (pane titles get the first ones); type a letter (two once there are more than 26) to zoom in.
- Arrow keys move the white highlight, `Enter` zooms into it; double-click zooms with the mouse.
- `Esc` / `Backspace` zoom out one level, keeping the box you came from highlighted.
- In the table (`t`), `Enter` on a row zooms into that server or client.
- Filter, sort, size and color apply at every level.

## Views

Every view shows what is in the current zoom focus:

| Key | View |
|---|---|
| `1` | map: the boxes; at client level, a detail page with a traffic graph of the last 2 minutes |
| `2` | connections: one row per connection (client port ↔ server port) with TCP state (`syn`, `open`, `closing`, `closed`, `reset`, or `active` when the handshake wasn't seen), rates, totals, packets, age and idle time; `Enter` zooms into its client |
| `3` | packet dump: time, direction (cyan = client → server, orange = back), TCP flags, seq/ack, payload length; `p` pauses so you can scroll |
| `4` | stream: follow one connection and read its reassembled payload (see below) |
| `t` | summary table of servers and clients |

Packets are recorded for the dump (last 2000) only while zoomed into a server or client, or while the dump is open.

### Following a stream

In the connections view (`2`), select a row and press `f` (or press `4` to follow the busiest connection in focus). netmon then collects the full payload of **that one connection** and puts it back together like Wireshark's "Follow TCP stream":

- each direction is reassembled by TCP sequence number; out-of-order segments wait for the hole before them, retransmitted bytes are counted once, and a hole still open after 1 s is shown as `[gap: N bytes missing]`;
- the overview bars show, per direction, which byte ranges arrived (█), are missing (░ red) or are waiting out of order (▒ yellow), plus totals for gaps, retransmissions and reordering;
- the conversation is shown in order, client → server in cyan, server → client in orange, as text or hex (`h`); encrypted/binary data is summarized in text mode;
- UDP is shown datagram by datagram.

Following starts with the next packet, so data sent earlier is not shown (marked "joined mid-connection"). The payload is kept in memory only while the stream view is open, at most 1 MiB per direction, and is discarded when you leave it (`Esc` goes back to the connections). Most internet traffic is TLS-encrypted, so this is most useful for plain protocols, local devices and the start of a TLS handshake.

**Payload bytes are opt-in:** `x` (or `--payload`) keeps the first 64 bytes of each packet's payload and shows them as hex + text in the dump. They are held in memory only, never written to disk. Most internet traffic is encrypted, so this is mainly useful for plain protocols (HTTP, DNS, MQTT, …).

## Keys

| Key | Action |
|---|---|
| `/` | filter (Enter apply, Esc close; Esc at the top level clears it) |
| `s` / `r` | cycle sort (size, name, clients, port) / reverse |
| `m` | size by current rate ↔ total bytes |
| `l` | size scale: sqrt → log → linear |
| `c` | color by distance → rate heat → protocol → service |
| `g` | one box per server host ↔ per host+port+protocol |
| `v` | zoom to: all → intranet → internet |
| `Space` / arrows + `Enter` / `Esc` | zoom with letters / select and zoom / back (see above) |
| `t` | table view |
| `1` / `2` / `3` / `4` | map / connections / packet dump / stream |
| `f` / `h` | follow the selected connection's stream / hex ↔ text in the stream view |
| `x` | payload capture on/off (first 64 bytes, opt-in) |
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
