# demo-v1ns-pcap-replay

Replays categorized sample pcaps out a real network interface via
`tcpreplay`, so a network sensor, IPS, NDR, or ATP solution on the wire can
detect the traffic — benign application traffic (DNS, HTTP, FTP, SMB,
database) alongside a broad spread of malicious activity (exploits,
malware, C2, exfiltration, cryptomining, web shells, hacking tools, scans,
and real ICS/OT attacks) mapped to MITRE ATT&CK.

## Setup

```
./setup.sh
```

Installs `tcpreplay`/`tcpdump`/`rich`, then runs `fetch_pcaps.py` to
validate every pcap under `pcaps/` and download the curated sample set
(see below).

## Categories

Pcaps live under `pcaps/<category>/`:

| Category | Type | Contents |
|---|---|---|
| `dns` | benign | DNS queries/responses |
| `http` | benign | Web browsing traffic |
| `ftp` | benign | FTP sessions |
| `smb` | benign | SMB/CIFS file sharing |
| `database` | benign | MySQL, MSSQL (TDS), PostgreSQL traffic |
| `exploits` | malicious | CVE exploitation (incl. Log4Shell), vulnerability probing, IDS evasion |
| `malware` | malicious | Ransomware, trojans, malicious email attachments |
| `c2` | malicious | Command-and-control beaconing (Cobalt Strike, Sliver) |
| `hacking-tools` | malicious | Mimikatz, PsExec, RDP tunneling, lateral movement |
| `scans` | malicious | Port/service scanning |
| `exfiltration` | malicious | DNS tunneling and other data-exfiltration techniques |
| `cryptomining` | malicious | Stratum protocol cryptomining/cryptojacking traffic |
| `webshells` | malicious | Post-exploitation web shell traffic |
| `ics-scada` | benign | DNP3, Modbus, and other OT protocol traffic (protocol conformance, not attacks) |
| `ics-attacks` | malicious | Genuine ICS/OT malware and attack traffic (TRITON/TRISIS) |

Run `./replay_menu.py` with no arguments to see live per-category file
counts and MITRE ATT&CK technique tags.

## MITRE ATT&CK mapping

Every malicious pcap is tagged with the network-observable ATT&CK
technique(s) it demonstrates — Enterprise ATT&CK for IT-side categories,
[ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) for the OT ones —
in `mitre.py`. See the full per-file mapping:

```
./replay_menu.py --mitre-report
```

Covers reconnaissance/scanning (T1595, T1046), initial access (T1190,
T1566), exploitation (T1210, T1203), credential access (T1003, T1558),
lateral movement (T1021, T1570), persistence (T1505.003 web shells),
command and control (T1071, T1572, T1219), exfiltration (T1041, T1048.003),
impact (T1486 ransomware, T1496 cryptojacking), and ICS-specific techniques
like unauthorized command messages (T0855) and manipulation of control
(T0831). The homogeneous `ics-scada` protocol-conformance set is tagged by
filename pattern (read vs. write/operate commands) rather than hand-tagged
file by file — see `mitre.py` for the exact rules.

## Two runners

**`replay_menu.py`** — interactive. Shows a numbered category menu, you
pick which to replay (comma-separated, or "all"), then watch a live
per-file dashboard (status/packets/bytes/rate).

```
sudo ./replay_menu.py
sudo ./replay_menu.py --categories dns,http,exploits    # skip the menu
```

**`replay_cron.py`** — unattended, no prompts, no TTY dependency, plain
timestamped log lines. For scheduled/cron runs.

```
sudo ./replay_cron.py --categories all
```

Example crontab entry:
```
0 * * * * /path/to/replay_cron.py --categories all >> /var/log/pcap-replay.log 2>&1
```
Since `tcpreplay` needs raw-socket privileges, both scripts re-exec
themselves under `sudo` if not already root. Under cron there's no TTY for
a password prompt, so either run the cron job as root or configure a
NOPASSWD sudoers entry for this script.

Both scripts share these flags:
- `--iface <name>` — network interface (default: auto-detected from the default route)
- `--jobs N` / `-j N` — concurrent replays (default: 8)
- `--realtime` — replay at each pcap's original capture timing instead of top speed (much slower; top speed + parallel is the default)
- `--base <dir>` — pcap source directory (default: `./localized` if present, else `./pcaps`)

## Normalizing the local IP (localize.py)

Each pcap captures traffic between a specific "local" test host (a private
RFC1918 address) and the remote/malicious side. `localize.py` finds that
local address per file — by packet frequency, then TCP handshake
initiator, then client/server port role (SMB, RPC, Kerberos, DNP3, Modbus,
TFTP, a Metasploit handler, etc.), then first-packet source as a last
resort for port-less protocols like ICMP — and rewrites it to a single
fixed IP via `tcprewrite`, leaving every other address (source or
destination) exactly as originally captured. When several private IPs are
all clients of one recurring server (e.g. multiple hosts polling a single
PLC), all of them are rewritten and the server stays untouched.

```
python3 localize.py --categories all              # dry run: reports what it *would* do
python3 localize.py --categories all --apply       # writes rewritten copies under ./localized/
sudo ./replay_menu.py --base localized             # (or replay_cron.py) replay the rewritten set
```

Default target is `192.168.50.222`; override with `--target <ip>`. Files
where no private IP is found, or where the tiebreaks can't resolve a clear
winner, are reported as `SKIP`/`REVIEW` and left untouched so they can be
checked by hand. `./localized/` is git-ignored — it's a derived output,
not committed. Both runners prefer `./localized/` automatically when it
exists.

**Switch port-security note:** `tcpreplay` sends frames using the *original*
source MAC addresses captured in each pcap, not this host's real NIC MAC. If
the switch port is running port-security/MAC-limiting, a burst of unfamiliar
MACs from one physical port can trip a violation and get the port
err-disabled — which looks like the host dropping off the network entirely.
Confirm port-security is off (or the port's in a monitoring/trunk mode that
tolerates it) before running this against a production switch.

## Maintaining the pcap set (fetch_pcaps.py)

```
python3 fetch_pcaps.py               # validate + download missing samples
python3 fetch_pcaps.py --check-only  # validate only, no downloads
```

Deletes anything under `pcaps/` that isn't a real, readable capture (empty
file, HTML error page, corrupt data), then downloads every entry in
`sources.py` not already present, verifying each download the same way
before keeping it. `sources.py` documents where each sample comes from —
all public research/education sources (Practical Packet Analysis book
captures, the Wireshark wiki SampleCaptures mirror, malware-traffic-analysis.net,
Elastic's own examples repo, an academic cryptomining-detection dataset,
Nozomi Networks' own published TRITON/TRISIS capture, and public C2/webshell
research projects). Add new entries there to grow any category — pair a new
entry with a `mitre.py` tag if it demonstrates a specific technique.

## Docker

`--net host` (plus raw-socket capabilities) is required — without it,
packets stay inside Docker's virtual bridge network and never reach the
physical wire a sensor would be watching.

```
./fetch_pcaps.py                 # populate pcaps/ before building
docker build -t demo-v1ns-pcap-replay .
docker run --rm -it --net host --cap-add=NET_RAW --cap-add=NET_ADMIN \
    demo-v1ns-pcap-replay --categories all
```
