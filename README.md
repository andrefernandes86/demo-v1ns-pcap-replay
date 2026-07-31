# demo-v1ns-pcap-replay

Replays IT and OT attack/protocol pcaps out a real network interface via
`tcpreplay`, so a network sensor on the wire can detect the traffic. Includes
a live terminal dashboard showing per-file status, packets, bytes, and rate.

## Bare metal (recommended)

```
./setup.sh          # installs tcpreplay, git-lfs, pulls real pcap binaries, installs the dashboard dep
sudo ./replay.py --set all      # or --set it / --set ot
```

The interface is auto-detected from the default route. Override with
`--iface <name>` or `IFACE=<name> sudo -E ./replay.py`.

Files replay at top speed and in parallel by default (`--jobs 8`). Use
`--jobs N` to change concurrency, or `--realtime` to replay each pcap at its
original (often much slower) capture timing instead.

Subset wrappers are still available: `./it/replay.sh`, `./ot/replay.sh`.

## Normalizing the local IP (localize.py)

Each pcap captures traffic between a specific "local" test host (a private
RFC1918 address) and the remote/malicious side. `localize.py` finds that
dominant local address per file (by packet frequency) and rewrites it to a
single fixed IP, leaving every other address — source or destination —
exactly as originally captured.

```
python3 localize.py --set all                 # dry run: reports what it *would* do
python3 localize.py --set all --apply         # writes rewritten copies under ./localized/
sudo ./replay.py --set all --base localized   # replay the rewritten set
```

Default target is `192.168.50.222`; override with `--target <ip>`. Files
where no private IP is found, or where two private IPs are similarly
dominant (ambiguous — can't tell which one is "local"), are reported but not
rewritten so you can check them by hand. `./localized/` is git-ignored —
it's a derived output, not committed.

**Switch port-security note:** `tcpreplay` sends frames using the *original*
source MAC addresses captured in each pcap, not this host's real NIC MAC. If
the switch port is running port-security/MAC-limiting, a burst of unfamiliar
MACs from one physical port can trip a violation and get the port
err-disabled — which looks like the host dropping off the network entirely.
Confirm port-security is off (or the port's in a monitoring/trunk mode that
tolerates it) before running this against a production switch.

## Docker

`--net host` (plus raw-socket capabilities) is required — without it,
packets stay inside Docker's virtual bridge network and never reach the
physical wire a sensor would be watching.

```
./setup.sh                       # pulls real pcap binaries via git-lfs first
docker build -t demo-v1ns-pcap-replay .
docker run --rm -it --net host --cap-add=NET_RAW --cap-add=NET_ADMIN \
    demo-v1ns-pcap-replay --set all
```
