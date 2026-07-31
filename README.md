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

Subset wrappers are still available: `./it/replay.sh`, `./ot/replay.sh`.

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
