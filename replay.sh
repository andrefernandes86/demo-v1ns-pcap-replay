#!/bin/sh
# Replays both the IT and OT pcap sets via replay.py's live dashboard.
# Run ./setup.sh once beforehand to install dependencies.
DIR="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$DIR/replay.py" --set all "$@"
