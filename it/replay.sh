#!/bin/sh
# Replays only the IT pcap set via replay.py's live dashboard.
DIR="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 "$DIR/replay.py" --set it "$@"
