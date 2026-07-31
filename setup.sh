#!/usr/bin/env bash
# Installs and configures everything replay.py needs: tcpreplay, git-lfs
# (to pull the real pcap binaries), and the python 'rich' dashboard library.
set -e

echo "==> Installing system dependencies (tcpreplay, git-lfs, tcpdump, python3)..."
sudo apt-get update -y
sudo apt-get install -y tcpreplay git-lfs tcpdump python3 python3-pip iproute2

echo "==> Pulling real pcap binaries via git-lfs..."
git lfs install --local
git lfs pull

echo "==> Installing python dashboard dependency (rich)..."
if ! python3 -c "import rich" >/dev/null 2>&1; then
    sudo apt-get install -y python3-rich 2>/dev/null \
        || python3 -m pip install --user --break-system-packages rich 2>/dev/null \
        || python3 -m pip install --user rich
fi

chmod +x replay.py replay.sh it/replay.sh ot/replay.sh 2>/dev/null || true

echo "==> Setup complete. Run: sudo ./replay.py --set all"
