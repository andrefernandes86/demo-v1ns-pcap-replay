#!/usr/bin/env bash
# Installs and configures everything the tools need: tcpreplay/tcprewrite,
# tcpdump, and the python 'rich' dashboard library. Then fetches/validates
# the sample pcap set (see fetch_pcaps.py, sources.py).
set -e

echo "==> Installing system dependencies (tcpreplay, tcpdump, python3)..."
sudo apt-get update -y
sudo apt-get install -y tcpreplay tcpdump python3 python3-pip iproute2

echo "==> Installing python dashboard dependency (rich)..."
if ! python3 -c "import rich" >/dev/null 2>&1; then
    sudo apt-get install -y python3-rich 2>/dev/null \
        || python3 -m pip install --user --break-system-packages rich 2>/dev/null \
        || python3 -m pip install --user rich
fi

chmod +x replay_cron.py replay_menu.py localize.py fetch_pcaps.py 2>/dev/null || true

echo "==> Fetching/validating sample pcaps..."
python3 fetch_pcaps.py

echo "==> Setup complete."
echo "    Interactive:  sudo ./replay_menu.py"
echo "    Unattended:   sudo ./replay_cron.py --categories all"
echo "    Normalize IPs first: ./localize.py --categories all --apply"
