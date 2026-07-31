FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpreplay tcpdump python3 python3-pip iproute2 sudo ca-certificates \
    && python3 -m pip install --no-cache-dir rich \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data
COPY categories.py sources.py mitre.py pcap_engine.py fetch_pcaps.py localize.py replay_cron.py replay_menu.py /data/
COPY pcaps /data/pcaps

# Requires --net host --cap-add=NET_RAW --cap-add=NET_ADMIN so packets
# actually egress the host's physical interface instead of a virtual bridge.
ENTRYPOINT ["python3", "replay_cron.py"]
CMD ["--categories", "all"]
