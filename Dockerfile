FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpreplay tcpdump python3 python3-pip iproute2 sudo ca-certificates \
    && python3 -m pip install --no-cache-dir rich \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /data
# Run ./setup.sh on the host first so git-lfs pulls the real pcap binaries
# before the build context is copied in.
COPY it /data/it
COPY ot /data/ot
COPY replay.py /data/replay.py

# Requires --net host --cap-add=NET_RAW --cap-add=NET_ADMIN so packets
# actually egress the host's physical interface instead of a virtual bridge.
ENTRYPOINT ["python3", "replay.py"]
CMD ["--set", "all"]
