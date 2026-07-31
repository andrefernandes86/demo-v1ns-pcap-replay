#!/usr/bin/env python3
"""
For each pcap, identify the dominant local (RFC1918) IP address(es) — the
capture's "this machine" endpoint(s) — and rewrite them to a fixed target IP
via tcprewrite, leaving every other address (source or destination)
untouched.

Local IP is picked in tiers, falling through as needed:
  1. Frequency: a single private IP clearly dominates packet count.
  2. TCP handshake: the private IP that sends the bare SYN is the client.
  3. Port role: the private IP using an ephemeral port against a known
     service port (SMB, RPC, Kerberos, DNP3, Modbus, TFTP, a Metasploit
     handler, ...) is the client. If several private IPs are all clients of
     one recurring server IP (e.g. multiple hosts polling one PLC), all of
     them are treated as local and rewritten; the server stays untouched.
  4. First packet: for port-less protocols (ICMP, ARP), whoever sends the
     first captured frame is treated as the initiator/local.
Files where none of these resolve a clear winner are reported, not
rewritten, so they can be checked by hand.
"""
import argparse
import ipaddress
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
IP_TOKEN_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\.\d{1,5})?")
LINE_RE = re.compile(r"IP6?\s+(\S+)\s+>\s+(\S+):")
SYN_RE = re.compile(r"IP6?\s+(\S+)\s+>\s+(\S+):.*Flags \[S\]")
NON_ROUTABLE = {"0.0.0.0", "255.255.255.255"}
KNOWN_SERVER_PORTS = {
    20, 21, 22, 23, 25, 53, 69, 80, 88, 102, 135, 139, 143, 389, 443, 445,
    502, 2404, 3389, 4444, 20000, 44818, 47808,
}


def is_lfs_pointer(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(60).startswith(b"version https://git-lfs.github.com/spec/v1")
    except Exception:
        return False


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private and not addr.is_multicast and not addr.is_loopback
    except ValueError:
        return False


def token_to_ip(tok: str):
    """'172.16.8.195.60209' -> '172.16.8.195' ; '172.16.8.195' -> itself."""
    candidate = ".".join(tok.split(".")[:4])
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return None


def split_ip_port(tok: str):
    ip = token_to_ip(tok)
    if ip is None:
        return None, None
    rest = tok[len(ip) + 1 :] if tok.startswith(ip + ".") else ""
    return ip, (int(rest) if rest.isdigit() else None)


def gather_files(sets):
    files = []
    for s in sets:
        d = ROOT / s
        if not d.is_dir():
            continue
        for pat in ("*.pcap", "*.pcapng"):
            files.extend(sorted(d.glob(pat)))
    return files


def analyze(pcap: Path):
    try:
        proc = subprocess.run(
            ["tcpdump", "-r", str(pcap), "-nn"], capture_output=True, text=True, timeout=180
        )
    except Exception as e:
        return None, f"tcpdump error: {e}"
    if proc.returncode != 0 and not proc.stdout:
        return None, f"tcpdump failed: {proc.stderr.strip()[:150]}"

    counts = Counter()
    client_votes = Counter()
    server_votes = Counter()
    syn_client_ip = None
    first_src_ip = None

    for line in proc.stdout.splitlines():
        m = LINE_RE.search(line)
        if not m:
            continue
        src_ip, src_port = split_ip_port(m.group(1))
        dst_ip, dst_port = split_ip_port(m.group(2))

        for ip in (src_ip, dst_ip):
            if ip and ip not in NON_ROUTABLE:
                counts[ip] += 1

        if first_src_ip is None and src_ip:
            first_src_ip = src_ip

        if syn_client_ip is None and SYN_RE.search(line):
            syn_client_ip = src_ip

        if src_port is not None and dst_port is not None and src_ip and dst_ip:
            if dst_port in KNOWN_SERVER_PORTS and src_port not in KNOWN_SERVER_PORTS:
                client_votes[src_ip] += 1
                server_votes[dst_ip] += 1
            elif src_port in KNOWN_SERVER_PORTS and dst_port not in KNOWN_SERVER_PORTS:
                client_votes[dst_ip] += 1
                server_votes[src_ip] += 1

    return {
        "counts": counts,
        "client_votes": client_votes,
        "server_votes": server_votes,
        "syn_client_ip": syn_client_ip,
        "first_src_ip": first_src_ip,
    }, None


def pick_local(a):
    counts = a["counts"]
    private_counts = {ip: c for ip, c in counts.items() if is_private(ip)}
    if not private_counts:
        return None, "no-private-ip-found"
    ranked = sorted(private_counts.items(), key=lambda kv: -kv[1])
    top_ip, top_count = ranked[0]

    if not (len(ranked) > 1 and ranked[1][1] > 0.5 * top_count):
        return [top_ip], f"ok, count={top_count}"

    # Ambiguous by frequency alone — try progressively weaker tiebreaks.
    syn_client_ip = a["syn_client_ip"]
    if syn_client_ip and syn_client_ip in private_counts:
        return [syn_client_ip], f"ok (client-tiebreak), count={private_counts[syn_client_ip]}"

    client_votes, server_votes = a["client_votes"], a["server_votes"]
    client_side = {ip for ip in private_counts if client_votes.get(ip, 0) > server_votes.get(ip, 0)}
    server_side = {ip for ip in private_counts if server_votes.get(ip, 0) > client_votes.get(ip, 0)}
    if client_side and server_side and not (client_side & server_side):
        if len(client_side) == 1:
            ip = next(iter(client_side))
            return [ip], f"ok (port-role tiebreak), count={private_counts[ip]}"
        return sorted(client_side), f"ok (multi-client port-role tiebreak, server={sorted(server_side)})"

    first_src_ip = a["first_src_ip"]
    if first_src_ip and first_src_ip in private_counts:
        return [first_src_ip], f"ok (first-packet tiebreak), count={private_counts[first_src_ip]}"

    return [top_ip], f"ambiguous (count={top_count})"


def rewrite(infile: Path, outfile: Path, local_ips, target: str):
    """Chain one tcprewrite pnat pass per local IP so multiple client IPs in
    the same file (e.g. several hosts polling one PLC) all collapse to the
    same target address."""
    outfile.parent.mkdir(parents=True, exist_ok=True)
    current_in = infile
    tmp_files = []
    try:
        for i, ip in enumerate(local_ips):
            is_last = i == len(local_ips) - 1
            dest = outfile if is_last else outfile.with_suffix(f".step{i}.pcap")
            cmd = [
                "tcprewrite",
                f"--pnat={ip}/32:{target}/32",
                "--fixcsum",
                f"--infile={current_in}",
                f"--outfile={dest}",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                return False, r.stderr.strip()[:200]
            if not is_last:
                tmp_files.append(dest)
            current_in = dest
        return True, None
    finally:
        for t in tmp_files:
            t.unlink(missing_ok=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--set", choices=["it", "ot", "all"], default="all")
    ap.add_argument("--target", default="192.168.50.222", help="IP to rewrite the local address(es) to")
    ap.add_argument("--out-dir", default="localized", help="output directory (mirrors it/ ot/ structure)")
    ap.add_argument("--apply", action="store_true", help="run tcprewrite; without this, only report")
    args = ap.parse_args()

    sets = ["it", "ot"] if args.set == "all" else [args.set]
    files = gather_files(sets)
    out_root = ROOT / args.out_dir

    rows = []
    for f in files:
        rel_set = f.parent.name
        if is_lfs_pointer(f):
            rows.append((rel_set, f.name, "SKIP", "-", "lfs-pointer-stub"))
            continue

        a, err = analyze(f)
        if err:
            rows.append((rel_set, f.name, "SKIP", "-", err))
            continue

        local_ips, detail = pick_local(a)
        if local_ips is None:
            rows.append((rel_set, f.name, "SKIP", "-", detail))
            continue
        if detail.startswith("ambiguous"):
            rows.append((rel_set, f.name, "REVIEW", ",".join(local_ips), detail))
            continue

        rows.append((rel_set, f.name, "REWRITE", ",".join(local_ips), detail))

        if args.apply:
            ok, rewrite_err = rewrite(f, out_root / rel_set / f.name, local_ips, args.target)
            if not ok:
                rows[-1] = (rel_set, f.name, "FAILED", ",".join(local_ips), rewrite_err)

    width = max(len(r[1]) for r in rows) if rows else 20
    ipwidth = max((len(r[3]) for r in rows), default=16)
    print(f"{'set':4} {'file':<{width}} {'action':8} {'local_ip':<{ipwidth}} detail")
    counts_summary = Counter(r[2] for r in rows)
    for s, name, action, ip, detail in rows:
        print(f"{s:4} {name:<{width}} {action:8} {ip:<{ipwidth}} {detail}")
    print()
    print("Summary: " + ", ".join(f"{k}={v}" for k, v in counts_summary.items()))
    if args.apply:
        print(f"Rewritten files written under: {out_root}")


if __name__ == "__main__":
    main()
