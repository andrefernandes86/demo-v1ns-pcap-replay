#!/usr/bin/env python3
"""
For each pcap, identify the dominant local (RFC1918) IP address — the
capture's "this machine" endpoint — and rewrite it to a fixed target IP via
tcprewrite, leaving every other address (source or destination) untouched.

Local IP is picked by frequency: the private-range address that appears in
the most packets. Rewrite only happens when that pick is clearly dominant
over any other private IP in the same file; ambiguous or IP-less files are
reported, not rewritten.
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
SYN_RE = re.compile(r"IP6?\s+(\S+)\s+>\s+(\S+):.*Flags \[S\]")
NON_ROUTABLE = {"0.0.0.0", "255.255.255.255"}


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
        return None, None, f"tcpdump error: {e}"
    if proc.returncode != 0 and not proc.stdout:
        return None, None, f"tcpdump failed: {proc.stderr.strip()[:150]}"

    counts = Counter()
    syn_client_ip = None
    for line in proc.stdout.splitlines():
        for tok in IP_TOKEN_RE.findall(line):
            ip = token_to_ip(tok)
            if ip and ip not in NON_ROUTABLE:
                counts[ip] += 1
        if syn_client_ip is None:
            m = SYN_RE.search(line)
            if m:
                syn_client_ip = token_to_ip(m.group(1))
    return counts, syn_client_ip, None


def pick_local(counts: Counter, syn_client_ip):
    private_counts = {ip: c for ip, c in counts.items() if is_private(ip)}
    if not private_counts:
        return None, None, "no-private-ip-found"
    ranked = sorted(private_counts.items(), key=lambda kv: -kv[1])
    local_ip, local_count = ranked[0]
    if len(ranked) > 1 and ranked[1][1] > 0.5 * local_count:
        # Two comparably-active private IPs (e.g. a request/response protocol
        # conversation) — frequency alone can't tell local from other. Break
        # the tie by TCP handshake: the SYN sender is treated as local.
        if syn_client_ip and syn_client_ip in private_counts:
            return syn_client_ip, private_counts[syn_client_ip], "ok (client-tiebreak)"
        return local_ip, local_count, "ambiguous"
    return local_ip, local_count, "ok"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--set", choices=["it", "ot", "all"], default="all")
    ap.add_argument("--target", default="192.168.50.222", help="IP to rewrite the local address to")
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

        counts, syn_client_ip, err = analyze(f)
        if err:
            rows.append((rel_set, f.name, "SKIP", "-", err))
            continue

        local_ip, local_count, verdict = pick_local(counts, syn_client_ip)
        if verdict == "no-private-ip-found":
            rows.append((rel_set, f.name, "SKIP", "-", verdict))
            continue
        if verdict == "ambiguous":
            rows.append((rel_set, f.name, "REVIEW", local_ip, f"ambiguous (count={local_count})"))
            continue

        rows.append((rel_set, f.name, "REWRITE", local_ip, f"{verdict}, count={local_count}"))

        if args.apply:
            out_dir = out_root / rel_set
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f.name
            cmd = [
                "tcprewrite",
                f"--pnat={local_ip}/32:{args.target}/32",
                "--fixcsum",
                f"--infile={f}",
                f"--outfile={out_file}",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                rows[-1] = (rel_set, f.name, "FAILED", local_ip, r.stderr.strip()[:150])

    width = max(len(r[1]) for r in rows) if rows else 20
    print(f"{'set':4} {'file':<{width}} {'action':8} {'local_ip':16} detail")
    counts_summary = Counter(r[2] for r in rows)
    for s, name, action, ip, detail in rows:
        print(f"{s:4} {name:<{width}} {action:8} {ip:16} {detail}")
    print()
    print("Summary: " + ", ".join(f"{k}={v}" for k, v in counts_summary.items()))
    if args.apply:
        print(f"Rewritten files written under: {out_root}")


if __name__ == "__main__":
    main()
