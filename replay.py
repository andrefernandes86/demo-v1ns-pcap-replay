#!/usr/bin/env python3
"""
pcap replay orchestrator — replays IT/OT pcap sets out a real network
interface via tcpreplay, with a live terminal dashboard.
"""
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    print("Missing dependency 'rich'. Run ./setup.sh first.", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent

STATS_RE = re.compile(
    r"Actual:\s+([\d,]+)\s+packets\s+\(([\d,]+)\s+bytes\)\s+sent\s+in\s+([\d.]+)\s+seconds"
)
RATE_RE = re.compile(r"Rated:\s+[\d.]+\s+bps,\s+[\d.]+\s+Mbps,\s+([\d.]+)\s+pps")

STATUS_COLOR = {
    "queued": "grey58",
    "running": "yellow",
    "done": "green",
    "failed": "red",
    "skipped": "dark_orange",
}


def detect_iface() -> str:
    env = os.environ.get("IFACE")
    if env:
        return env
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def is_lfs_pointer(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(60).startswith(b"version https://git-lfs.github.com/spec/v1")
    except Exception:
        return False


def gather_files(sets):
    files = []
    for s in sets:
        d = ROOT / s
        if not d.is_dir():
            continue
        for pat in ("*.pcap", "*.pcapng"):
            files.extend(sorted(d.glob(pat)))
    return files


def ensure_root():
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)


def render(iface, rows, files, totals):
    t = Table(expand=True)
    t.add_column("File")
    t.add_column("Status")
    t.add_column("Packets", justify="right")
    t.add_column("Bytes", justify="right")
    t.add_column("Rate (pps)", justify="right")
    t.add_column("Duration (s)", justify="right")
    for name, r in rows.items():
        color = STATUS_COLOR[r["status"]]
        t.add_row(name, f"[{color}]{r['status']}[/{color}]", r["packets"], r["bytes"], r["pps"], r["dur"])

    summary = (
        f"Files: {len(files)}   [green]OK: {totals['ok']}[/green]   "
        f"[red]Failed: {totals['fail']}[/red]   [dark_orange]Skipped: {totals['skip']}[/dark_orange]   "
        f"Total packets: {totals['packets']}   Total bytes: {totals['bytes']}"
    )
    return Panel(t, title=f"[bold]pcap replay[/bold] — interface [cyan]{iface}[/cyan]", subtitle=summary)


def replay(iface, files, console):
    rows = {f.name: {"status": "queued", "packets": "-", "bytes": "-", "pps": "-", "dur": "-"} for f in files}
    totals = {"packets": 0, "bytes": 0, "ok": 0, "fail": 0, "skip": 0}

    with Live(render(iface, rows, files, totals), console=console, refresh_per_second=4) as live:
        for f in files:
            name = f.name

            if is_lfs_pointer(f):
                rows[name]["status"] = "skipped"
                totals["skip"] += 1
                live.update(render(iface, rows, files, totals))
                continue

            rows[name]["status"] = "running"
            live.update(render(iface, rows, files, totals))

            cmd = ["tcpreplay", f"--intf1={iface}", "--stats=1", str(f)]
            last_stats = None
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            except FileNotFoundError:
                console.print("[red]tcpreplay not found — run ./setup.sh first[/red]")
                sys.exit(1)

            for line in proc.stdout:
                m = STATS_RE.search(line)
                if m:
                    last_stats = m
                    rows[name]["packets"] = m.group(1)
                    rows[name]["bytes"] = m.group(2)
                    rows[name]["dur"] = m.group(3)
                    live.update(render(iface, rows, files, totals))
                rm = RATE_RE.search(line)
                if rm:
                    rows[name]["pps"] = rm.group(1)
                    live.update(render(iface, rows, files, totals))

            proc.wait()
            if proc.returncode == 0:
                rows[name]["status"] = "done"
                totals["ok"] += 1
                if last_stats:
                    totals["packets"] += int(last_stats.group(1).replace(",", ""))
                    totals["bytes"] += int(last_stats.group(2).replace(",", ""))
            else:
                rows[name]["status"] = "failed"
                totals["fail"] += 1

            live.update(render(iface, rows, files, totals))

    console.print(render(iface, rows, files, totals))


def main():
    ap = argparse.ArgumentParser(description="Replay IT/OT pcap sets out a network interface.")
    ap.add_argument("--set", choices=["it", "ot", "all"], default="all", help="which pcap set to replay")
    ap.add_argument("--iface", help="network interface to send on (default: auto-detected default route iface)")
    args = ap.parse_args()

    ensure_root()

    iface = args.iface or detect_iface()
    sets = ["it", "ot"] if args.set == "all" else [args.set]
    files = gather_files(sets)

    if not files:
        print("No pcap files found for set(s): " + ", ".join(sets), file=sys.stderr)
        sys.exit(1)

    console = Console()
    replay(iface, files, console)


if __name__ == "__main__":
    main()
