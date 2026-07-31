"""
Shared tcpreplay orchestration engine used by both replay_cron.py
(unattended) and replay_menu.py (interactive). Runs pcaps concurrently at
top speed by default and reports per-file packets/bytes/rate.

Two render modes:
  run_live()  - a rich Live dashboard table (interactive TTY)
  run_plain() - one plain timestamped log line per event (cron/log-safe)
"""
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

STATS_RE = re.compile(
    r"Actual:\s+([\d,]+)\s+packets\s+\(([\d,]+)\s+bytes\)\s+sent\s+in\s+([\d.]+)\s+seconds"
)
RATE_RE = re.compile(r"Rated:\s+[\d.]+\s+bps,\s+[\d.]+\s+Mbps,\s+([\d.]+)\s+pps")
STATUS_COLOR = {
    "queued": "grey58", "running": "yellow", "done": "green",
    "failed": "red", "skipped": "dark_orange",
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


def is_lfs_pointer(path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(60).startswith(b"version https://git-lfs.github.com/spec/v1")
    except Exception:
        return False


def ensure_root():
    if os.geteuid() != 0:
        os.execvp("sudo", ["sudo", "-E", sys.executable] + sys.argv)


def _tcpreplay_cmd(iface, topspeed, path):
    cmd = ["tcpreplay", f"--intf1={iface}", "--stats=1"]
    if topspeed:
        cmd.append("-t")
    cmd.append(str(path))
    return cmd


def _run_one(f, iface, topspeed, on_event):
    """on_event(name, status, packets, bytes_, pps, dur) called on each update."""
    name = f.name
    if is_lfs_pointer(f):
        on_event(name, "skipped", None, None, None, None)
        return "skipped", None, None

    on_event(name, "running", None, None, None, None)
    try:
        proc = subprocess.Popen(
            _tcpreplay_cmd(iface, topspeed, f), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
    except FileNotFoundError:
        on_event(name, "failed", None, None, None, None)
        return "failed", None, None

    last_stats = None
    for line in proc.stdout:
        m = STATS_RE.search(line)
        rm = RATE_RE.search(line)
        if m:
            last_stats = m
        if m or rm:
            on_event(
                name, "running",
                m.group(1) if m else (last_stats.group(1) if last_stats else None),
                m.group(2) if m else (last_stats.group(2) if last_stats else None),
                rm.group(1) if rm else None,
                m.group(3) if m else (last_stats.group(3) if last_stats else None),
            )

    proc.wait()
    if proc.returncode == 0:
        packets = int(last_stats.group(1).replace(",", "")) if last_stats else 0
        bytes_ = int(last_stats.group(2).replace(",", "")) if last_stats else 0
        on_event(name, "done", last_stats.group(1) if last_stats else "-", last_stats.group(2) if last_stats else "-", None, last_stats.group(3) if last_stats else "-")
        return "done", packets, bytes_
    on_event(name, "failed", None, None, None, None)
    return "failed", None, None


def run_live(iface, files, jobs, topspeed, console, title_suffix=""):
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel

    rows = {f.name: {"status": "queued", "packets": "-", "bytes": "-", "pps": "-", "dur": "-"} for f in files}
    totals = {"packets": 0, "bytes": 0, "ok": 0, "fail": 0, "skip": 0}
    lock = threading.Lock()

    def render():
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
        return Panel(
            t,
            title=f"[bold]pcap replay[/bold] — interface [cyan]{iface}[/cyan]{title_suffix} (jobs: {jobs})",
            subtitle=summary,
        )

    with Live(render(), console=console, refresh_per_second=4) as live:
        def on_event(name, status, packets, bytes_, pps, dur):
            with lock:
                rows[name]["status"] = status
                if packets is not None:
                    rows[name]["packets"] = packets
                if bytes_ is not None:
                    rows[name]["bytes"] = bytes_
                if pps is not None:
                    rows[name]["pps"] = pps
                if dur is not None:
                    rows[name]["dur"] = dur
                live.update(render())

        def worker(f):
            status, packets, bytes_ = _run_one(f, iface, topspeed, on_event)
            with lock:
                if status == "done":
                    totals["ok"] += 1
                    totals["packets"] += packets
                    totals["bytes"] += bytes_
                elif status == "skipped":
                    totals["skip"] += 1
                else:
                    totals["fail"] += 1
                live.update(render())

        with ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = [pool.submit(worker, f) for f in files]
            for fut in as_completed(futures):
                fut.result()

    console.print(render())
    return totals


def run_plain(iface, files, jobs, topspeed, log=print):
    """Cron/log-friendly runner: one timestamped line per event, no TTY redraw."""
    lock = threading.Lock()
    totals = {"packets": 0, "bytes": 0, "ok": 0, "fail": 0, "skip": 0}

    def ts():
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def worker(f):
        def on_event(name, status, packets, bytes_, pps, dur):
            if status in ("done", "failed", "skipped"):
                with lock:
                    log(f"[{ts()}] {name}: {status}"
                        + (f" packets={packets} bytes={bytes_} dur={dur}s" if status == "done" else ""))

        status, packets, bytes_ = _run_one(f, iface, topspeed, on_event)
        with lock:
            if status == "done":
                totals["ok"] += 1
                totals["packets"] += packets
                totals["bytes"] += bytes_
            elif status == "skipped":
                totals["skip"] += 1
            else:
                totals["fail"] += 1

    log(f"[{ts()}] starting replay: iface={iface} files={len(files)} jobs={jobs} topspeed={topspeed}")
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(worker, f) for f in files]
        for fut in as_completed(futures):
            fut.result()

    log(f"[{ts()}] done: ok={totals['ok']} failed={totals['fail']} skipped={totals['skip']} "
        f"packets={totals['packets']} bytes={totals['bytes']}")
    return totals
