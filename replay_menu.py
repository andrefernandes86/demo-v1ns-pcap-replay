#!/usr/bin/env python3
"""
Interactive pcap replay: pick which categories to run from a menu, then
watch a live dashboard. Defaults to the IP-normalized ./localized/ set (see
localize.py) if present, else the raw ./pcaps/ set.
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import categories as cat
import pcap_engine as engine

try:
    from rich.console import Console
except ImportError:
    print("Missing dependency 'rich'. Run ./setup.sh first.", file=sys.stderr)
    sys.exit(1)


def resolve_base(explicit):
    if explicit:
        return ROOT / explicit
    localized = ROOT / "localized"
    if localized.is_dir() and any(localized.iterdir()):
        return localized
    return cat.PCAPS_DIR


def prompt_categories(console, base):
    counts = cat.category_counts(base=base)
    keys = list(cat.CATEGORIES)

    console.print("\n[bold]Select pcap categories to replay[/bold]\n")
    for i, key in enumerate(keys, 1):
        label, desc, malicious = cat.CATEGORIES[key]
        n = counts.get(key, 0)
        tag = "[red]malicious[/red]" if malicious else "[green]benign[/green]"
        avail = f"{n} file{'s' if n != 1 else ''}" if n else "[dim]none available[/dim]"
        console.print(f"  [cyan]{i:2d}[/cyan]. {label:<20} {tag:<20} {desc}  ({avail})")
    console.print(f"\n  [cyan]{len(keys)+1:2d}[/cyan]. All categories\n")

    while True:
        raw = console.input("Enter numbers separated by commas (e.g. 1,3,7), or 'all': ").strip().lower()
        if raw in ("all", str(len(keys) + 1)):
            return list(keys)
        try:
            idxs = [int(x.strip()) for x in raw.split(",") if x.strip()]
            chosen = [keys[i - 1] for i in idxs if 1 <= i <= len(keys)]
        except (ValueError, IndexError):
            chosen = []
        if chosen:
            return chosen
        console.print("[red]No valid selection — try again.[/red]")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--categories", help="skip the menu; comma-separated category list, or 'all'")
    ap.add_argument("--iface", help="interface to send on (default: auto-detected default route iface)")
    ap.add_argument("--jobs", "-j", type=int, default=8, help="concurrent replays (default: 8)")
    ap.add_argument("--realtime", action="store_true", help="replay at original capture timing (slower)")
    ap.add_argument("--base", help="override pcap source dir (default: ./localized if present, else ./pcaps)")
    args = ap.parse_args()

    engine.ensure_root()

    console = Console()
    base = resolve_base(args.base)

    if args.categories:
        selected = [c.strip() for c in args.categories.split(",") if c.strip()]
        if "all" in selected:
            selected = list(cat.CATEGORIES)
        unknown = [c for c in selected if c not in cat.CATEGORIES]
        if unknown:
            console.print(f"[red]Unknown categories: {', '.join(unknown)}[/red]")
            sys.exit(2)
    else:
        selected = prompt_categories(console, base)

    files = cat.gather_files(selected, base=base)
    if not files:
        console.print(f"[red]No pcap files found for: {', '.join(selected)} under {base}[/red]")
        sys.exit(1)

    iface = args.iface or engine.detect_iface()
    jobs = max(1, min(args.jobs, len(files)))

    console.print(f"\nReplaying {len(files)} file(s) from categories: {', '.join(selected)}\n")
    totals = engine.run_live(
        iface, files, jobs, topspeed=not args.realtime, console=console,
        title_suffix=f" [{','.join(selected)}]",
    )
    sys.exit(0 if totals["fail"] == 0 else 1)


if __name__ == "__main__":
    main()
