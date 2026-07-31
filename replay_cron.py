#!/usr/bin/env python3
"""
Unattended pcap replay for cron / scheduled runs. No prompts, no TTY
dependency, plain timestamped log lines. Defaults to the IP-normalized
./localized/ set (see localize.py) if present, else the raw ./pcaps/ set.

Example crontab entry (root, or a user with NOPASSWD sudo for this script):
    0 * * * * /path/to/replay_cron.py --categories all >> /var/log/pcap-replay.log 2>&1

Because tcpreplay needs raw-socket privileges, this re-execs itself under
sudo if not already root — set up NOPASSWD sudo for cron, since a password
prompt has nowhere to go under cron.
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import categories as cat
import pcap_engine as engine


def resolve_base(explicit):
    if explicit:
        return ROOT / explicit
    localized = ROOT / "localized"
    if localized.is_dir() and any(localized.iterdir()):
        return localized
    return cat.PCAPS_DIR


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--categories", default="all",
        help="comma-separated category list, or 'all' (default). Categories: " + ", ".join(cat.CATEGORIES),
    )
    ap.add_argument("--iface", help="interface to send on (default: auto-detected default route iface)")
    ap.add_argument("--jobs", "-j", type=int, default=8, help="concurrent replays (default: 8)")
    ap.add_argument("--realtime", action="store_true", help="replay at original capture timing (slower)")
    ap.add_argument("--base", help="override pcap source dir (default: ./localized if present, else ./pcaps)")
    ap.add_argument("--log-file", help="append log lines here instead of stdout")
    args = ap.parse_args()

    engine.ensure_root()

    selected = [c.strip() for c in args.categories.split(",") if c.strip()]
    unknown = [c for c in selected if c != "all" and c not in cat.CATEGORIES]
    if unknown:
        print(f"Unknown categories: {', '.join(unknown)}", file=sys.stderr)
        sys.exit(2)

    base = resolve_base(args.base)
    files = cat.gather_files(selected, base=base)
    if not files:
        print(f"No pcap files found for categories: {', '.join(selected)} under {base}", file=sys.stderr)
        sys.exit(1)

    iface = args.iface or engine.detect_iface()
    jobs = max(1, min(args.jobs, len(files)))

    log_fh = open(args.log_file, "a") if args.log_file else None

    def log(msg):
        print(msg, file=log_fh or sys.stdout, flush=True)

    totals = engine.run_plain(iface, files, jobs, topspeed=not args.realtime, log=log)
    if log_fh:
        log_fh.close()

    sys.exit(0 if totals["fail"] == 0 else 1)


if __name__ == "__main__":
    main()
