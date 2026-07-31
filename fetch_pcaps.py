#!/usr/bin/env python3
"""
Maintains the pcaps/<category>/ tree:
  1. Validates every existing pcap (tcpdump can read it, not a stub/HTML
     error page/empty file) and deletes anything broken.
  2. Downloads every sources.py entry not already present, verifying each
     download the same way before keeping it.

Run with --check-only to validate without downloading.
"""
import argparse
import gzip
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import categories as cat
from sources import SOURCES


def is_valid_pcap(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except Exception:
        return False
    if head.startswith(b"version https://git-lfs.github.com/spec/v1"):
        return False
    if head[:1] in (b"<", b"{") or head.startswith(b"<!DOCTYPE") or head.startswith(b"<html"):
        return False
    try:
        r = subprocess.run(
            ["tcpdump", "-r", str(path), "-c", "1"], capture_output=True, text=True, timeout=30
        )
    except Exception:
        return False
    return r.returncode == 0 and "reading from file" in (r.stdout + r.stderr)


def validate_existing(remove_broken=True, log=print):
    removed = []
    checked = 0
    for cat_dir in sorted(cat.PCAPS_DIR.glob("*")):
        if not cat_dir.is_dir():
            continue
        for f in list(cat_dir.glob("*.pcap")) + list(cat_dir.glob("*.pcapng")):
            checked += 1
            if not is_valid_pcap(f):
                log(f"  BROKEN: {f.relative_to(ROOT)}")
                if remove_broken:
                    f.unlink()
                removed.append(str(f.relative_to(ROOT)))
    log(f"Validated {checked} existing files, {len(removed)} broken" + (" (removed)" if remove_broken else ""))
    return removed


def download_one(entry, log=print):
    dest_dir = cat.PCAPS_DIR / entry["category"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / entry["filename"]

    if dest.exists() and is_valid_pcap(dest):
        return "already-present"

    tmp = dest.with_suffix(dest.suffix + ".download")
    try:
        req = urllib.request.Request(entry["url"], headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as out:
            shutil.copyfileobj(resp, out)

        if entry.get("zip"):
            zi = entry["zip"]
            with zipfile.ZipFile(tmp) as zf:
                with zf.open(zi["member"], pwd=zi["password"].encode()) as member, open(dest, "wb") as out:
                    shutil.copyfileobj(member, out)
            tmp.unlink()
        elif entry.get("gz"):
            with gzip.open(tmp, "rb") as gz_in, open(dest, "wb") as out:
                shutil.copyfileobj(gz_in, out)
            tmp.unlink()
        else:
            tmp.rename(dest)

        if not is_valid_pcap(dest):
            dest.unlink(missing_ok=True)
            log(f"  FAILED (invalid after download): {entry['category']}/{entry['filename']}")
            return "failed"
        log(f"  OK: {entry['category']}/{entry['filename']}")
        return "downloaded"
    except Exception as e:
        tmp.unlink(missing_ok=True)
        log(f"  FAILED ({e}): {entry['category']}/{entry['filename']}")
        return "failed"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check-only", action="store_true", help="only validate existing files, do not download")
    args = ap.parse_args()

    print("== Validating existing pcaps ==")
    validate_existing(remove_broken=True)

    if args.check_only:
        return

    print("\n== Fetching new sample pcaps ==")
    results = {}
    for entry in SOURCES:
        status = download_one(entry)
        results[status] = results.get(status, 0) + 1

    print("\nSummary: " + ", ".join(f"{k}={v}" for k, v in results.items()))


if __name__ == "__main__":
    main()
