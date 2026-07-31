"""Shared category taxonomy for the pcap set under pcaps/<category>/."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PCAPS_DIR = ROOT / "pcaps"
PCAP_GLOBS = ("*.pcap", "*.pcapng", "*.cap")

# category -> (label, description, is_malicious)
CATEGORIES = {
    "dns": ("DNS", "Benign DNS queries/responses", False),
    "http": ("HTTP", "Benign web browsing traffic", False),
    "ftp": ("FTP", "Benign FTP sessions", False),
    "smb": ("SMB", "Benign SMB/CIFS file sharing", False),
    "database": ("Database", "Benign MySQL/MSSQL/PostgreSQL traffic", False),
    "exploits": ("Exploits", "CVE exploitation and vulnerability probing", True),
    "malware": ("Malware", "Ransomware, trojans, malicious email attachments", True),
    "c2": ("C2 / Cobalt Strike", "Command-and-control beaconing traffic", True),
    "hacking-tools": ("Hacking tools", "Mimikatz, PsExec, RDP tunneling, lateral movement", True),
    "scans": ("Scans", "Port/service scanning activity", True),
    "ics-scada": ("ICS/SCADA", "DNP3, Modbus, and other OT protocol traffic", True),
}


def gather_files(selected_categories, base=None):
    """Return sorted pcap/pcapng files for the given categories.
    selected_categories: iterable of category keys, or None/["all"] for everything.
    base: directory containing category subfolders (defaults to pcaps/).
    """
    base = base or PCAPS_DIR
    if not selected_categories or "all" in selected_categories:
        cats = list(CATEGORIES)
    else:
        cats = list(selected_categories)

    files = []
    for cat in cats:
        d = base / cat
        if not d.is_dir():
            continue
        for pat in PCAP_GLOBS:
            files.extend(sorted(d.glob(pat)))
    return files


def category_counts(base=None):
    base = base or PCAPS_DIR
    counts = {}
    for cat in CATEGORIES:
        d = base / cat
        n = 0
        if d.is_dir():
            n = sum(len(list(d.glob(pat))) for pat in PCAP_GLOBS)
        counts[cat] = n
    return counts
