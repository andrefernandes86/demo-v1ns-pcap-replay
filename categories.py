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
    "snmp": ("SNMP", "Benign SNMP monitoring traffic", False),
    "ntp": ("NTP", "Benign NTP time-sync traffic", False),
    "exploits": ("Exploits", "CVE exploitation, vulnerability probing, IDS evasion", True),
    "malware": ("Malware", "Ransomware, trojans, malicious email attachments, infostealers, RATs", True),
    "c2": ("C2", "Command-and-control beaconing (Cobalt Strike, Sliver)", True),
    "hacking-tools": ("Hacking tools", "Mimikatz, PsExec, RDP tunneling, lateral movement", True),
    "scans": ("Scans", "Port/service scanning activity", True),
    "exfiltration": ("Exfiltration", "DNS tunneling and other data exfiltration techniques", True),
    "cryptomining": ("Cryptomining", "Stratum protocol cryptomining/cryptojacking traffic", True),
    "webshells": ("Web shells", "Post-exploitation web shell traffic", True),
    "phishing": ("Phishing", "Phishing/credential-harvesting traffic", True),
    "brute-force": ("Brute force", "RDP/SSH/FTP credential brute-forcing", True),
    "ddos": ("DDoS", "Denial-of-service and reflection/amplification attack traffic", True),
    "ics-scada": ("ICS/SCADA", "DNP3, Modbus, and other OT protocol traffic (benign protocol conformance)", False),
    "ics-attacks": ("ICS/OT attacks", "Genuine ICS/OT malware and attack traffic (e.g. TRITON/TRISIS)", True),
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
