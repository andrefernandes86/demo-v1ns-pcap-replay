"""
Manifest of externally-hosted sample pcaps fetch_pcaps.py can download to
populate categories with no (or few) local samples. All sources are public,
free research/education resources:

  - chrissanders/packets: companion captures for "Practical Packet Analysis"
    (Chris Sanders), published for public teaching use.
  - markofu/pcaps: mirror of the same book's earlier capture set.
  - briliant-ben/SampleCaptures: community mirror of the Wireshark wiki's
    official SampleCaptures page.
  - malware-traffic-analysis.net: the standard public malware/C2 pcap
    archive used across the industry; zips are password-protected with a
    fixed, publicly documented scheme (infected_YYYYMMDD).

Each entry: category, filename (as saved locally), url, and optional
extraction info ("gz": True, or "zip": {"password": str, "member": str}).
"""

SOURCES = [
    # -- benign --
    {"category": "dns", "filename": "dns.pcap",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/dns.pcap"},
    {"category": "dns", "filename": "dns_query_response.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/dns_query_response.pcapng"},

    {"category": "http", "filename": "http_google.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/http_google.pcapng"},
    {"category": "http", "filename": "http.cap",
     "url": "https://raw.githubusercontent.com/briliant-ben/SampleCaptures/main/specific-protocols-and-protocol-families/hypertext-transport-protocol-http/http.cap"},

    {"category": "ftp", "filename": "ftp.pcap",
     "url": "https://raw.githubusercontent.com/markofu/pcaps/master/PracticalPacketAnalysis/ppa-capture-files/ftp.pcap"},

    {"category": "smb", "filename": "smb-on-windows-10.pcapng",
     "url": "https://raw.githubusercontent.com/briliant-ben/SampleCaptures/main/specific-protocols-and-protocol-families/smb31-handshake/smb-on-windows-10.pcapng"},

    {"category": "database", "filename": "mysql_complete.pcap",
     "url": "https://raw.githubusercontent.com/briliant-ben/SampleCaptures/main/specific-protocols-and-protocol-families/mysql-protocol/mysql_complete.pcap"},
    {"category": "database", "filename": "ms-sql-tds-rpc-requests.cap",
     "url": "https://raw.githubusercontent.com/briliant-ben/SampleCaptures/main/specific-protocols-and-protocol-families/ms-sql-server-protocol-tabular-data-stream-tds/ms-sql-tds-rpc-requests.cap"},
    {"category": "database", "filename": "pgsql.cap",
     "url": "https://raw.githubusercontent.com/briliant-ben/SampleCaptures/main/specific-protocols-and-protocol-families/postgresql-v3-frontend-backend-protocol/pgsql.cap.gz",
     "gz": True},

    # -- malicious --
    {"category": "exploits", "filename": "aurora.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/aurora.pcapng"},
    {"category": "exploits", "filename": "http_dvwa_sqlinjection.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/http_dvwa_sqlinjection.pcapng"},
    {"category": "exploits", "filename": "http_dvwa_directorytraversal.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/http_dvwa_directorytraversal.pcapng"},
    {"category": "exploits", "filename": "ek_to_cryptowall4.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/ek_to_cryptowall4.pcapng"},

    {"category": "malware", "filename": "cryptowall4_c2.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/cryptowall4_c2.pcapng"},
    {"category": "malware", "filename": "ratinfected.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/ratinfected.pcapng"},

    {"category": "c2", "filename": "2021-05-26-trickbot-cobaltstrike.pcap",
     "url": "https://www.malware-traffic-analysis.net/2021/05/26/2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap.zip",
     "zip": {"password": "infected_20210526",
             "member": "2021-05-26-Trickbot-infection-with-Cobalt-Strike.pcap"}},

    {"category": "hacking-tools", "filename": "arppoison.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/arppoison.pcapng"},
    {"category": "hacking-tools", "filename": "sessionhijacking.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/sessionhijacking.pcapng"},

    {"category": "scans", "filename": "synscan.pcapng",
     "url": "https://raw.githubusercontent.com/chrissanders/packets/master/synscan.pcapng"},
]
