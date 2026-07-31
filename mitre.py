"""
MITRE ATT&CK mapping for the pcap set — ties each file (or filename
pattern) to the network-observable technique(s) it demonstrates, across
both the Enterprise matrix and ATT&CK for ICS.

Reference: https://attack.mitre.org/matrices/enterprise/  and
           https://attack.mitre.org/matrices/ics/
"""

ENTERPRISE = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1189": ("Drive-by Compromise", "Initial Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1204": ("User Execution", "Execution"),
    "T1203": ("Exploitation for Client Execution", "Execution"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1078": ("Valid Accounts", "Defense Evasion / Persistence"),
    "T1021.001": ("Remote Services: RDP", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Admin Shares", "Lateral Movement"),
    "T1570": ("Lateral Tool Transfer", "Lateral Movement"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1558": ("Steal or Forge Kerberos Tickets", "Credential Access"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access / Collection"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1049": ("System Network Connections Discovery", "Discovery"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1572": ("Protocol Tunneling", "Command and Control"),
    "T1219": ("Remote Access Software", "Command and Control"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1048.003": ("Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol", "Exfiltration"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1496": ("Resource Hijacking", "Impact"),
}

ICS = {
    "T0801": ("Monitor Process State", "Collection"),
    "T0846": ("Remote System Information Discovery", "Discovery"),
    "T0888": ("Remote System Discovery", "Discovery"),
    "T0855": ("Unauthorized Command Message", "Impair Process Control"),
    "T0836": ("Modify Parameter", "Impair Process Control"),
    "T0831": ("Manipulation of Control", "Impair Process Control"),
    "T0866": ("Exploitation of Remote Services", "Lateral Movement"),
    "T0800": ("Activate Firmware Update Mode", "Impair Process Control"),
    "T0828": ("Loss of Productivity and Revenue", "Impact"),
}

ALL_TECHNIQUES = {**ENTERPRISE, **ICS}

# Explicit per-file tags: "category/filename" -> [technique_ids]
FILE_TECHNIQUES = {
    # exploits
    "exploits/CVE-2019-0708.pcap": ["T1190", "T1210"],
    "exploits/CVE-2020-1472_exploit_win2016.pcap": ["T1210", "T1078"],
    "exploits/CVE-2020-1472_exploit_win2019.pcap": ["T1210", "T1078"],
    "exploits/CVE-2020-1472_test_win2016.pcap": ["T1210"],
    "exploits/CVE-2020-1472_test_win2019.pcap": ["T1210"],
    "exploits/CVE-2020-1472_Zerologon_RPC_NetLogon_NullChallenge_SecChan_6_from_nonDC_to_DC.pcapng": ["T1210", "T1078"],
    "exploits/CVE-2020-0796_SMBGhost_PrivEsc_Loopback_traffic.pcapng": ["T1210"],
    "exploits/cve-2019-19781_port80_GET_vulnerability_path_check.pcap": ["T1190", "T1595"],
    "exploits/Exploit_DoS_cve-2020-1350_dns_sig_maxspl0it.pcapng": ["T1190"],
    "exploits/trffic_445_exploit.pcap": ["T1210"],
    "exploits/HTTP_Apache_chunk_S.pcap": ["T1190", "T1595"],
    "exploits/HTTP_Apache_nosejob_U.pcap": ["T1190", "T1595"],
    "exploits/http_dvwa_sqlinjection.pcapng": ["T1190"],
    "exploits/http_dvwa_directorytraversal.pcapng": ["T1190"],
    "exploits/aurora.pcapng": ["T1203", "T1566"],
    "exploits/ek_to_cryptowall4.pcapng": ["T1189", "T1203"],
    "exploits/2022-01-03-log4j-server-probes.pcap": ["T1190", "T1595"],

    # malware
    "malware/WANNACRYBHExploitationW7.pcap": ["T1210", "T1486"],
    "malware/2018-11-02-GandCrab-ransomware-infection.pcap": ["T1486", "T1071.001"],
    "malware/Malware_HTML_REDIR.SMR_B0FF5BC5-2C88-5805-8567-73A7FC20360C.eml.pcap": ["T1566", "T1204"],
    "malware/Malware_JAVA_ADWIND.JORH_D1E73216-2C8C-8F05-8567-74A477A7E29D.eml.pcap": ["T1566", "T1204"],
    "malware/Malware_PDF_FAKEDLH.PQ_F2F91368-2C89-C105-8567-5501F9F837DE.eml.pcap": ["T1566", "T1204"],
    "malware/Malware_WORM_NETSKY.Q_FD5CECB0-2C8E-C605-8567-AE3BBFB03655.eml.pcap": ["T1566", "T1204"],
    "malware/cryptowall4_c2.pcapng": ["T1486", "T1071.001"],
    "malware/ratinfected.pcapng": ["T1219", "T1071.001"],

    # hacking-tools
    "hacking-tools/LM_psexec_smb_dcerpc_epm_svcctl.pcapng": ["T1570", "T1021.002"],
    "hacking-tools/LM_smbexec_smb_dcerpc_svcctl_epm.pcapng": ["T1570", "T1021.002"],
    "hacking-tools/LM_rdp_sharprdp.pcapng": ["T1021.001"],
    "hacking-tools/rdp_tunneling_meterpreter_portfwd.pcapng": ["T1572", "T1021.001", "T1219"],
    "hacking-tools/lm_mimikazt_skeleton_kerberos_rc4_etype.pcapng": ["T1558", "T1003"],
    "hacking-tools/Remote_Pwd_Reset_RPC_Admin_Mimikatz_PostZeroLogon.pcapng": ["T1003", "T1078"],
    "hacking-tools/zerologon_mimikatz_ntlm_privacy_scan_and_exploit_encrypted.pcapng": ["T1210", "T1003"],
    "hacking-tools/arppoison.pcapng": ["T1557"],
    "hacking-tools/sessionhijacking.pcapng": ["T1557", "T1078"],

    # scans
    "scans/trffic_445_scan.pcap": ["T1595", "T1046"],
    "scans/synscan.pcapng": ["T1595", "T1046"],

    # c2
    "c2/2021-05-26-trickbot-cobaltstrike.pcap": ["T1071.001", "T1105", "T1219"],
    "c2/capture_from_C2_to_botnet.pcap": ["T1071.001", "T1105", "T1219"],

    # exfiltration
    "exfiltration/dns-tunnel-iodine.pcap": ["T1071.004", "T1572", "T1048.003"],

    # cryptomining
    "cryptomining/xmr-eu1.nanopool.org.pcapng": ["T1496"],

    # webshells
    "webshells/webshell.pcap": ["T1190", "T1505.003"],

    # ics-attacks
    "ics-attacks/triton-malware-exec.pcap": ["T0866", "T0855", "T0800", "T0828"],
}

# Filename-keyword fallback for the large homogeneous ics-scada protocol set
# (DNP3/Modbus master<->outstation conformance traffic) — these aren't
# attacks themselves, but tag what technique the SAME command would map to
# if issued by an unauthorized source, since that's the detection scenario
# a network sensor cares about.
ICS_KEYWORD_RULES = [
    (("write", "operate", "assign_class", "select_operate", "immediate_freeze",
      "restart", "unsolicited", "disable_unsol", "enable_unsol"), ["T0855", "T0836"]),
    (("read", "class", "file_list", "file_read", "time_sync"), ["T0801", "T0846"]),
    (("file_delete", "file_write"), ["T0855"]),
]

CATEGORY_DEFAULTS = {
    "ics-scada": ["T0888"],  # generic OT protocol discovery/operations
}


def techniques_for(category: str, filename: str):
    key = f"{category}/{filename}"
    if key in FILE_TECHNIQUES:
        return FILE_TECHNIQUES[key]

    if category == "ics-scada":
        lower = filename.lower()
        for keywords, techniques in ICS_KEYWORD_RULES:
            if any(k in lower for k in keywords):
                return techniques
        return CATEGORY_DEFAULTS["ics-scada"]

    return CATEGORY_DEFAULTS.get(category, [])


def describe(technique_id: str) -> str:
    name, tactic = ALL_TECHNIQUES.get(technique_id, ("Unknown", "Unknown"))
    return f"{technique_id} {name} ({tactic})"
