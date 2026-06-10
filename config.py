"""
Central configuration for PredatorEye.
"""

TOOL_VERSION = "1.0.0"
TOOL_NAME = "PredatorEye - System Attack Path Predictor"

# Severity levels and their numeric scores
SEVERITY_SCORES = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2,
    "Info": 0,
}

SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High": "#e67e22",
    "Medium": "#f1c40f",
    "Low": "#2ecc71",
    "Info": "#3498db",
}

# Common dangerous ports and what they represent
RISKY_PORTS = {
    21:   ("FTP", "High",     "Unencrypted file transfer — plaintext credentials"),
    22:   ("SSH", "Medium",   "Remote shell; brute-force target"),
    23:   ("Telnet", "Critical", "Completely unencrypted remote access"),
    25:   ("SMTP", "Medium",  "Mail relay; potential spam/phishing pivot"),
    53:   ("DNS", "Medium",   "DNS tunneling / exfiltration channel"),
    80:   ("HTTP", "Medium",  "Unencrypted web service"),
    110:  ("POP3", "High",    "Plaintext email retrieval"),
    135:  ("RPC", "High",     "Windows RPC — lateral movement vector"),
    137:  ("NetBIOS-NS", "High", "NetBIOS name service — enumeration"),
    139:  ("NetBIOS-SSN", "High", "NetBIOS session — SMB relay target"),
    143:  ("IMAP", "High",    "Plaintext email access"),
    443:  ("HTTPS", "Info",   "Encrypted web service"),
    445:  ("SMB", "Critical", "EternalBlue / ransomware lateral movement"),
    1433: ("MSSQL", "High",   "SQL Server — SQL injection / credential attack"),
    1723: ("PPTP", "High",    "Weak VPN protocol"),
    3306: ("MySQL", "High",   "Database exposed to network"),
    3389: ("RDP", "Critical", "Remote Desktop — brute force / BlueKeep target"),
    4444: ("Metasploit", "Critical", "Default Metasploit listener — likely compromise"),
    5900: ("VNC", "Critical", "Remote desktop without NLA"),
    5985: ("WinRM-HTTP", "High", "Windows Remote Management — lateral movement"),
    5986: ("WinRM-HTTPS", "Medium", "Windows Remote Management (encrypted)"),
    6379: ("Redis", "High",   "In-memory DB often unauthenticated"),
    8080: ("HTTP-Alt", "Medium", "Alternative HTTP — often admin panels"),
    8443: ("HTTPS-Alt", "Low", "Alternative HTTPS"),
    27017:("MongoDB", "High", "NoSQL DB — often unauthenticated"),
}

# MITRE ATT&CK tactic categories used internally
ATTACK_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
]

# Ports to scan (subset for speed)
SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 137, 139, 143,
    443, 445, 1433, 1723, 3306, 3389, 4444, 5900,
    5985, 5986, 6379, 8080, 8443, 27017,
]

PORT_SCAN_TIMEOUT = 0.5   # seconds per port
MAX_PORT_THREADS = 50
