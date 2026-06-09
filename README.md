# AttackPath — System Attack Path Predictor

A defensive security tool that scans your Windows system, maps potential attack paths using MITRE ATT&CK tactics, scores risk, and generates an actionable HTML remediation report.

> **For authorised use only.** Run only on systems you own or have explicit permission to scan.

---

## Features

- **System Scan** — OS info, local users, scheduled tasks, shared resources, environment variables
- **Network Scan** — Open ports with risk classification, active connections, routing
- **Process Scan** — Detects suspicious/LOLBin processes (PowerShell, WMIC, Mimikatz, etc.)
- **Software Scan** — Flags risky or outdated installed software (Flash, Java, FileZilla, etc.)
- **Service Scan** — Detects unquoted service paths (privilege escalation vector)
- **Security Scan** — Checks Firewall, UAC, Windows Defender, SMB, RDP, BitLocker, password policy
- **Attack Path Prediction** — Chains findings into realistic multi-step attack scenarios
- **Risk Scoring** — Weighted severity scoring with an overall 0–100 risk score
- **Prevention Engine** — Per-finding remediation steps with CIS/MITRE references
- **Reports** — Self-contained HTML dashboard + machine-readable JSON

---

## Attack Paths Modelled

| Attack Path | Tactics Used |
|---|---|
| Ransomware via SMB/EternalBlue | Initial Access → Lateral Movement → Impact |
| RDP Brute-Force & Remote Takeover | Initial Access → Credential Access → Persistence |
| NTLM Relay & Lateral Movement | Credential Access → Lateral Movement |
| Local Privilege Escalation | Privilege Escalation → Defense Evasion |
| Credential Harvesting | Credential Access → Exfiltration |
| Data Exfiltration | Collection → Exfiltration |
| Persistence via Scheduled Tasks | Persistence → Execution |
| USB / Physical Media Attack | Initial Access → Execution |

---

## Requirements

- Windows 10/11 (primary support)
- Python 3.9+
- Run as **Administrator** for full results (some scans require elevated privileges)

---

## Installation

```bash
git clone https://github.com/yourusername/AttackPath.git
cd AttackPath
pip install -r requirements.txt
```

---

## Usage

```bash
# Full scan — HTML + JSON reports saved to output/
python main.py

# Quick scan (skip software registry — faster)
python main.py --quick

# Custom output directory
python main.py --output C:\Reports\

# JSON report only
python main.py --no-html

# HTML report only
python main.py --no-json
```

### Run as Administrator (recommended)

Right-click PowerShell → "Run as Administrator", then:

```powershell
cd "C:\path\to\AttackPath"
python main.py
```

---

## Output

Reports are saved in the `output/` directory:

```
output/
├── attackpath_HOSTNAME_20240101_120000.html   ← Interactive dashboard
└── attackpath_HOSTNAME_20240101_120000.json   ← Machine-readable data
```

The HTML report includes:
- Overall risk score (0–100)
- Severity breakdown chart
- MITRE ATT&CK tactic distribution
- Top predicted attack paths with step-by-step chains
- All findings with technical details
- Actionable remediation steps per finding
- General hardening recommendations

---

## Project Structure

```
AttackPath/
├── main.py                    # CLI entry point
├── config.py                  # Constants and configuration
├── requirements.txt
├── scanners/
│   ├── system_scanner.py      # OS, users, tasks, shares
│   ├── network_scanner.py     # Ports, connections, interfaces
│   ├── process_scanner.py     # Running processes
│   ├── software_scanner.py    # Installed software
│   ├── service_scanner.py     # Windows services
│   └── security_scanner.py   # Firewall, AV, UAC, SMB, RDP
├── analyzers/
│   ├── risk_scorer.py         # Converts scan data → findings
│   └── attack_path.py         # Chains findings → attack paths
├── predictors/
│   └── path_predictor.py      # Risk scoring & threat profiling
├── prevention/
│   └── recommendations.py    # Per-finding remediation steps
└── reports/
    ├── html_reporter.py       # Self-contained HTML report
    └── json_reporter.py       # JSON report
```

---

## Disclaimer

This tool is intended for **defensive purposes only** — to help system administrators and security professionals identify and remediate vulnerabilities on systems they own or are authorised to test.

Do not use this tool on systems you do not own or have explicit written permission to test.

---

## License

MIT License — see [LICENSE](LICENSE)
