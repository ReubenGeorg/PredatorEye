# PredatorEye — Vulnerability Assessment & Active Protection Platform

A defensive security platform that scans your Windows system, maps potential attack paths using MITRE ATT&CK tactics, scores risk, detects active threats using a three-layer AV engine, and generates an actionable HTML remediation report.

> **For authorised use only.** Run only on systems you own or have explicit permission to scan.

---

## Features

### Vulnerability Assessment
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

### Active Protection Stack (--protect)
- **Layer 1 — Signature Engine** — MD5/SHA256 hash lookup against a local threat database
- **Layer 2 — YARA Engine** — Pattern-matching against YARA rules (catches obfuscated variants)
- **Layer 3 — Behaviour Monitor** — Heuristic process scoring (10 rules, MITRE ATT&CK mapped)
- **File Watcher** — Real-time drop-folder monitoring (Downloads, Desktop, Temp)
- **Quarantine** — XOR-obfuscated file isolation with manifest, restore, and delete
- **Persistence Monitor** — Registry Run key / Startup folder / Scheduled task delta detection

### Correlation Engine
- **Threat Correlator** — 6 cross-engine rules that combine VA findings with active detections to produce high-confidence alerts (e.g. "AV disabled AND malware detected")

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

Optional (for protection stack):
- `yara-python` — required for YARA pattern matching (Layer 2)
- `watchdog` — required for real-time file watching

---

## Installation

```bash
git clone https://github.com/ReubenGeorg/PredatorEye.git
cd PredatorEye
pip install -r requirements.txt
```

For the full protection stack (desktop use):
```bash
pip install -r requirements_desktop.txt
```

---

## Usage

```bash
# Full scan — HTML + JSON reports saved to output/
python main.py

# Quick scan (skip software registry — faster)
python main.py --quick

# Full scan + active protection stack + correlation
python main.py --protect

# Custom output directory
python main.py --output C:\Reports\

# JSON report only
python main.py --no-json

# HTML report only
python main.py --no-html
```

### Run as Administrator (recommended)

Right-click PowerShell → "Run as Administrator", then:

```powershell
cd "C:\path\to\PredatorEye"
python main.py --protect
```

---

## Output

Reports are saved in the `output/` directory:

```
output/
├── predatoreye_HOSTNAME_20240101_120000.html   ← Interactive dashboard
└── predatoreye_HOSTNAME_20240101_120000.json   ← Machine-readable data
```

The HTML report includes:
- Overall risk score (0–100)
- Severity breakdown chart
- MITRE ATT&CK tactic distribution
- Top predicted attack paths with step-by-step chains
- All findings with technical details
- Active Threats section (when `--protect` is used)
- Correlated Findings section (when `--protect` is used)
- Actionable remediation steps per finding
- General hardening recommendations

---

## Project Structure

```
PredatorEye/
├── main.py                        # CLI entry point (--protect flag)
├── config.py                      # Constants and configuration
├── requirements.txt               # Web/server dependencies
├── requirements_desktop.txt       # Full desktop dependencies
├── pytest.ini                     # Test configuration
├── scanners/
│   ├── system_scanner.py          # OS, users, tasks, shares
│   ├── network_scanner.py         # Ports, connections, interfaces
│   ├── process_scanner.py         # Running processes
│   ├── software_scanner.py        # Installed software
│   ├── service_scanner.py         # Windows services
│   ├── security_scanner.py        # Firewall, AV, UAC, SMB, RDP
│   └── file_scanner.py            # Malicious file static analysis
├── analyzers/
│   ├── risk_scorer.py             # Converts scan data → findings
│   └── attack_path.py             # Chains findings → attack paths
├── predictors/
│   └── path_predictor.py          # Risk scoring & threat profiling
├── prevention/
│   └── recommendations.py         # Per-finding remediation steps
├── protection/                    # Active protection stack
│   ├── signature_engine.py        # Layer 1: hash-based detection
│   ├── yara_engine.py             # Layer 2: YARA pattern matching
│   ├── behavior_monitor.py        # Layer 3: heuristic process scoring
│   ├── file_watcher.py            # Real-time drop-folder monitoring
│   ├── quarantine.py              # File isolation + manifest
│   ├── persistence_monitor.py     # Registry/startup delta detection
│   └── signatures.json            # Local hash signature database
├── correlation/
│   └── threat_correlator.py       # 6-rule cross-engine correlation
├── rules/
│   ├── eicar_test.yar             # EICAR validation rule
│   └── common_threats.yar         # Mimikatz, PowerShell, LOLBin, Run key rules
├── reports/
│   ├── html_reporter.py           # Self-contained HTML report
│   └── json_reporter.py           # JSON report
├── web/                           # Hosted web app (Render.com)
│   ├── app.py                     # Flask backend
│   ├── requirements.txt           # Web-only dependencies
│   └── templates/                 # Jinja2 HTML templates
└── tests/                         # pytest suite (85 tests)
    ├── test_signature_engine.py
    ├── test_yara_engine.py
    └── test_threat_correlator.py
```

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/

# Skip tests that write EICAR content to disk
python -m pytest tests/ -m "not eicar"
```

---

## Disclaimer

This tool is intended for **defensive purposes only** — to help system administrators and security professionals identify and remediate vulnerabilities on systems they own or are authorised to test.

Do not use this tool on systems you do not own or have explicit written permission to test.

---

## License

MIT License — see [LICENSE](LICENSE)
