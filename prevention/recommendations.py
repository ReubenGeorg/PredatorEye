"""
Maps each finding to specific, actionable prevention recommendations.
"""


# Maps title keywords → list of recommendation dicts
RECOMMENDATION_MAP = [
    # ── Network ──────────────────────────────────────────────────────
    {
        "keywords": ["port 23", "telnet"],
        "steps": [
            "Disable the Telnet service: `sc config tlntsvr start= disabled && sc stop tlntsvr`",
            "Block port 23 in Windows Firewall: `netsh advfirewall firewall add rule name='Block Telnet' protocol=TCP dir=in localport=23 action=block`",
            "Use SSH (port 22) instead for remote administration.",
        ],
        "ref": "CIS Control 4.8 — Uninstall or Disable Unnecessary Services",
    },
    {
        "keywords": ["port 445", "smbv1", "smb1", "eternalblue"],
        "steps": [
            "Disable SMBv1 immediately: `Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force`",
            "Apply MS17-010 patch if not already done (Windows Update).",
            "Block SMB at the network perimeter — never expose port 445 to the internet.",
            "Enable SMB signing: `Set-SmbServerConfiguration -RequireSecuritySignature $true -Force`",
        ],
        "ref": "MS17-010 / CVE-2017-0144 — Microsoft Security Bulletin",
    },
    {
        "keywords": ["port 3389", "rdp"],
        "steps": [
            "Enable NLA: `Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1`",
            "Change RDP to a non-default port and restrict via firewall to trusted IPs only.",
            "Enforce account lockout after 5 failed attempts.",
            "Use a VPN or RD Gateway rather than exposing RDP directly.",
            "Enable Network Level Authentication in System Properties → Remote.",
        ],
        "ref": "CIS Control 12.3 — Limit Access via Remote Access Protocols",
    },
    {
        "keywords": ["port 21", "ftp"],
        "steps": [
            "Migrate to SFTP (SSH File Transfer Protocol) or FTPS.",
            "Disable the FTP service if not required.",
            "If FTP must run, restrict to internal IPs only via firewall rules.",
        ],
        "ref": "OWASP — Insecure Transport",
    },
    {
        "keywords": ["smb signing"],
        "steps": [
            "Enable SMB signing on servers: `Set-SmbServerConfiguration -RequireSecuritySignature $true`",
            "Enable SMB signing on clients: `Set-SmbClientConfiguration -RequireSecuritySignature $true`",
            "Consider deploying this via Group Policy: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → Microsoft network server: Digitally sign communications (always).",
        ],
        "ref": "MITRE ATT&CK T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay",
    },
    # ── Firewall ─────────────────────────────────────────────────────
    {
        "keywords": ["firewall disabled", "firewall off"],
        "steps": [
            "Re-enable the firewall for all profiles: `netsh advfirewall set allprofiles state on`",
            "Set default inbound policy to block: `netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound`",
            "Review and remove any overly permissive inbound rules.",
            "Use Group Policy to prevent users from disabling the firewall.",
        ],
        "ref": "CIS Control 12.4 — Deny Communications with Known Malicious IP Addresses",
    },
    # ── UAC ──────────────────────────────────────────────────────────
    {
        "keywords": ["uac", "never notify", "user account control"],
        "steps": [
            "Enable UAC: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1`",
            "Set UAC to highest level in Control Panel → User Accounts → Change UAC settings.",
            "Deploy via Group Policy: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → User Account Control: Run all administrators in Admin Approval Mode.",
        ],
        "ref": "CIS Benchmark — Ensure UAC is set to Automatically Deny",
    },
    # ── Antivirus / Defender ─────────────────────────────────────────
    {
        "keywords": ["real-time protection", "no antivirus", "defender"],
        "steps": [
            "Re-enable Windows Defender real-time protection: `Set-MpPreference -DisableRealtimeMonitoring $false`",
            "Run a full scan: `Start-MpScan -ScanType FullScan`",
            "Ensure Windows Security settings haven't been tampered with — investigate if protection was disabled by malware.",
            "Consider a commercial EDR solution for enhanced detection.",
        ],
        "ref": "CIS Control 10.1 — Deploy and Maintain Anti-Malware Software",
    },
    # ── Password Policy ───────────────────────────────────────────────
    {
        "keywords": ["password", "lockout", "complexity"],
        "steps": [
            "Set minimum password length to 14+ characters: `net accounts /minpwlen:14`",
            "Enable account lockout: `net accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30`",
            "Enable complexity requirements via secpol.msc → Account Policies → Password Policy.",
            "Consider moving to passphrases and a password manager.",
            "Enable Windows Hello or hardware security keys for MFA.",
        ],
        "ref": "NIST SP 800-63B — Digital Identity Guidelines",
    },
    # ── BitLocker ─────────────────────────────────────────────────────
    {
        "keywords": ["bitlocker"],
        "steps": [
            "Enable BitLocker on all drives: `Enable-BitLocker -MountPoint C: -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest`",
            "Back up the recovery key to Azure AD or a secure offline location.",
            "Ensure TPM is enabled in UEFI/BIOS settings.",
        ],
        "ref": "CIS Control 3.6 — Encrypt Data on End-User Devices",
    },
    # ── Services ──────────────────────────────────────────────────────
    {
        "keywords": ["unquoted service"],
        "steps": [
            "Wrap the binary path in quotes in the service registry key: `HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>\\ImagePath`",
            "Use `sc config <service> binpath= '\"C:\\path with spaces\\service.exe\"'` to fix.",
            "Audit all services with spaces in their path: `wmic service get name,pathname | findstr /i /v '\"C:\\Windows\\\\'`",
            "Apply principle of least privilege — services should not run as SYSTEM unless absolutely required.",
        ],
        "ref": "MITRE ATT&CK T1574.009 — Path Interception by Unquoted Path",
    },
    {
        "keywords": ["remote registry"],
        "steps": [
            "Disable Remote Registry: `sc config RemoteRegistry start= disabled && sc stop RemoteRegistry`",
            "If required for management, restrict access via firewall to specific admin IPs only.",
        ],
        "ref": "CIS Control 4.8 — Uninstall or Disable Unnecessary Services",
    },
    # ── Software ──────────────────────────────────────────────────────
    {
        "keywords": ["flash", "shockwave"],
        "steps": [
            "Uninstall Adobe Flash Player immediately — it is end-of-life and has no security updates.",
            "Check all browsers have Flash disabled or removed.",
        ],
        "ref": "Adobe Flash EOL — Adobe Security Advisory",
    },
    {
        "keywords": ["java", "jre"],
        "steps": [
            "Update Java to the latest LTS version.",
            "Disable Java in all browsers if not needed for web applications.",
            "Remove unused old Java versions via Programs and Features.",
        ],
        "ref": "CIS Control 2.2 — Ensure Software is Updated",
    },
    {
        "keywords": ["filezilla", "winscp"],
        "steps": [
            "FileZilla and WinSCP can store plaintext credentials — review and clear saved site manager entries.",
            "Use credential managers instead of in-app credential storage.",
            "Ensure the application config directories are access-controlled.",
        ],
        "ref": "MITRE ATT&CK T1555.003 — Credentials from Web Browsers / Applications",
    },
    # ── Processes ─────────────────────────────────────────────────────
    {
        "keywords": ["powershell"],
        "steps": [
            "Enable PowerShell Constrained Language Mode for standard users via AppLocker or WDAC.",
            "Enable PowerShell Script Block Logging: Group Policy → Administrative Templates → Windows Components → Windows PowerShell.",
            "Enable PowerShell Transcription logging.",
            "Investigate the running instance — review command line arguments for malicious activity.",
        ],
        "ref": "MITRE ATT&CK T1059.001 — Command and Scripting Interpreter: PowerShell",
    },
    {
        "keywords": ["mimikatz"],
        "steps": [
            "IMMEDIATE: Assume credential compromise — rotate all passwords and service account credentials.",
            "Isolate the machine from the network immediately.",
            "Run a full forensic investigation to determine what credentials were harvested.",
            "Enable Credential Guard to protect LSASS from memory dumping.",
            "Enable Protected Users security group for all privileged accounts.",
        ],
        "ref": "MITRE ATT&CK T1003 — OS Credential Dumping",
    },
    # ── System ────────────────────────────────────────────────────────
    {
        "keywords": ["environment variable", "credentials in environment"],
        "steps": [
            "Remove credentials from environment variables — use a secrets manager (HashiCorp Vault, Azure Key Vault, Windows Credential Manager).",
            "Audit environment variables: `Get-ChildItem Env:` and remove sensitive entries.",
            "Restart any services that loaded those credentials after removing them.",
        ],
        "ref": "OWASP — Sensitive Data Exposure",
    },
    {
        "keywords": ["autorun", "autoplay"],
        "steps": [
            "Disable AutoRun for all drive types: `Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255`",
            "Configure via Group Policy: Computer Configuration → Administrative Templates → Windows Components → AutoPlay Policies → Turn off AutoPlay.",
        ],
        "ref": "CIS Control 10.3 — Disable Autorun and Autoplay for Removable Media",
    },
    {
        "keywords": ["multiple administrator", "admin account"],
        "steps": [
            "Audit all administrator accounts and remove unnecessary ones.",
            "Disable the built-in Administrator account: `net user Administrator /active:no`",
            "Apply principle of least privilege — users should not have admin rights for daily tasks.",
            "Create a dedicated IT admin account used only for admin tasks.",
        ],
        "ref": "CIS Control 5.4 — Restrict Administrator Privileges to Dedicated Admin Accounts",
    },
    {
        "keywords": ["network shares"],
        "steps": [
            "Review all shares and remove unnecessary ones: `net share <name> /delete`",
            "Apply proper NTFS and share permissions — restrict to specific users/groups.",
            "Enable SMB access logging via Group Policy.",
            "Ensure $IPC and admin shares are secured.",
        ],
        "ref": "CIS Control 3.3 — Configure Data Access Control Lists",
    },
    {
        "keywords": ["scheduled task"],
        "steps": [
            "Audit elevated scheduled tasks: `Get-ScheduledTask | Where-Object { $_.Principal.RunLevel -eq 'Highest' }`",
            "Remove any tasks running from user-writable directories.",
            "Restrict task creation to administrators only.",
            "Enable scheduled task audit logging in Group Policy.",
        ],
        "ref": "MITRE ATT&CK T1053.005 — Scheduled Task/Job: Scheduled Task",
    },
]

# General hardening recommendations always included
GENERAL_RECOMMENDATIONS = [
    {
        "title": "Keep Windows and all software up to date",
        "steps": [
            "Enable automatic Windows Updates: Settings → Windows Update → Advanced Options.",
            "Subscribe to Microsoft Security Response Center (MSRC) alerts.",
            "Patch third-party software regularly — use tools like Winget or Chocolatey.",
        ],
    },
    {
        "title": "Enable comprehensive logging and monitoring",
        "steps": [
            "Enable Windows Event Log audit policies: `auditpol /set /category:* /success:enable /failure:enable`",
            "Forward logs to a SIEM or centralised log server.",
            "Enable PowerShell Transcription and Script Block Logging.",
            "Monitor for Event IDs: 4624 (logon), 4625 (failed logon), 4672 (special privileges), 7045 (new service).",
        ],
    },
    {
        "title": "Implement network segmentation and least privilege",
        "steps": [
            "Segment the network — workstations should not communicate directly with each other.",
            "Use VLANs to isolate servers, workstations, and IoT devices.",
            "Apply principle of least privilege to all user accounts and service accounts.",
        ],
    },
    {
        "title": "Enable Multi-Factor Authentication (MFA)",
        "steps": [
            "Enable MFA for all accounts, especially privileged ones.",
            "Use Windows Hello for Business or FIDO2 hardware keys.",
            "Enable MFA on all cloud services (Microsoft 365, Azure, AWS, etc.).",
        ],
    },
    {
        "title": "Maintain and test offline backups",
        "steps": [
            "Follow the 3-2-1 backup rule: 3 copies, 2 different media, 1 offsite.",
            "Test backup restoration quarterly.",
            "Ensure backups are not accessible from the primary network (air-gapped or immutable).",
            "Use Windows Server Backup or a third-party solution with ransomware protection.",
        ],
    },
]


class RecommendationEngine:
    def __init__(self, findings: list):
        self.findings = findings

    def generate(self) -> dict:
        specific = self._specific_recommendations()
        return {
            "specific": specific,
            "general": GENERAL_RECOMMENDATIONS,
            "total_specific": len(specific),
        }

    def _specific_recommendations(self) -> list:
        matched = []
        seen_keywords = set()

        for finding in self.findings:
            title_lower = finding.title.lower()
            for rule in RECOMMENDATION_MAP:
                rule_key = tuple(rule["keywords"])
                if rule_key in seen_keywords:
                    continue
                if any(kw in title_lower for kw in rule["keywords"]):
                    matched.append({
                        "finding_id": finding.id,
                        "finding_title": finding.title,
                        "severity": finding.severity,
                        "steps": rule["steps"],
                        "reference": rule.get("ref", ""),
                    })
                    seen_keywords.add(rule_key)

        return sorted(matched, key=lambda r: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(r["severity"], 5))
