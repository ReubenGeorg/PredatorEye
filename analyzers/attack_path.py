"""
Builds attack paths by chaining related findings into realistic attack scenarios.
Each AttackPath represents a multi-step attack sequence an adversary could follow.
"""

from config import SEVERITY_SCORES


class AttackPath:
    def __init__(self, path_id, name, description, steps, likelihood, impact):
        self.id = path_id
        self.name = name
        self.description = description
        self.steps = steps          # list of Finding objects
        self.likelihood = likelihood  # 0.0–1.0
        self.impact = impact          # severity string
        self.risk_score = round(
            SEVERITY_SCORES.get(impact, 0) * likelihood, 2
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "steps": [s.to_dict() if hasattr(s, "to_dict") else s for s in self.steps],
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
        }


class AttackPathAnalyzer:
    def __init__(self, findings: list):
        self.findings = findings
        self._pid = 0

    def _next_id(self) -> str:
        self._pid += 1
        return f"AP{self._pid:02d}"

    def _by_category(self, category: str) -> list:
        return [f for f in self.findings if f.category == category]

    def _by_title_keyword(self, *keywords) -> list:
        kw_lower = [k.lower() for k in keywords]
        return [f for f in self.findings if any(k in f.title.lower() for k in kw_lower)]

    def _has(self, *keywords) -> bool:
        return bool(self._by_title_keyword(*keywords))

    def analyze(self) -> list:
        paths = []
        paths += self._ransomware_path()
        paths += self._rdp_brute_force_path()
        paths += self._lateral_movement_path()
        paths += self._privilege_escalation_path()
        paths += self._credential_harvesting_path()
        paths += self._data_exfiltration_path()
        paths += self._persistence_path()
        paths += self._usb_attack_path()
        return sorted(paths, key=lambda p: p.risk_score, reverse=True)

    # ------------------------------------------------------------------
    def _ransomware_path(self) -> list:
        steps = []
        likelihood = 0.0

        smb1 = self._by_title_keyword("smbv1")
        fw_off = self._by_title_keyword("firewall disabled")
        no_av = self._by_title_keyword("real-time protection", "no antivirus")
        no_backup = self._by_title_keyword("bitlocker")
        smb_sign = self._by_title_keyword("smb signing")

        if smb1:
            steps += smb1
            likelihood += 0.35
        if fw_off:
            steps += fw_off[:1]
            likelihood += 0.20
        if no_av:
            steps += no_av[:1]
            likelihood += 0.25
        if smb_sign:
            steps += smb_sign[:1]
            likelihood += 0.10
        if no_backup:
            steps += no_backup[:1]
            likelihood += 0.05

        if likelihood < 0.15 or not steps:
            return []

        return [AttackPath(
            self._next_id(),
            "Ransomware via SMB / EternalBlue",
            "An attacker on the same network exploits SMBv1 (MS17-010/EternalBlue) to gain remote code execution, "
            "then drops ransomware. Disabled AV and firewall accelerate the spread. "
            "WannaCry and NotPetya used this exact path.",
            steps,
            min(likelihood, 0.95),
            "Critical",
        )]

    def _rdp_brute_force_path(self) -> list:
        steps = []
        likelihood = 0.0

        rdp_open = self._by_title_keyword("port 3389", "rdp is enabled", "rdp enabled")
        no_nla = self._by_title_keyword("without network level", "without nla")
        weak_pwd = self._by_title_keyword("weak password", "no account lockout", "lockout")
        no_av = self._by_title_keyword("real-time protection", "no antivirus")
        fw = self._by_title_keyword("firewall disabled")

        if rdp_open:
            steps += rdp_open[:1]
            likelihood += 0.30
        if no_nla:
            steps += no_nla[:1]
            likelihood += 0.25
        if weak_pwd:
            steps += weak_pwd[:2]
            likelihood += 0.20
        if fw:
            steps += fw[:1]
            likelihood += 0.10
        if no_av:
            steps += no_av[:1]
            likelihood += 0.10

        if likelihood < 0.20 or not steps:
            return []

        return [AttackPath(
            self._next_id(),
            "RDP Brute-Force & Remote Takeover",
            "RDP exposed without NLA and weak password policy allows an attacker to brute-force credentials "
            "and gain interactive desktop access. From there they can install backdoors, dump credentials, "
            "and move laterally to other machines.",
            steps,
            min(likelihood, 0.95),
            "Critical",
        )]

    def _lateral_movement_path(self) -> list:
        steps = []
        likelihood = 0.0

        smb_sign = self._by_title_keyword("smb signing")
        shares = self._by_title_keyword("network shares", "custom shares")
        remote_reg = self._by_title_keyword("remote registry")
        winrm = self._by_title_keyword("port 5985", "port 5986", "winrm")
        psexec = self._by_title_keyword("psexec")

        if smb_sign:
            steps += smb_sign[:1]
            likelihood += 0.25
        if shares:
            steps += shares[:1]
            likelihood += 0.15
        if remote_reg:
            steps += remote_reg[:1]
            likelihood += 0.15
        if winrm:
            steps += winrm[:1]
            likelihood += 0.20
        if psexec:
            steps += psexec[:1]
            likelihood += 0.15

        if likelihood < 0.20 or not steps:
            return []

        return [AttackPath(
            self._next_id(),
            "NTLM Relay & Lateral Movement",
            "Without SMB signing, an attacker can relay NTLM authentication tokens to authenticate as the "
            "victim on other machines (Pass-the-Hash). Combined with open shares and WinRM, "
            "they can pivot across the network silently.",
            steps,
            min(likelihood, 0.90),
            "High",
        )]

    def _privilege_escalation_path(self) -> list:
        steps = []
        likelihood = 0.0

        unquoted = self._by_title_keyword("unquoted service")
        uac_off = self._by_title_keyword("uac", "never notify")
        multi_admin = self._by_title_keyword("multiple administrator")
        tasks = self._by_title_keyword("scheduled task")

        if unquoted:
            steps += unquoted[:2]
            likelihood += 0.35
        if uac_off:
            steps += uac_off[:1]
            likelihood += 0.30
        if multi_admin:
            steps += multi_admin[:1]
            likelihood += 0.10
        if tasks:
            steps += tasks[:1]
            likelihood += 0.15

        if likelihood < 0.20 or not steps:
            return []

        return [AttackPath(
            self._next_id(),
            "Local Privilege Escalation",
            "A low-privileged attacker can exploit unquoted service paths or disabled UAC to elevate to "
            "SYSTEM/Administrator. Once elevated, they can dump credentials, disable security tools, "
            "and establish persistent backdoors.",
            steps,
            min(likelihood, 0.90),
            "High",
        )]

    def _credential_harvesting_path(self) -> list:
        steps = []
        likelihood = 0.0

        env_creds = self._by_title_keyword("environment variable")
        weak_pwd = self._by_title_keyword("weak password", "complexity")
        lockout = self._by_title_keyword("lockout")
        mimikatz = self._by_title_keyword("mimikatz")
        filezilla = self._by_title_keyword("filezilla", "winscp")

        if env_creds:
            steps += env_creds[:1]
            likelihood += 0.30
        if weak_pwd:
            steps += weak_pwd[:1]
            likelihood += 0.20
        if lockout:
            steps += lockout[:1]
            likelihood += 0.20
        if mimikatz:
            steps += mimikatz[:1]
            likelihood += 0.30
        if filezilla:
            steps += filezilla[:1]
            likelihood += 0.15

        if likelihood < 0.20 or not steps:
            return []

        return [AttackPath(
            self._next_id(),
            "Credential Harvesting & Account Takeover",
            "Credentials leaked via environment variables, plaintext storage (FileZilla, WinSCP), or weak "
            "password policies allow attackers to harvest valid credentials. These are then used for "
            "account takeover, lateral movement, or cloud service access.",
            steps,
            min(likelihood, 0.90),
            "High",
        )]

    def _data_exfiltration_path(self) -> list:
        steps = []
        likelihood = 0.0

        ftp = self._by_title_keyword("port 21", "ftp")
        dns = self._by_title_keyword("port 53", "dns")
        no_bitlocker = self._by_title_keyword("bitlocker")
        shares = self._by_title_keyword("network shares")
        ext_conns = self._by_title_keyword("external connections")

        if ftp:
            steps += ftp[:1]
            likelihood += 0.20
        if dns:
            steps += dns[:1]
            likelihood += 0.15
        if no_bitlocker:
            steps += no_bitlocker[:1]
            likelihood += 0.15
        if shares:
            steps += shares[:1]
            likelihood += 0.15
        if ext_conns:
            steps += ext_conns[:1]
            likelihood += 0.20

        if likelihood < 0.20 or not steps:
            return []

        return [AttackPath(
            self._next_id(),
            "Data Exfiltration",
            "Unencrypted FTP, DNS tunneling channels, or exposed network shares allow an attacker to "
            "exfiltrate sensitive data without detection. Unencrypted drives make physical theft equally "
            "effective for data theft.",
            steps,
            min(likelihood, 0.85),
            "High",
        )]

    def _persistence_path(self) -> list:
        steps = []
        likelihood = 0.0

        tasks = self._by_title_keyword("scheduled task")
        remote_reg = self._by_title_keyword("remote registry")
        suspicious_proc = self._by_title_keyword("suspicious process")

        if tasks:
            steps += tasks[:2]
            likelihood += 0.30
        if remote_reg:
            steps += remote_reg[:1]
            likelihood += 0.20
        if suspicious_proc:
            steps += suspicious_proc[:2]
            likelihood += 0.20

        if likelihood < 0.25 or not steps:
            return []

        return [AttackPath(
            self._next_id(),
            "Persistence via Scheduled Tasks & Registry",
            "Attackers can plant backdoors via elevated scheduled tasks or registry run keys. "
            "Remote Registry access enables stealthy registry manipulation. "
            "Suspicious LOLBins processes suggest this may already be underway.",
            steps,
            min(likelihood, 0.80),
            "High",
        )]

    def _usb_attack_path(self) -> list:
        steps = []
        likelihood = 0.0

        autorun = self._by_title_keyword("autorun", "autoplay")
        no_av = self._by_title_keyword("real-time protection", "no antivirus")
        no_bitlocker = self._by_title_keyword("bitlocker")

        if autorun:
            steps += autorun[:1]
            likelihood += 0.40
        if no_av:
            steps += no_av[:1]
            likelihood += 0.25
        if no_bitlocker:
            steps += no_bitlocker[:1]
            likelihood += 0.15

        if likelihood < 0.30 or not steps:
            return []

        return [AttackPath(
            self._next_id(),
            "USB / Physical Media Attack",
            "Enabled AutoRun allows a malicious USB drive to execute code automatically when plugged in. "
            "Without AV, the payload runs undetected. Without BitLocker, a stolen drive gives full data access.",
            steps,
            min(likelihood, 0.85),
            "High",
        )]
