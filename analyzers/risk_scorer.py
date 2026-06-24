"""
Converts raw scan results into a flat list of scored Finding objects.
"""

from config import SEVERITY_SCORES


class Finding:
    def __init__(self, fid, title, description, category, severity, details=None):
        self.id = fid
        self.title = title
        self.description = description
        self.category = category
        self.severity = severity
        self.score = SEVERITY_SCORES.get(severity, 0)
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "score": self.score,
            "details": self.details,
        }


class RiskScorer:
    def __init__(self, scan_results: dict):
        self.data = scan_results
        self._fid = 0

    def _next_id(self) -> str:
        self._fid += 1
        return f"F{self._fid:03d}"

    def score(self) -> list:
        findings = []
        findings += self._score_network()
        findings += self._score_security()
        findings += self._score_system()
        findings += self._score_services()
        findings += self._score_software()
        findings += self._score_processes()
        return sorted(findings, key=lambda f: f.score, reverse=True)

    # ------------------------------------------------------------------
    def _score_network(self) -> list:
        findings = []
        network = self.data.get("network", {})

        for port_info in network.get("open_ports", []):
            sev = port_info.get("severity", "Info")
            if sev == "Info":
                continue
            findings.append(Finding(
                self._next_id(),
                f"Open port {port_info['port']} ({port_info['service']})",
                port_info["risk_note"],
                "Initial Access",
                sev,
                {"port": port_info["port"], "service": port_info["service"],
                 "banner": port_info.get("banner", "")},
            ))

        # Many established connections to external IPs
        ext_conns = [
            c for c in network.get("active_connections", [])
            if not c["remote"].startswith("127.") and not c["remote"].startswith("::1")
        ]
        if len(ext_conns) > 20:
            findings.append(Finding(
                self._next_id(),
                f"Unusually high external connections ({len(ext_conns)})",
                "High number of established external connections may indicate C2 traffic or data exfiltration.",
                "Exfiltration",
                "Medium",
                {"count": len(ext_conns)},
            ))

        return findings

    def _score_security(self) -> list:
        findings = []
        sec = self.data.get("security", {})

        # Firewall
        fw = sec.get("firewall", {})
        for profile in ("domain", "private", "public"):
            if fw.get(profile) == "OFF":
                findings.append(Finding(
                    self._next_id(),
                    f"Windows Firewall disabled ({profile} profile)",
                    f"The {profile} firewall profile is off, exposing all ports to the network.",
                    "Defense Evasion",
                    "Critical" if profile == "public" else "High",
                    {"profile": profile},
                ))

        # UAC
        uac = sec.get("uac", {})
        if not uac.get("enabled", True):
            findings.append(Finding(
                self._next_id(),
                "UAC (User Account Control) is disabled",
                "Without UAC, any process can elevate to administrator silently.",
                "Privilege Escalation",
                "Critical",
                uac,
            ))
        elif "Never notify" in uac.get("level", ""):
            findings.append(Finding(
                self._next_id(),
                "UAC set to 'Never Notify' (effectively disabled)",
                "UAC level 0 means no prompt for admin actions — privilege escalation is silent.",
                "Privilege Escalation",
                "High",
                uac,
            ))

        # Antivirus
        av = sec.get("antivirus", {})
        third_party_active = av.get("third_party_av_active", False)
        defender_rt = av.get("defender_realtime")

        if defender_rt is False and not third_party_active:
            # Defender is off AND no other AV is covering the system — genuine risk
            findings.append(Finding(
                self._next_id(),
                "Windows Defender real-time protection is OFF",
                "Malware can execute without being detected or blocked. "
                "No third-party antivirus was detected as active.",
                "Defense Evasion",
                "Critical",
                av,
            ))
        elif defender_rt is False and third_party_active:
            # Defender intentionally disabled because another AV is active — normal
            names = ", ".join(
                p["name"] for p in av.get("products", [])
                if p.get("enabled") and "windows defender" not in p["name"].lower()
            ) or "third-party antivirus"
            findings.append(Finding(
                self._next_id(),
                f"Windows Defender passive (replaced by {names})",
                f"Defender is disabled because {names} is the active antivirus. "
                "This is expected behaviour — ensure the third-party AV is kept updated.",
                "Defense Evasion",
                "Low",
                av,
            ))

        if not av.get("products") and not third_party_active:
            findings.append(Finding(
                self._next_id(),
                "No antivirus product detected",
                "No AV registered in the Security Center — system has no malware protection.",
                "Defense Evasion",
                "High",
                av,
            ))

        # RDP
        rdp = sec.get("rdp", {})
        if rdp.get("enabled"):
            sev = "High"
            if not rdp.get("nla_required"):
                sev = "Critical"
                findings.append(Finding(
                    self._next_id(),
                    "RDP enabled without Network Level Authentication (NLA)",
                    "RDP without NLA is vulnerable to BlueKeep (CVE-2019-0708) and brute-force attacks.",
                    "Initial Access",
                    "Critical",
                    rdp,
                ))
            else:
                findings.append(Finding(
                    self._next_id(),
                    "RDP is enabled (NLA required)",
                    "RDP is active; ensure strong passwords and account lockout are enforced.",
                    "Initial Access",
                    "Medium",
                    rdp,
                ))

        # SMB
        smb = sec.get("smb", {})
        if smb.get("smb1_enabled"):
            findings.append(Finding(
                self._next_id(),
                "SMBv1 is enabled (EternalBlue target)",
                "SMBv1 is exploited by EternalBlue (MS17-010) — used by WannaCry and NotPetya ransomware.",
                "Lateral Movement",
                "Critical",
                smb,
            ))
        if not smb.get("signing_required"):
            findings.append(Finding(
                self._next_id(),
                "SMB signing not required",
                "Without SMB signing, relay attacks (NTLM relay) can compromise the system.",
                "Credential Access",
                "High",
                smb,
            ))

        # Password policy
        pwd = sec.get("password_policy", {})
        if pwd.get("min_length", 0) < 8:
            findings.append(Finding(
                self._next_id(),
                f"Weak password minimum length ({pwd.get('min_length', 0)} chars)",
                "Short passwords are trivially brute-forced or dictionary-attacked.",
                "Credential Access",
                "High",
                pwd,
            ))
        if pwd.get("lockout_threshold", 0) == 0:
            findings.append(Finding(
                self._next_id(),
                "No account lockout policy configured",
                "Without lockout, attackers can brute-force passwords indefinitely.",
                "Credential Access",
                "High",
                pwd,
            ))
        if not pwd.get("complexity"):
            findings.append(Finding(
                self._next_id(),
                "Password complexity not enforced",
                "Simple passwords are easily cracked by dictionary or rainbow table attacks.",
                "Credential Access",
                "Medium",
                pwd,
            ))

        # BitLocker
        bl = sec.get("bitlocker", {})
        if not bl.get("enabled"):
            findings.append(Finding(
                self._next_id(),
                "BitLocker disk encryption not enabled",
                "Without disk encryption, physical access or stolen drives expose all data.",
                "Impact",
                "Medium",
                bl,
            ))

        # AutoRun
        ar = sec.get("autorun", {})
        if not ar.get("autorun_disabled"):
            findings.append(Finding(
                self._next_id(),
                "AutoRun/AutoPlay may be enabled",
                "Enabled AutoRun allows malicious USB drives to execute code automatically.",
                "Initial Access",
                "Medium",
                ar,
            ))

        # Remote Registry
        rr = sec.get("remote_registry", {})
        if rr.get("running"):
            findings.append(Finding(
                self._next_id(),
                "Remote Registry service is running",
                "Remote Registry allows remote read/write of the registry — reconnaissance and persistence vector.",
                "Discovery",
                "High",
                rr,
            ))

        return findings

    def _score_system(self) -> list:
        findings = []
        system = self.data.get("system", {})

        # Sensitive env vars with credentials
        env_vars = system.get("env_vars", [])
        if env_vars:
            findings.append(Finding(
                self._next_id(),
                f"Sensitive credentials in environment variables ({len(env_vars)} found)",
                "Credentials stored in environment variables can be read by any process running as the same user.",
                "Credential Access",
                "High",
                {"variables": [v["variable"] for v in env_vars]},
            ))

        # Elevated scheduled tasks running unknown binaries
        tasks = system.get("scheduled_tasks", [])
        suspicious_tasks = [
            t for t in tasks
            if t.get("elevated") and any(
                kw in (t.get("command") or "").lower()
                for kw in ["temp", "appdata", "downloads", "public", "http", "ftp", "\\users\\"]
            )
        ]
        for task in suspicious_tasks[:5]:
            findings.append(Finding(
                self._next_id(),
                f"Suspicious elevated scheduled task: {task['name'][:60]}",
                f"SYSTEM/Admin scheduled task runs from a user-writable location: {task.get('command', '')[:100]}",
                "Persistence",
                "High",
                task,
            ))

        # Shared resources (admin shares are normal; custom shares are risky)
        shares = system.get("shares", [])
        custom_shares = [s for s in shares if s["name"].upper() not in ("C$", "D$", "E$", "ADMIN$", "IPC$", "PRINT$")]
        if custom_shares:
            findings.append(Finding(
                self._next_id(),
                f"Custom network shares detected ({len(custom_shares)})",
                "Non-default shares can expose sensitive data to the network.",
                "Discovery",
                "Medium",
                {"shares": custom_shares},
            ))

        # Multiple admin users
        users = system.get("users", [])
        admin_users = [u for u in users if u.get("admin")]
        if len(admin_users) > 2:
            findings.append(Finding(
                self._next_id(),
                f"Multiple administrator accounts ({len(admin_users)})",
                "Excess admin accounts increase the attack surface for privilege escalation.",
                "Privilege Escalation",
                "Medium",
                {"admin_users": [u["name"] for u in admin_users]},
            ))

        # Inactive users with admin rights
        inactive_admins = [u for u in users if u.get("admin") and u.get("last_logon") == "Never"]
        if inactive_admins:
            findings.append(Finding(
                self._next_id(),
                f"Inactive admin accounts never logged in ({len(inactive_admins)})",
                "Dormant admin accounts are targets for takeover; disable or remove them.",
                "Privilege Escalation",
                "Medium",
                {"accounts": [u["name"] for u in inactive_admins]},
            ))

        return findings

    def _score_services(self) -> list:
        findings = []
        services = self.data.get("services", {})

        for svc in services.get("unquoted_path_services", []):
            findings.append(Finding(
                self._next_id(),
                f"Unquoted service path: {svc['name']}",
                svc.get("risk_note", "Unquoted service path with spaces — local privilege escalation vector."),
                "Privilege Escalation",
                "High",
                svc,
            ))

        return findings

    def _score_software(self) -> list:
        findings = []
        software = self.data.get("software", {})

        for app in software.get("flagged_software", []):
            name = app["name"]
            reason = app.get("risk_reason", "Potentially risky software")
            severity = "Critical" if any(kw in name.lower() for kw in ("flash", "silverlight", "internet explorer")) else "Medium"
            findings.append(Finding(
                self._next_id(),
                f"Risky software installed: {name}",
                reason,
                "Initial Access",
                severity,
                {"name": name, "version": app.get("version", ""), "publisher": app.get("publisher", "")},
            ))

        return findings

    def _score_processes(self) -> list:
        findings = []
        processes = self.data.get("processes", {})

        for proc in processes.get("suspicious", []):
            findings.append(Finding(
                self._next_id(),
                f"Suspicious process running: {proc['name']} (PID {proc['pid']})",
                proc.get("suspicious_reason", ""),
                "Execution",
                "Medium",
                proc,
            ))

        return findings
