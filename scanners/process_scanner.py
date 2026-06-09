"""
Scans running processes, highlighting privileged and suspicious ones.
"""

import platform
import subprocess


# Processes known to be exploitable or commonly abused
SUSPICIOUS_PROCESSES = {
    "powershell.exe": "PowerShell — often used in fileless malware and LOLBins attacks",
    "cmd.exe": "Command Prompt — can be used for lateral movement or persistence",
    "wscript.exe": "Windows Script Host — VBScript execution, malware delivery",
    "cscript.exe": "Command-line Script Host — malware / admin script execution",
    "mshta.exe": "HTML App host — commonly abused for payload execution",
    "regsvr32.exe": "COM/DLL registration — AppLocker bypass technique",
    "rundll32.exe": "DLL runner — code execution bypass",
    "certutil.exe": "Certificate utility — abused to download payloads",
    "bitsadmin.exe": "BITS admin — downloads malware stealthily",
    "wmic.exe": "WMI CLI — recon, lateral movement, persistence",
    "msiexec.exe": "Installer — remote MSI-based execution",
    "netsh.exe": "Network config — firewall manipulation",
    "schtasks.exe": "Task scheduler — persistence mechanism",
    "at.exe": "Legacy task scheduler — persistence",
    "psexec.exe": "Sysinternals remote exec — lateral movement",
    "mimikatz.exe": "Credential dumper — immediate compromise indicator",
    "procdump.exe": "Process dumper — credential harvesting",
    "nmap.exe": "Port scanner — active reconnaissance",
    "nc.exe": "Netcat — reverse shells / data exfiltration",
    "ncat.exe": "Netcat variant — same as nc.exe",
}


class ProcessScanner:
    def scan(self) -> dict:
        processes = self._get_processes()
        suspicious = [p for p in processes if p.get("suspicious")]
        privileged = [p for p in processes if p.get("elevated")]
        return {
            "all_count": len(processes),
            "suspicious": suspicious,
            "privileged": privileged,
            "processes": processes,
        }

    def _get_processes(self) -> list:
        processes = []
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "status"]):
                try:
                    info = proc.info
                    name_lower = (info.get("name") or "").lower()
                    username = info.get("username") or ""
                    elevated = any(
                        kw in username.upper()
                        for kw in ("SYSTEM", "ADMINISTRATOR", "ADMIN", "ROOT")
                    )
                    suspicious_reason = SUSPICIOUS_PROCESSES.get(name_lower, "")
                    cmdline = " ".join(info.get("cmdline") or [])[:200]
                    processes.append({
                        "pid": info["pid"],
                        "name": info.get("name", ""),
                        "username": username,
                        "cmdline": cmdline,
                        "elevated": elevated,
                        "suspicious": bool(suspicious_reason),
                        "suspicious_reason": suspicious_reason,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except ImportError:
            processes = self._fallback_tasklist()
        return processes

    def _fallback_tasklist(self) -> list:
        processes = []
        if platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    ["tasklist", "/fo", "csv", "/v"],
                    text=True, stderr=subprocess.DEVNULL
                )
                lines = out.strip().splitlines()
                if len(lines) < 2:
                    return processes
                for line in lines[1:]:
                    parts = [p.strip('"') for p in line.split('","')]
                    if len(parts) >= 2:
                        name = parts[0]
                        pid = parts[1]
                        username = parts[6] if len(parts) > 6 else ""
                        elevated = any(kw in username.upper() for kw in ("SYSTEM", "ADMINISTRATOR"))
                        suspicious_reason = SUSPICIOUS_PROCESSES.get(name.lower(), "")
                        processes.append({
                            "pid": pid,
                            "name": name,
                            "username": username,
                            "cmdline": "",
                            "elevated": elevated,
                            "suspicious": bool(suspicious_reason),
                            "suspicious_reason": suspicious_reason,
                        })
            except Exception:
                pass
        return processes
