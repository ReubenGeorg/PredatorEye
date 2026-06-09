"""
Scans installed software via Windows registry and checks for outdated/risky apps.
"""

import platform
import subprocess


# Software known to be frequently exploited when outdated
RISKY_SOFTWARE_KEYWORDS = {
    "adobe reader": "PDF reader — historically many RCE vulnerabilities",
    "adobe acrobat": "PDF editor — high CVE count, keep updated",
    "flash": "Adobe Flash — end-of-life, remove immediately",
    "java": "Java Runtime — frequent RCE vulnerabilities; disable if unused",
    "jre": "Java Runtime Environment — same as Java",
    "silverlight": "Microsoft Silverlight — end-of-life, remove",
    "winrar": "WinRAR — path traversal CVEs (CVE-2023-38831 etc.)",
    "7-zip": "7-Zip — occasional heap overflows; keep updated",
    "vlc": "VLC Media Player — heap overflows in old versions",
    "putty": "PuTTY SSH — privilege escalation in older versions",
    "filezilla": "FileZilla — stores plaintext credentials on disk",
    "winscp": "WinSCP — credential storage vulnerabilities",
    "teamviewer": "TeamViewer — targeted by attackers, ensure updated",
    "anydesk": "AnyDesk — remote access tool; ensure updated & monitor",
    "chrome": "Google Chrome — keep updated, many zero-days",
    "firefox": "Mozilla Firefox — keep updated regularly",
    "internet explorer": "Internet Explorer — end-of-life, remove",
    "microsoft edge": "Edge — keep updated",
    "wireshark": "Wireshark — indicates network analysis capability",
    "nmap": "Nmap — port scanner installed; audit intended use",
    "metasploit": "Metasploit — exploitation framework; verify legitimacy",
    "python": "Python — scripting runtime; can execute arbitrary code",
    "node": "Node.js — JavaScript runtime; attack surface if exposed",
    "openssh": "OpenSSH — ensure key-based auth and no root login",
    "wamp": "WAMP/XAMPP — local web server often misconfigured",
    "xampp": "XAMPP — local web server; remove if not needed",
}


class SoftwareScanner:
    def scan(self) -> dict:
        software = self._get_installed_software()
        flagged = []
        for app in software:
            name_lower = app["name"].lower()
            for kw, reason in RISKY_SOFTWARE_KEYWORDS.items():
                if kw in name_lower:
                    flagged.append({**app, "risk_reason": reason})
                    break
        return {
            "total_installed": len(software),
            "flagged_software": flagged,
            "all_software": software,
        }

    def _get_installed_software(self) -> list:
        apps = []
        if platform.system() == "Windows":
            apps = self._from_registry()
        if not apps:
            apps = self._from_wmic()
        seen = set()
        unique = []
        for a in apps:
            key = a["name"].lower()
            if key not in seen:
                seen.add(key)
                unique.append(a)
        return sorted(unique, key=lambda x: x["name"].lower())

    def _from_registry(self) -> list:
        apps = []
        try:
            import winreg
            keys = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ]
            hives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
            for hive in hives:
                for key_path in keys:
                    try:
                        with winreg.OpenKey(hive, key_path) as key:
                            for i in range(winreg.QueryInfoKey(key)[0]):
                                try:
                                    sub_name = winreg.EnumKey(key, i)
                                    with winreg.OpenKey(key, sub_name) as sub:
                                        def _get(name):
                                            try:
                                                return winreg.QueryValueEx(sub, name)[0]
                                            except Exception:
                                                return ""
                                        display = _get("DisplayName")
                                        if display:
                                            apps.append({
                                                "name": display,
                                                "version": _get("DisplayVersion"),
                                                "publisher": _get("Publisher"),
                                                "install_date": _get("InstallDate"),
                                            })
                                except Exception:
                                    continue
                    except Exception:
                        continue
        except ImportError:
            pass
        return apps

    def _from_wmic(self) -> list:
        apps = []
        try:
            out = subprocess.check_output(
                ["wmic", "product", "get", "Name,Version,Vendor"],
                text=True, stderr=subprocess.DEVNULL, timeout=30
            )
            for line in out.splitlines()[1:]:
                parts = line.strip()
                if parts:
                    apps.append({"name": parts, "version": "", "publisher": "", "install_date": ""})
        except Exception:
            pass
        return apps
