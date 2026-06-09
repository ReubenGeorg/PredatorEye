"""
Scans Windows security settings: firewall, UAC, antivirus, Windows Update,
BitLocker, SMB signing, RDP security, and password policy.
"""

import platform
import subprocess
import re


class SecurityScanner:
    def scan(self) -> dict:
        return {
            "firewall": self._firewall_status(),
            "uac": self._uac_status(),
            "antivirus": self._antivirus_status(),
            "windows_update": self._windows_update_status(),
            "rdp": self._rdp_settings(),
            "smb": self._smb_settings(),
            "password_policy": self._password_policy(),
            "bitlocker": self._bitlocker_status(),
            "autorun": self._autorun_status(),
            "remote_registry": self._remote_registry_status(),
        }

    # ------------------------------------------------------------------
    def _firewall_status(self) -> dict:
        result = {"domain": "Unknown", "private": "Unknown", "public": "Unknown"}
        if platform.system() != "Windows":
            return result
        try:
            out = subprocess.check_output(
                ["netsh", "advfirewall", "show", "allprofiles"],
                text=True, stderr=subprocess.DEVNULL
            )
            profile = None
            for line in out.splitlines():
                low = line.strip().lower()
                if "domain profile" in low:
                    profile = "domain"
                elif "private profile" in low:
                    profile = "private"
                elif "public profile" in low:
                    profile = "public"
                elif "state" in low and profile:
                    state = "ON" if "on" in low else "OFF"
                    result[profile] = state
        except Exception:
            pass
        return result

    def _uac_status(self) -> dict:
        result = {"enabled": True, "level": "Unknown"}
        if platform.system() != "Windows":
            return result
        try:
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                try:
                    val, _ = winreg.QueryValueEx(key, "EnableLUA")
                    result["enabled"] = bool(val)
                except Exception:
                    pass
                try:
                    lvl, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
                    levels = {0: "Never notify (disabled)", 1: "Notify (no desktop dimming)",
                              2: "Always notify", 5: "Notify only for app changes (default)"}
                    result["level"] = levels.get(lvl, str(lvl))
                except Exception:
                    pass
        except Exception:
            pass
        return result

    def _antivirus_status(self) -> dict:
        products = []
        if platform.system() != "Windows":
            return {"products": products, "defender_realtime": "Unknown"}
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled,AntivirusEnabled | ConvertTo-Json"],
                text=True, stderr=subprocess.DEVNULL, timeout=15
            )
            import json
            data = json.loads(out)
            return {
                "products": ["Windows Defender"],
                "defender_realtime": data.get("RealTimeProtectionEnabled", "Unknown"),
                "defender_av_enabled": data.get("AntivirusEnabled", "Unknown"),
                "mode": data.get("AMRunningMode", "Unknown"),
            }
        except Exception:
            pass
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState | ConvertTo-Json"],
                text=True, stderr=subprocess.DEVNULL, timeout=15
            )
            import json
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                products.append(item.get("displayName", "Unknown"))
        except Exception:
            pass
        return {"products": products, "defender_realtime": "Unknown"}

    def _windows_update_status(self) -> dict:
        result = {"last_check": "Unknown", "pending_updates": -1}
        if platform.system() != "Windows":
            return result
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate"],
                text=True, stderr=subprocess.DEVNULL, timeout=15
            )
            result["last_check"] = out.strip()
        except Exception:
            pass
        return result

    def _rdp_settings(self) -> dict:
        result = {"enabled": False, "nla_required": True, "port": 3389}
        if platform.system() != "Windows":
            return result
        try:
            import winreg
            key_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                try:
                    val, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
                    result["enabled"] = (val == 0)
                except Exception:
                    pass
            nla_path = r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, nla_path) as key:
                try:
                    nla, _ = winreg.QueryValueEx(key, "UserAuthentication")
                    result["nla_required"] = bool(nla)
                    port, _ = winreg.QueryValueEx(key, "PortNumber")
                    result["port"] = port
                except Exception:
                    pass
        except Exception:
            pass
        return result

    def _smb_settings(self) -> dict:
        result = {"smb1_enabled": False, "signing_required": False}
        if platform.system() != "Windows":
            return result
        try:
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,RequireSecuritySignature | ConvertTo-Json"],
                text=True, stderr=subprocess.DEVNULL, timeout=15
            )
            import json
            data = json.loads(out)
            result["smb1_enabled"] = data.get("EnableSMB1Protocol", False)
            result["signing_required"] = data.get("RequireSecuritySignature", False)
        except Exception:
            pass
        return result

    def _password_policy(self) -> dict:
        policy = {"min_length": 0, "max_age_days": 0, "complexity": False, "lockout_threshold": 0}
        if platform.system() != "Windows":
            return policy
        try:
            out = subprocess.check_output(
                ["net", "accounts"], text=True, stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                low = line.lower()
                if "minimum password length" in low:
                    m = re.search(r'\d+', line)
                    if m:
                        policy["min_length"] = int(m.group())
                if "maximum password age" in low:
                    m = re.search(r'\d+', line)
                    if m:
                        policy["max_age_days"] = int(m.group())
                if "lockout threshold" in low:
                    m = re.search(r'\d+', line)
                    if m:
                        policy["lockout_threshold"] = int(m.group())
        except Exception:
            pass
        try:
            import winreg
            key_path = r"SYSTEM\CurrentControlSet\Control\SAM"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                try:
                    val, _ = winreg.QueryValueEx(key, "PasswordComplexity")
                    policy["complexity"] = bool(val)
                except Exception:
                    pass
        except Exception:
            pass
        return policy

    def _bitlocker_status(self) -> dict:
        result = {"enabled": False, "status": "Unknown"}
        if platform.system() != "Windows":
            return result
        try:
            out = subprocess.check_output(
                ["manage-bde", "-status", "C:"],
                text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            if "Protection On" in out:
                result["enabled"] = True
                result["status"] = "Protection On"
            elif "Protection Off" in out:
                result["enabled"] = False
                result["status"] = "Protection Off"
        except Exception:
            result["status"] = "Could not determine (may need elevation)"
        return result

    def _autorun_status(self) -> dict:
        """Check if AutoRun/AutoPlay is disabled (USB attack vector)."""
        result = {"autorun_disabled": False}
        if platform.system() != "Windows":
            return result
        try:
            import winreg
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                try:
                    val, _ = winreg.QueryValueEx(key, "NoDriveTypeAutoRun")
                    result["autorun_disabled"] = (val == 255)
                    result["value"] = val
                except Exception:
                    result["autorun_disabled"] = False
        except Exception:
            pass
        return result

    def _remote_registry_status(self) -> dict:
        result = {"running": False}
        if platform.system() != "Windows":
            return result
        try:
            out = subprocess.check_output(
                ["sc", "query", "RemoteRegistry"],
                text=True, stderr=subprocess.DEVNULL
            )
            result["running"] = "RUNNING" in out.upper()
        except Exception:
            pass
        return result
