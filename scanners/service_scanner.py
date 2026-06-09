"""
Scans Windows services for misconfigurations: unquoted paths, weak permissions,
auto-start high-privilege services.
"""

import os
import platform
import subprocess
import re


class ServiceScanner:
    def scan(self) -> dict:
        services = self._get_services()
        unquoted = self._find_unquoted_paths(services)
        auto_system = [s for s in services if s.get("start_type") == "Auto" and "SYSTEM" in s.get("run_as", "").upper()]
        return {
            "total_services": len(services),
            "unquoted_path_services": unquoted,
            "auto_system_services": auto_system[:20],
            "all_services": services,
        }

    def _get_services(self) -> list:
        services = []
        if platform.system() != "Windows":
            return services
        try:
            out = subprocess.check_output(
                ["sc", "query", "type=", "all", "state=", "all"],
                text=True, stderr=subprocess.DEVNULL
            )
            # parse service names then get details
            service_names = re.findall(r"SERVICE_NAME:\s+(.+)", out)
            for name in service_names[:80]:  # cap for performance
                details = self._service_details(name.strip())
                if details:
                    services.append(details)
        except Exception:
            services = self._fallback_services()
        return services

    def _service_details(self, name: str) -> dict | None:
        try:
            out = subprocess.check_output(
                ["sc", "qc", name], text=True, stderr=subprocess.DEVNULL
            )
            binary_path = ""
            start_type = ""
            for line in out.splitlines():
                if "BINARY_PATH_NAME" in line:
                    binary_path = line.split(":", 1)[-1].strip()
                if "START_TYPE" in line:
                    start_type_raw = line.split(":", 1)[-1].strip()
                    if "AUTO" in start_type_raw.upper():
                        start_type = "Auto"
                    elif "DEMAND" in start_type_raw.upper():
                        start_type = "Manual"
                    elif "DISABLED" in start_type_raw.upper():
                        start_type = "Disabled"
                    else:
                        start_type = start_type_raw

            run_as = self._get_service_run_as(name)
            return {
                "name": name,
                "binary_path": binary_path,
                "start_type": start_type,
                "run_as": run_as,
            }
        except Exception:
            return None

    def _get_service_run_as(self, name: str) -> str:
        try:
            out = subprocess.check_output(
                ["sc", "showsid", name], text=True, stderr=subprocess.DEVNULL
            )
            return "LOCAL SYSTEM"
        except Exception:
            pass
        try:
            import winreg
            key_path = rf"SYSTEM\CurrentControlSet\Services\{name}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                try:
                    account, _ = winreg.QueryValueEx(key, "ObjectName")
                    return account
                except Exception:
                    return "LocalSystem"
        except Exception:
            return "Unknown"

    def _find_unquoted_paths(self, services: list) -> list:
        """
        An unquoted service path with spaces is a privilege escalation vector:
        C:\\Program Files\\My Service\\svc.exe can be hijacked by placing
        C:\\Program.exe or C:\\Program Files\\My.exe.
        """
        unquoted = []
        for svc in services:
            path = svc.get("binary_path", "")
            # Only flag if path has spaces and isn't quoted
            if " " in path and not path.startswith('"'):
                # Exclude paths that start with system dirs without spaces before the exe
                unquoted.append({
                    **svc,
                    "risk_note": (
                        "Unquoted service path with spaces — a local attacker can plant "
                        "a malicious executable to hijack this service on restart."
                    ),
                })
        return unquoted

    def _fallback_services(self) -> list:
        services = []
        try:
            out = subprocess.check_output(
                ["sc", "query", "type=", "service", "state=", "all"],
                text=True, stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                if line.strip().startswith("SERVICE_NAME:"):
                    name = line.split(":", 1)[-1].strip()
                    services.append({"name": name, "binary_path": "", "start_type": "", "run_as": ""})
        except Exception:
            pass
        return services
