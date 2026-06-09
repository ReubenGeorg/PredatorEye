"""
Scans OS information, local users, groups, and scheduled tasks.
"""

import os
import platform
import subprocess
import socket
import getpass
import datetime


class SystemScanner:
    def scan(self) -> dict:
        return {
            "os_info": self._os_info(),
            "users": self._local_users(),
            "groups": self._admin_groups(),
            "scheduled_tasks": self._scheduled_tasks(),
            "shares": self._shared_resources(),
            "env_vars": self._sensitive_env_vars(),
        }

    # ------------------------------------------------------------------
    def _os_info(self) -> dict:
        uname = platform.uname()
        return {
            "hostname": socket.gethostname(),
            "os": uname.system,
            "version": uname.version,
            "release": uname.release,
            "machine": uname.machine,
            "processor": uname.processor,
            "current_user": getpass.getuser(),
            "scan_time": datetime.datetime.now().isoformat(),
            "uptime_seconds": self._uptime(),
        }

    def _uptime(self) -> int:
        try:
            import psutil
            return int((datetime.datetime.now() - datetime.datetime.fromtimestamp(psutil.boot_time())).total_seconds())
        except Exception:
            return -1

    def _local_users(self) -> list:
        users = []
        if platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    ["net", "user"], text=True, stderr=subprocess.DEVNULL
                )
                in_list = False
                for line in out.splitlines():
                    if "---" in line:
                        in_list = not in_list
                        continue
                    if in_list:
                        for name in line.split():
                            if name:
                                details = self._win_user_details(name)
                                users.append(details)
            except Exception:
                pass
        return users

    def _win_user_details(self, username: str) -> dict:
        result = {"name": username, "active": True, "admin": False, "last_logon": "Unknown", "password_expires": "Unknown"}
        try:
            out = subprocess.check_output(
                ["net", "user", username], text=True, stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                low = line.lower()
                if "account active" in low:
                    result["active"] = "yes" in low
                if "password expires" in low:
                    result["password_expires"] = line.split(None, 2)[-1].strip()
                if "last logon" in low:
                    result["last_logon"] = line.split(None, 2)[-1].strip()
        except Exception:
            pass
        try:
            admins_out = subprocess.check_output(
                ["net", "localgroup", "administrators"], text=True, stderr=subprocess.DEVNULL
            )
            if username.lower() in admins_out.lower():
                result["admin"] = True
        except Exception:
            pass
        return result

    def _admin_groups(self) -> list:
        groups = []
        if platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    ["net", "localgroup", "administrators"], text=True, stderr=subprocess.DEVNULL
                )
                in_members = False
                for line in out.splitlines():
                    if "---" in line:
                        in_members = not in_members
                        continue
                    if in_members and line.strip() and "The command" not in line:
                        groups.append(line.strip())
            except Exception:
                pass
        return groups

    def _scheduled_tasks(self) -> list:
        tasks = []
        if platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    ["schtasks", "/query", "/fo", "CSV", "/v"],
                    text=True, stderr=subprocess.DEVNULL
                )
                lines = out.strip().splitlines()
                if len(lines) < 2:
                    return tasks
                headers = [h.strip('"') for h in lines[0].split('","')]
                for line in lines[1:]:
                    if not line.strip():
                        continue
                    cols = [c.strip('"') for c in line.split('","')]
                    if len(cols) < len(headers):
                        continue
                    row = dict(zip(headers, cols))
                    task_name = row.get("TaskName", "")
                    run_as = row.get("Run As User", "")
                    status = row.get("Status", "")
                    task_to_run = row.get("Task To Run", "")
                    if run_as and ("SYSTEM" in run_as.upper() or "ADMINISTRATOR" in run_as.upper()):
                        tasks.append({
                            "name": task_name,
                            "run_as": run_as,
                            "status": status,
                            "command": task_to_run[:120],
                            "elevated": True,
                        })
            except Exception:
                pass
        return tasks[:30]  # cap to 30 most relevant

    def _shared_resources(self) -> list:
        shares = []
        if platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    ["net", "share"], text=True, stderr=subprocess.DEVNULL
                )
                for line in out.splitlines()[3:]:
                    parts = line.split()
                    if parts and parts[0] not in ("The", ""):
                        shares.append({
                            "name": parts[0],
                            "path": parts[1] if len(parts) > 1 else "N/A",
                        })
            except Exception:
                pass
        return shares

    def _sensitive_env_vars(self) -> list:
        sensitive_keywords = [
            "password", "passwd", "secret", "token", "api_key",
            "apikey", "key", "credential", "auth", "aws", "azure",
        ]
        found = []
        for var, value in os.environ.items():
            if any(kw in var.lower() for kw in sensitive_keywords):
                found.append({"variable": var, "value_hint": f"{value[:4]}***" if value else "(empty)"})
        return found
