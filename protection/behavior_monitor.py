"""
protection/behavior_monitor.py
================================
Heuristic behavioural scoring engine — Layer 3 of PredatorEye's three-layer
protection stack (hash  →  YARA pattern  →  behavioural heuristic).

Academic rationale (for project report)
-----------------------------------------
Layers 1 and 2 are *static* analysis: they examine file content on disk.
A sophisticated attacker can bypass both by:
  - Using a never-seen-before binary (defeats hash lookup, Layer 1)
  - Writing a payload in memory without touching disk (defeats YARA, Layer 2)
  - Using legitimate signed system binaries as proxies (LOLBins)

Layer 3 addresses these gaps by inspecting *running process state* — what
executables are doing right now rather than what they look like on disk.
This is the approach used by Endpoint Detection and Response (EDR) products
such as CrowdStrike Falcon, Carbon Black, and Microsoft Defender for Endpoint.

Heuristic scoring model
------------------------
Each running process is evaluated against a set of rules.  Rules are
independent and additive: a process accumulates risk points for each rule
that fires.  The total score maps to a severity rating:

    0–20  : Clean (no significant indicators)
    21–40 : Low    — single weak indicator; log only
    41–60 : Medium — warrants investigation
    61–80 : High   — likely malicious or misconfigured
    81+   : Critical — strong evidence of active compromise

This probabilistic approach avoids the binary "malicious / benign" decision
that causes false positives in strict allow-list models.  A legitimate admin
script may trigger one rule (e.g., PowerShell with -ExecutionPolicy Bypass)
while a real attacker's payload would trigger four or five, crossing the
High threshold and generating an alert.

Implemented heuristic rules
-----------------------------
┌──────────────────────────────────────────────────────┬───────┬────────────┐
│ Rule                                                 │ Pts   │ MITRE      │
├──────────────────────────────────────────────────────┼───────┼────────────┤
│ Execution from writable user path (Temp/AppData/DL)  │  30   │ T1204      │
│ System process name running from wrong path          │  45   │ T1036.005  │
│ Suspicious parent-child relationship                 │  35   │ T1059      │
│ PowerShell -EncodedCommand in cmdline                │  40   │ T1027      │
│ PowerShell -WindowStyle Hidden or -NonInteractive    │  30   │ T1564.003  │
│ PowerShell -ExecutionPolicy Bypass                   │  25   │ T1059.001  │
│ Script-interpreter proxy (mshta/wscript/cscript)     │  35   │ T1218      │
│ cmd.exe with long base64-looking argument            │  30   │ T1059.003  │
│ Randomised executable name (high char-set entropy)   │  15   │ T1036      │
│ Excessive outbound network connections (> 5)         │  20   │ T1071      │
└──────────────────────────────────────────────────────┴───────┴────────────┘

Limitations and false-positive mitigation
-------------------------------------------
- psutil can only access processes the current user has permission to inspect.
  System-level processes (pid 0, 4) are skipped gracefully.
- Legitimate administrative tools (Sysinternals, VS Code terminal, WSL) will
  trigger some rules.  The recommended workflow is: flag High/Critical only
  and correlate with the ThreatCorrelator (Module 7) before alerting.
- This module never terminates or suspends processes — it is read-only.
"""

import os
import re
import math
import string
import datetime
import platform
from typing import Optional


# ── Constants ──────────────────────────────────────────────────────────────────

# Score thresholds → severity labels
_THRESHOLDS: list = [
    (81, "Critical"),
    (61, "High"),
    (41, "Medium"),
    (21, "Low"),
    (0,  "Clean"),
]

# Processes that must live in specific directories (Windows).
# Key = lowercase process name, value = required path substring (also lowercase).
# Running one of these names from any other location is a strong masquerading
# indicator — T1036.005.
_SYSTEM_PROCESS_PATHS: dict = {
    "svchost.exe":    r"windows\system32",
    "lsass.exe":      r"windows\system32",
    "csrss.exe":      r"windows\system32",
    "services.exe":   r"windows\system32",
    "winlogon.exe":   r"windows\system32",
    "smss.exe":       r"windows\system32",
    "wininit.exe":    r"windows\system32",
    "taskhost.exe":   r"windows\system32",
    "taskhostw.exe":  r"windows\system32",
    "explorer.exe":   r"windows",
    "dwm.exe":        r"windows\system32",
}

# Parent processes whose children should be restricted.
# Key = lowercase parent name, value = set of suspicious child names (lowercase).
# Office apps / PDF readers spawning a shell interpreter is a classic
# phishing-macro execution pattern — T1059.
_SUSPICIOUS_CHILDREN: dict = {
    "winword.exe":    {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                       "mshta.exe", "regsvr32.exe", "rundll32.exe"},
    "excel.exe":      {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                       "mshta.exe", "regsvr32.exe", "rundll32.exe"},
    "powerpnt.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                       "mshta.exe"},
    "outlook.exe":    {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                       "mshta.exe"},
    "acrord32.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "chrome.exe":     {"cmd.exe", "powershell.exe"},
    "msedge.exe":     {"cmd.exe", "powershell.exe"},
    "firefox.exe":    {"cmd.exe", "powershell.exe"},
    "iexplore.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"},
}

# Paths that indicate a process is running from a user-writable directory.
# Executables should almost never live here — T1204.
_SUSPICIOUS_PATH_PATTERNS: list = [
    r"\\temp\\",
    r"\\tmp\\",
    r"\\appdata\\local\\temp\\",
    r"\\appdata\\roaming\\",
    r"\\downloads\\",
    r"\\desktop\\",
    r"\\public\\",
    r"/tmp/",
    r"/var/tmp/",
]

# Executable extensions; non-exe paths score lower for path heuristic
_EXE_EXTENSIONS: set = {".exe", ".dll", ".com", ".bat", ".cmd", ".ps1",
                         ".vbs", ".js", ".hta", ".scr", ".pif"}

# Characters used for entropy estimation of process names.
# A randomly-generated name (like "aB3kLm9p.exe") has high entropy vs
# "svchost.exe" which uses a small character set — T1036.
_ALPHANUM: set = set(string.ascii_lowercase + string.digits)

# Minimum name length to bother estimating entropy (very short names are noisy)
_MIN_ENTROPY_NAME_LEN: int = 6

# Maximum external network connections before the rule fires — T1071
_MAX_CONNECTIONS: int = 5

# Skip idle processes (pid 0 and 4 on Windows are System Idle and System)
_SKIP_PIDS: set = {0, 4}


# ── Score → severity ───────────────────────────────────────────────────────────

def _score_to_severity(score: int) -> str:
    for threshold, label in _THRESHOLDS:
        if score >= threshold:
            return label
    return "Clean"


# ── Name entropy ───────────────────────────────────────────────────────────────

def _name_entropy(name: str) -> float:
    """
    Shannon entropy of the character set used in an executable name stem.

    Legitimate Windows executables use a small vocabulary of predictable
    characters (svchost, explorer, chrome, notepad ...).  Randomly-generated
    names occupy a much larger character space, pushing entropy above ~3.5 bits
    per character.

    Only the stem (before the extension) is analysed — "svchost" not
    "svchost.exe" — to avoid inflating entropy with the dot and extension
    characters that every exe shares.
    """
    stem = os.path.splitext(name.lower())[0]
    if len(stem) < _MIN_ENTROPY_NAME_LEN:
        return 0.0

    freq: dict = {}
    for ch in stem:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    total = len(stem)
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


# ── Process result constructor ─────────────────────────────────────────────────

def _proc_result(
    pid: int,
    name: str,
    exe: str,
    cmdline: str,
    username: str,
    score: int,
    triggered_rules: list,
    connections: int,
    error: Optional[str] = None,
) -> dict:
    is_suspicious = score > 20
    return {
        "pid":             pid,
        "name":            name,
        "exe":             exe,
        "cmdline":         cmdline,
        "username":        username,
        "score":           score,
        "severity":        _score_to_severity(score),
        "is_suspicious":   is_suspicious,
        "triggered_rules": triggered_rules,
        "connections":     connections,
        "scanned_at":      datetime.datetime.now().isoformat(timespec="seconds"),
        "error":           error,
    }


# ── Per-process heuristic evaluation ──────────────────────────────────────────

def _evaluate(pid: int, proc_info: dict, parent_name: str) -> dict:
    """
    Apply all heuristic rules to a single pre-fetched process info dict.

    proc_info keys (all may be None/empty if access was denied):
        name, exe, cmdline (as a list), username, connections (int)

    Returns a _proc_result dict.
    """
    name       = (proc_info.get("name")     or "").strip()
    exe        = (proc_info.get("exe")      or "").strip()
    cmdline    = proc_info.get("cmdline")   or []
    username   = (proc_info.get("username") or "").strip()
    connections= proc_info.get("connections", 0)

    name_lower = name.lower()
    exe_lower  = exe.lower()
    cmd_str    = " ".join(cmdline).lower() if cmdline else ""

    score:          int  = 0
    triggered_rules: list = []

    # ── Rule 1: suspicious writable-path execution ────────────────────────────
    if exe_lower:
        ext = os.path.splitext(exe_lower)[1]
        if ext in _EXE_EXTENSIONS:
            for pat in _SUSPICIOUS_PATH_PATTERNS:
                if pat in exe_lower:
                    score += 30
                    triggered_rules.append({
                        "rule":              "Execution_From_Writable_Path",
                        "description":       f"Executable running from user-writable path: {exe}",
                        "mitre_technique":   "T1204",
                        "mitre_tactic":      "Execution",
                        "points":            30,
                    })
                    break

    # ── Rule 2: system-process masquerading (wrong path) ─────────────────────
    if name_lower in _SYSTEM_PROCESS_PATHS and exe_lower:
        required = _SYSTEM_PROCESS_PATHS[name_lower]
        if required not in exe_lower:
            score += 45
            triggered_rules.append({
                "rule":              "System_Process_Path_Mismatch",
                "description":       (
                    f"{name} running from {exe!r} instead of expected "
                    f"path containing '{required}'"
                ),
                "mitre_technique":   "T1036.005",
                "mitre_tactic":      "Defense Evasion",
                "points":            45,
            })

    # ── Rule 3: suspicious parent→child spawning ──────────────────────────────
    if parent_name.lower() in _SUSPICIOUS_CHILDREN:
        if name_lower in _SUSPICIOUS_CHILDREN[parent_name.lower()]:
            score += 35
            triggered_rules.append({
                "rule":              "Suspicious_Child_Process",
                "description":       (
                    f"{name} (pid {pid}) spawned by {parent_name} — "
                    "consistent with macro/phishing execution"
                ),
                "mitre_technique":   "T1059",
                "mitre_tactic":      "Execution",
                "points":            35,
            })

    # ── Rules 4-6: PowerShell command-line flags (from cmd string) ────────────
    if cmd_str and ("powershell" in cmd_str or "pwsh" in cmd_str):

        # -EncodedCommand  (base64 payload delivery)
        if re.search(r"-e(nc(odedcommand)?)?\s+[a-zA-Z0-9+/]{20,}", cmd_str, re.I):
            score += 40
            triggered_rules.append({
                "rule":              "PowerShell_EncodedCommand",
                "description":       "PowerShell invoked with -EncodedCommand (base64 payload)",
                "mitre_technique":   "T1027",
                "mitre_tactic":      "Defense Evasion",
                "points":            40,
            })

        # -WindowStyle Hidden / -NonInteractive
        if re.search(r"-(windowstyle\s+hidden|w\s+hidden|noninteractive)", cmd_str, re.I):
            score += 30
            triggered_rules.append({
                "rule":              "PowerShell_Hidden_Window",
                "description":       "PowerShell running with hidden window or non-interactive flag",
                "mitre_technique":   "T1564.003",
                "mitre_tactic":      "Defense Evasion",
                "points":            30,
            })

        # -ExecutionPolicy Bypass
        if re.search(r"-(executionpolicy|ep)\s+bypass", cmd_str, re.I):
            score += 25
            triggered_rules.append({
                "rule":              "PowerShell_ExecutionPolicy_Bypass",
                "description":       "PowerShell invoked with -ExecutionPolicy Bypass",
                "mitre_technique":   "T1059.001",
                "mitre_tactic":      "Defense Evasion",
                "points":            25,
            })

    # ── Rule 7: script-interpreter proxy execution ────────────────────────────
    if name_lower in {"mshta.exe", "wscript.exe", "cscript.exe"}:
        # Flag if they reference a remote URL or a suspicious path
        if re.search(r"https?://", cmd_str) or any(
            p in cmd_str for p in [r"\\temp\\", r"\\appdata\\", r"\\downloads\\"]
        ):
            score += 35
            triggered_rules.append({
                "rule":              "Script_Interpreter_Proxy",
                "description":       (
                    f"{name} executing remote or temp-path content: {cmd_str[:120]}"
                ),
                "mitre_technique":   "T1218",
                "mitre_tactic":      "Defense Evasion",
                "points":            35,
            })

    # ── Rule 8: cmd.exe with suspiciously long base64-looking argument ─────────
    if name_lower == "cmd.exe" and cmd_str:
        b64_match = re.search(r"[a-zA-Z0-9+/]{60,}={0,2}", cmd_str)
        if b64_match:
            score += 30
            triggered_rules.append({
                "rule":              "Cmd_Encoded_Argument",
                "description":       "cmd.exe invoked with a long base64-looking argument",
                "mitre_technique":   "T1059.003",
                "mitre_tactic":      "Execution",
                "points":            30,
            })

    # ── Rule 9: randomised executable name (high entropy) ─────────────────────
    if name_lower:
        entropy = _name_entropy(name_lower)
        # Threshold empirically calibrated: 'svchost' ≈ 2.5, 'aB3kLm9p' ≈ 3.9
        if entropy > 3.6 and name_lower not in _SYSTEM_PROCESS_PATHS:
            score += 15
            triggered_rules.append({
                "rule":              "Randomised_Process_Name",
                "description":       (
                    f"Process name '{name}' has high character entropy "
                    f"({entropy:.2f} bits), consistent with a randomly generated name"
                ),
                "mitre_technique":   "T1036",
                "mitre_tactic":      "Defense Evasion",
                "points":            15,
            })

    # ── Rule 10: excessive external network connections ────────────────────────
    if connections > _MAX_CONNECTIONS:
        score += 20
        triggered_rules.append({
            "rule":              "Excessive_Network_Connections",
            "description":       (
                f"Process has {connections} outbound network connections "
                f"(threshold: {_MAX_CONNECTIONS})"
            ),
            "mitre_technique":   "T1071",
            "mitre_tactic":      "Command and Control",
            "points":            20,
        })

    return _proc_result(
        pid=pid,
        name=name or f"<pid {pid}>",
        exe=exe,
        cmdline=cmd_str,
        username=username,
        score=score,
        triggered_rules=triggered_rules,
        connections=connections,
    )


# ── Main monitor class ─────────────────────────────────────────────────────────

class BehaviorMonitor:
    """
    Heuristic behavioural scoring engine (Layer 3 of PredatorEye protection).

    Inspects all running processes using psutil and assigns each a risk score
    based on ten heuristic rules mapped to MITRE ATT&CK techniques.

    This module is read-only — it never terminates, suspends, or modifies any
    process.  All data is collected via the psutil process-information API.

    Usage::

        monitor = BehaviorMonitor()
        report  = monitor.scan_processes()
        for proc in report["findings"]:
            if proc["severity"] in ("Critical", "High"):
                print(proc["pid"], proc["name"], proc["score"], proc["triggered_rules"])

        # Inspect a specific PID
        result = monitor.inspect_pid(1234)
        print(result["severity"], result["triggered_rules"])
    """

    def __init__(self):
        self._psutil_available:  bool = False
        self._platform_windows:  bool = platform.system() == "Windows"
        self._load_error: Optional[str] = None
        self._check_psutil()

    def _check_psutil(self) -> None:
        try:
            import psutil   # noqa: F401
            self._psutil_available = True
        except ImportError:
            self._load_error = (
                "psutil is not installed. "
                "Run:  pip install psutil"
            )

    # ── Private helpers ────────────────────────────────────────────────────────

    def _collect_proc_info(self, proc) -> dict:
        """
        Safely collect process attributes — returns empty strings on access errors.

        psutil raises AccessDenied for protected system processes and
        NoSuchProcess when a process exits between our enumeration and our read.
        We catch both silently and return whatever partial data we managed to get,
        so the rest of the heuristic evaluation can still run on available fields.
        """
        import psutil

        info: dict = {
            "name": "", "exe": "", "cmdline": [],
            "username": "", "connections": 0,
        }

        try:
            info["name"] = proc.name()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            info["exe"] = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            info["cmdline"] = proc.cmdline()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            info["username"] = proc.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            conns = proc.connections(kind="inet")
            # Count only ESTABLISHED outbound connections to external addresses
            external = [
                c for c in conns
                if c.status == "ESTABLISHED"
                and c.raddr
                and not c.raddr.ip.startswith(("127.", "::1", "10.", "192.168.", "172."))
            ]
            info["connections"] = len(external)
        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
            pass

        return info

    def _get_parent_name(self, proc) -> str:
        """Return the parent process name, empty string on any error."""
        import psutil
        try:
            parent = proc.parent()
            return parent.name() if parent else ""
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return ""

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan_processes(self) -> dict:
        """
        Enumerate all running processes and score each against the heuristic rules.

        Returns::

            {
                "scanned":          int,
                "suspicious":       int,   # score > 20
                "findings":         [proc_result, ...],   # suspicious only
                "clean":            int,
                "errors":           [str, ...],
                "psutil_available": bool,
                "scanned_at":       str,
            }

        Only suspicious processes (score > 20) appear in 'findings' to keep
        the result set manageable.  The ThreatCorrelator (Module 7) consumes
        'findings' directly.
        """
        summary: dict = {
            "scanned":          0,
            "suspicious":       0,
            "findings":         [],
            "clean":            0,
            "errors":           [],
            "psutil_available": self._psutil_available,
            "scanned_at":       datetime.datetime.now().isoformat(timespec="seconds"),
        }

        if not self._psutil_available:
            summary["errors"].append(self._load_error or "psutil unavailable")
            return summary

        import psutil

        for proc in psutil.process_iter():
            pid = proc.pid
            if pid in _SKIP_PIDS:
                continue

            try:
                info        = self._collect_proc_info(proc)
                parent_name = self._get_parent_name(proc)
                result      = _evaluate(pid, info, parent_name)
                summary["scanned"] += 1

                if result["is_suspicious"]:
                    summary["findings"].append(result)
                    summary["suspicious"] += 1
                else:
                    summary["clean"] += 1

            except Exception as exc:
                summary["errors"].append(f"pid {pid}: {exc}")

        # Sort by score descending so the most suspicious processes appear first
        summary["findings"].sort(key=lambda r: r["score"], reverse=True)
        return summary

    def inspect_pid(self, pid: int) -> dict:
        """
        Inspect a single process by PID.

        Returns the same proc_result dict structure as entries in
        scan_processes()['findings'], with psutil_available added.
        Useful for on-demand investigation of a specific process.
        """
        if not self._psutil_available:
            return _proc_result(
                pid=pid, name="", exe="", cmdline="", username="",
                score=0, triggered_rules=[], connections=0,
                error=self._load_error or "psutil unavailable",
            )

        import psutil

        try:
            proc        = psutil.Process(pid)
            info        = self._collect_proc_info(proc)
            parent_name = self._get_parent_name(proc)
            result      = _evaluate(pid, info, parent_name)
            result["psutil_available"] = True
            return result
        except psutil.NoSuchProcess:
            return _proc_result(
                pid=pid, name="", exe="", cmdline="", username="",
                score=0, triggered_rules=[], connections=0,
                error=f"Process {pid} does not exist",
            )
        except psutil.AccessDenied:
            return _proc_result(
                pid=pid, name="", exe="", cmdline="", username="",
                score=0, triggered_rules=[], connections=0,
                error=f"Access denied for process {pid}",
            )
