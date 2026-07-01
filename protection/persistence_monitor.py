"""
protection/persistence_monitor.py
====================================
Registry Run key / Startup folder / Scheduled task delta detection
— Module 6 of PredatorEye's active protection stack.

Academic rationale (for project report)
-----------------------------------------
Persistence is one of the most reliable indicators that a system has been
compromised: legitimate software almost never needs to survive a reboot,
but malware almost always does.  MITRE ATT&CK lists more than 20 techniques
under the Persistence tactic (TA0003); this module covers the three most
common mechanisms on Windows:

  ┌───────────────────────────────────────────────────────────┬──────────────┐
  │ Mechanism                                                 │ MITRE        │
  ├───────────────────────────────────────────────────────────┼──────────────┤
  │ Registry Run / RunOnce keys                               │ T1547.001    │
  │ Startup folder (user + common)                            │ T1547.001    │
  │ Windows Scheduled Tasks                                   │ T1053.005    │
  └───────────────────────────────────────────────────────────┴──────────────┘

Delta-based detection
----------------------
Point-in-time scans of persistence locations produce enormous noise because
a healthy Windows installation has hundreds of Run entries and scheduled tasks
installed by legitimate software.  Flagging all of them as threats would be
unusable.

Delta detection solves this: take a baseline snapshot when the system is
known-clean, then on each subsequent run compare the current state against
the baseline.  Only *new or changed* entries are reported.  This is the
approach used by system integrity monitors (Tripwire, AIDE) and endpoint
security tools (Sysmon Event ID 13 for registry changes).

Workflow::

    monitor = PersistenceMonitor()

    # First run (no baseline exists yet):
    result = monitor.scan()
    #  → result["is_baseline_run"] == True
    #  → baseline saved to disk, no changes reported

    # Subsequent run (after malware installs a Run key):
    result = monitor.scan()
    #  → result["is_baseline_run"] == False
    #  → result["changes"]["registry"]["added"] contains the new key
    #  → result["findings"] contains Finding-compatible dicts

Persistence locations monitored
---------------------------------
Registry Run keys:
  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce
  HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run

Startup folders:
  %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup
  %ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

Scheduled tasks:
  All non-Microsoft tasks (\\Microsoft\\* excluded) via `schtasks /query`

Platform
---------
Registry and schtasks reading require Windows.  On other platforms the
module initialises successfully but all three readers return empty results
with informative messages — the rest of the protection stack is unaffected.
"""

import os
import csv
import json
import datetime
import platform
import subprocess
import threading
from io import StringIO
from typing import Optional, List

# winreg is Windows-only; import guarded at call site
_IS_WINDOWS: bool = platform.system() == "Windows"


# ── Paths and constants ────────────────────────────────────────────────────────

_DEFAULT_BASELINE_PATH: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "persistence_baseline.json",
)

# Registry Run key locations: (display_name, hive_constant_name, subkey)
# hive_constant_name stored as string so the module can be imported on
# non-Windows without touching winreg at module level.
_REGISTRY_KEYS: list = [
    ("HKCU\\...\\Run",
     "HKEY_CURRENT_USER",
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU\\...\\RunOnce",
     "HKEY_CURRENT_USER",
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM\\...\\Run",
     "HKEY_LOCAL_MACHINE",
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM\\...\\RunOnce",
     "HKEY_LOCAL_MACHINE",
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM\\...\\Run (WOW64)",
     "HKEY_LOCAL_MACHINE",
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

# File extensions in startup folders that are executable / meaningful
_STARTUP_EXTS: set = {
    ".exe", ".bat", ".cmd", ".lnk", ".vbs", ".js",
    ".hta", ".ps1", ".pif", ".com", ".scr",
}

# schtasks subprocess timeout (seconds)
_TASKS_TIMEOUT: int = 30

# Paths that make a persistence entry suspicious regardless of source
_SUSPICIOUS_PATH_FRAGMENTS: list = [
    r"\temp\\", r"\tmp\\", r"\appdata\roaming\\",
    r"\appdata\local\temp\\", r"\downloads\\", r"\desktop\\",
    r"\public\\", "/tmp/", "/var/tmp/",
]


# ── Severity helper ────────────────────────────────────────────────────────────

def _entry_severity(value: str) -> str:
    """
    Assign severity to a persistence entry based on its target path.

    New entries pointing to user-writable locations (Temp, AppData, Downloads)
    are rated High because legitimate software almost never installs there.
    All other new entries are Medium — they warrant investigation but are more
    likely to be legitimate software installers.
    """
    val_lower = (value or "").lower()
    for frag in _SUSPICIOUS_PATH_FRAGMENTS:
        if frag in val_lower:
            return "High"
    return "Medium"


# ── Registry reader ────────────────────────────────────────────────────────────

def _read_registry_run_keys() -> dict:
    """
    Return {display_name: {value_name: value_data}} for all Run/RunOnce keys.

    Uses winreg (Windows built-in).  Returns empty dicts for each key on
    access-denied or key-not-found errors so the caller always gets a
    consistent structure regardless of OS or permission level.
    """
    if not _IS_WINDOWS:
        return {display: {} for display, _, _ in _REGISTRY_KEYS}

    import winreg

    _HIVE_MAP: dict = {
        "HKEY_CURRENT_USER":  winreg.HKEY_CURRENT_USER,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    }

    result: dict = {}
    for display, hive_name, subkey in _REGISTRY_KEYS:
        hive = _HIVE_MAP.get(hive_name)
        if hive is None:
            result[display] = {}
            continue
        try:
            with winreg.OpenKey(hive, subkey,
                                access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                values: dict = {}
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        values[name] = str(data)
                        i += 1
                    except OSError:
                        break
                result[display] = values
        except OSError:
            result[display] = {}

    return result


# ── Startup folder reader ──────────────────────────────────────────────────────

def _read_startup_files() -> dict:
    """
    Return {folder_label: {filename: full_path}} for each startup folder.

    Scans only files with executable extensions to exclude thumbs.db / desktop.ini.
    """
    folders: dict = {}

    if _IS_WINDOWS:
        user_startup   = os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        common_startup = os.path.expandvars(
            r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        folders = {
            "User Startup":   user_startup,
            "Common Startup": common_startup,
        }
    else:
        home = os.path.expanduser("~")
        autostart = os.path.join(home, ".config", "autostart")
        folders = {"XDG Autostart": autostart}

    result: dict = {}
    for label, folder_path in folders.items():
        result[label] = {}
        if not os.path.isdir(folder_path):
            continue
        try:
            for fname in os.listdir(folder_path):
                ext = os.path.splitext(fname)[1].lower()
                if ext in _STARTUP_EXTS or not ext:
                    full = os.path.join(folder_path, fname)
                    if os.path.isfile(full):
                        result[label][fname] = full
        except OSError:
            pass

    return result


# ── Scheduled task reader ──────────────────────────────────────────────────────

def _read_scheduled_tasks() -> tuple:
    """
    Return (task_dict, errors) where task_dict is {taskname: info_dict}.

    Uses `schtasks /query /fo CSV /v` and parses the CSV output.
    Excludes tasks under \\Microsoft\\* to filter OS-managed tasks from the
    baseline — we only care about third-party / user-created tasks.

    Returns an empty dict on non-Windows platforms or if schtasks fails.
    """
    if not _IS_WINDOWS:
        return {}, []

    errors: list = []
    tasks:  dict = {}

    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=_TASKS_TIMEOUT,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0:
            errors.append(f"schtasks exited {proc.returncode}: {proc.stderr.strip()[:200]}")
            return tasks, errors

        raw = proc.stdout
    except FileNotFoundError:
        errors.append("schtasks.exe not found")
        return tasks, errors
    except subprocess.TimeoutExpired:
        errors.append(f"schtasks timed out after {_TASKS_TIMEOUT}s")
        return tasks, errors
    except Exception as exc:
        errors.append(f"schtasks failed: {exc}")
        return tasks, errors

    # Parse CSV — schtasks produces one header row then data rows.
    # Multiple "blocks" separated by blank lines may appear (one per task on
    # some Windows versions).  csv.DictReader handles the header automatically.
    try:
        reader = csv.DictReader(StringIO(raw))
        for row in reader:
            taskname = row.get("TaskName", "").strip().strip('"')
            if not taskname:
                continue
            # Exclude built-in Microsoft tasks to reduce baseline noise
            if taskname.lower().startswith("\\microsoft\\"):
                continue
            task_to_run = row.get("Task To Run", "").strip().strip('"')
            run_as_user = row.get("Run As User", "").strip().strip('"')
            state       = row.get("Scheduled Task State", "").strip().strip('"')
            status      = row.get("Status", "").strip().strip('"')

            tasks[taskname] = {
                "task_to_run": task_to_run,
                "run_as_user": run_as_user,
                "state":       state,
                "status":      status,
            }
    except Exception as exc:
        errors.append(f"CSV parse error: {exc}")

    return tasks, errors


# ── Snapshot ───────────────────────────────────────────────────────────────────

def _take_snapshot() -> dict:
    """
    Collect the current state of all three persistence locations.

    Returns a snapshot dict that can be serialised to JSON and later compared
    against a new snapshot to produce a delta.
    """
    task_data, task_errors = _read_scheduled_tasks()

    return {
        "taken_at":       datetime.datetime.now().isoformat(timespec="seconds"),
        "registry_run":   _read_registry_run_keys(),
        "startup_files":  _read_startup_files(),
        "scheduled_tasks": task_data,
        "_task_errors":   task_errors,   # stored for diagnostics, not compared
    }


def _load_baseline(path: str) -> Optional[dict]:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def _save_baseline(snapshot: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


# ── Delta computation ──────────────────────────────────────────────────────────

def _delta_registry(old: dict, new: dict) -> dict:
    """
    Compare old and new registry snapshots.

    Returns {added, removed, modified} lists.
    Each item is {location, name, value, [old_value], severity, mitre_technique}.
    """
    added:    list = []
    removed:  list = []
    modified: list = []

    all_keys = set(old) | set(new)
    for key in all_keys:
        old_vals = old.get(key, {})
        new_vals = new.get(key, {})

        for name, value in new_vals.items():
            if name not in old_vals:
                added.append({
                    "location":        key,
                    "name":            name,
                    "value":           value,
                    "severity":        _entry_severity(value),
                    "mitre_technique": "T1547.001",
                    "mitre_tactic":    "Persistence",
                })
            elif old_vals[name] != value:
                modified.append({
                    "location":        key,
                    "name":            name,
                    "old_value":       old_vals[name],
                    "new_value":       value,
                    "severity":        _entry_severity(value),
                    "mitre_technique": "T1547.001",
                    "mitre_tactic":    "Persistence",
                })

        for name, value in old_vals.items():
            if name not in new_vals:
                removed.append({
                    "location":        key,
                    "name":            name,
                    "value":           value,
                    "severity":        "Info",
                    "mitre_technique": "T1547.001",
                    "mitre_tactic":    "Persistence",
                })

    return {"added": added, "removed": removed, "modified": modified}


def _delta_startup(old: dict, new: dict) -> dict:
    """Compare old and new startup folder snapshots."""
    added:   list = []
    removed: list = []

    all_labels = set(old) | set(new)
    for label in all_labels:
        old_files = old.get(label, {})
        new_files = new.get(label, {})

        for fname, fpath in new_files.items():
            if fname not in old_files:
                added.append({
                    "location":        label,
                    "filename":        fname,
                    "path":            fpath,
                    "severity":        _entry_severity(fpath),
                    "mitre_technique": "T1547.001",
                    "mitre_tactic":    "Persistence",
                })

        for fname, fpath in old_files.items():
            if fname not in new_files:
                removed.append({
                    "location": label,
                    "filename": fname,
                    "path":     fpath,
                    "severity": "Info",
                    "mitre_technique": "T1547.001",
                    "mitre_tactic":    "Persistence",
                })

    return {"added": added, "removed": removed}


def _delta_tasks(old: dict, new: dict) -> dict:
    """Compare old and new scheduled task snapshots."""
    added:   list = []
    removed: list = []

    for taskname, info in new.items():
        if taskname not in old:
            task_to_run = info.get("task_to_run", "")
            added.append({
                "taskname":        taskname,
                "task_to_run":     task_to_run,
                "run_as_user":     info.get("run_as_user", ""),
                "state":           info.get("state", ""),
                "severity":        _entry_severity(task_to_run),
                "mitre_technique": "T1053.005",
                "mitre_tactic":    "Persistence",
            })

    for taskname, info in old.items():
        if taskname not in new:
            removed.append({
                "taskname":        taskname,
                "task_to_run":     info.get("task_to_run", ""),
                "run_as_user":     info.get("run_as_user", ""),
                "severity":        "Info",
                "mitre_technique": "T1053.005",
                "mitre_tactic":    "Persistence",
            })

    return {"added": added, "removed": removed}


def _build_findings(changes: dict) -> list:
    """
    Convert delta changes into Finding-compatible dicts.

    Only 'added' and 'modified' entries generate findings — removals are
    informational and do not represent an active threat.

    Finding severity mapping:
      High  → new entry points to a writable/suspicious path
      Medium → new entry at a normal path (still warrants review)
    """
    findings: list = []

    # Registry additions
    for item in changes["registry"]["added"]:
        findings.append({
            "fid":         f"PRS-REG-{len(findings)+1:03d}",
            "title":       f"New Run Key: {item['name']}",
            "description": (
                f"A new autorun registry entry was added at "
                f"'{item['location']}'.\n"
                f"Name:  {item['name']}\n"
                f"Value: {item['value']}"
            ),
            "category":    "Persistence",
            "severity":    item["severity"],
            "details": {
                "location":        item["location"],
                "name":            item["name"],
                "value":           item["value"],
                "mitre_technique": item["mitre_technique"],
            },
        })

    # Registry modifications
    for item in changes["registry"]["modified"]:
        findings.append({
            "fid":         f"PRS-REG-{len(findings)+1:03d}",
            "title":       f"Modified Run Key: {item['name']}",
            "description": (
                f"An existing autorun entry was changed at '{item['location']}'.\n"
                f"Name:      {item['name']}\n"
                f"Old value: {item['old_value']}\n"
                f"New value: {item['new_value']}"
            ),
            "category":    "Persistence",
            "severity":    item["severity"],
            "details": {
                "location":        item["location"],
                "name":            item["name"],
                "old_value":       item["old_value"],
                "new_value":       item["new_value"],
                "mitre_technique": item["mitre_technique"],
            },
        })

    # Startup additions
    for item in changes["startup"]["added"]:
        findings.append({
            "fid":         f"PRS-STA-{len(findings)+1:03d}",
            "title":       f"New Startup File: {item['filename']}",
            "description": (
                f"A new file appeared in the {item['location']} folder.\n"
                f"File: {item['path']}"
            ),
            "category":    "Persistence",
            "severity":    item["severity"],
            "details": {
                "location":        item["location"],
                "filename":        item["filename"],
                "path":            item["path"],
                "mitre_technique": item["mitre_technique"],
            },
        })

    # Scheduled task additions
    for item in changes["tasks"]["added"]:
        findings.append({
            "fid":         f"PRS-TSK-{len(findings)+1:03d}",
            "title":       f"New Scheduled Task: {item['taskname']}",
            "description": (
                f"A new scheduled task was created.\n"
                f"Task:        {item['taskname']}\n"
                f"Runs:        {item['task_to_run']}\n"
                f"Run as user: {item['run_as_user']}"
            ),
            "category":    "Persistence",
            "severity":    item["severity"],
            "details": {
                "taskname":        item["taskname"],
                "task_to_run":     item["task_to_run"],
                "run_as_user":     item["run_as_user"],
                "mitre_technique": item["mitre_technique"],
            },
        })

    return findings


# ── Main monitor class ─────────────────────────────────────────────────────────

class PersistenceMonitor:
    """
    Registry Run key / Startup folder / Scheduled task delta detector.

    On the first call to scan(), a baseline snapshot is saved and
    is_baseline_run=True is returned — no changes are reported because there
    is nothing to compare against.  Every subsequent scan() compares current
    state to the baseline and returns only what changed.

    Call reset_baseline() to force a new baseline (e.g., after confirming
    that all current entries are legitimate).

    Usage::

        monitor = PersistenceMonitor()

        result = monitor.scan()
        if result["is_baseline_run"]:
            print("Baseline captured — re-run to detect changes.")
        else:
            for f in result["findings"]:
                print(f["severity"], f["title"])
    """

    def __init__(self, baseline_path: str = _DEFAULT_BASELINE_PATH):
        self.baseline_path: str = baseline_path
        self._lock = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> dict:
        """
        Compare current persistence state against the saved baseline.

        Returns::

            {
                "snapshot_taken_at":  str,
                "baseline_taken_at":  str | None,
                "is_baseline_run":    bool,
                "changes": {
                    "registry": {"added": [...], "removed": [...], "modified": [...]},
                    "startup":  {"added": [...], "removed": [...]},
                    "tasks":    {"added": [...], "removed": [...]},
                },
                "total_changes": int,   # added + modified (removals excluded)
                "findings":      [finding_dict, ...],
                "errors":        [str, ...],
            }

        On a baseline run, 'changes' contains empty lists and 'findings' is [].
        """
        with self._lock:
            snapshot = _take_snapshot()
            baseline = _load_baseline(self.baseline_path)
            errors   = list(snapshot.pop("_task_errors", []))

            if baseline is None:
                _save_baseline(snapshot, self.baseline_path)
                return {
                    "snapshot_taken_at": snapshot["taken_at"],
                    "baseline_taken_at": None,
                    "is_baseline_run":   True,
                    "changes": {
                        "registry": {"added": [], "removed": [], "modified": []},
                        "startup":  {"added": [], "removed": []},
                        "tasks":    {"added": [], "removed": []},
                    },
                    "total_changes": 0,
                    "findings":      [],
                    "errors":        errors,
                }

            # Compute deltas
            changes: dict = {
                "registry": _delta_registry(
                    baseline.get("registry_run",    {}),
                    snapshot.get("registry_run",    {}),
                ),
                "startup": _delta_startup(
                    baseline.get("startup_files",   {}),
                    snapshot.get("startup_files",   {}),
                ),
                "tasks": _delta_tasks(
                    baseline.get("scheduled_tasks", {}),
                    snapshot.get("scheduled_tasks", {}),
                ),
            }

            total_changes = (
                len(changes["registry"]["added"])
                + len(changes["registry"]["modified"])
                + len(changes["startup"]["added"])
                + len(changes["tasks"]["added"])
            )

            findings = _build_findings(changes)

            return {
                "snapshot_taken_at": snapshot["taken_at"],
                "baseline_taken_at": baseline.get("taken_at"),
                "is_baseline_run":   False,
                "changes":           changes,
                "total_changes":     total_changes,
                "findings":          findings,
                "errors":            errors,
            }

    def reset_baseline(self) -> dict:
        """
        Take a new baseline snapshot, overwriting the existing one.

        Use this after verifying that all current persistence entries are
        legitimate — the next scan() will then only flag genuinely new entries.

        Returns::

            {"success": bool, "taken_at": str, "error": str | None}
        """
        with self._lock:
            try:
                snapshot = _take_snapshot()
                snapshot.pop("_task_errors", None)
                _save_baseline(snapshot, self.baseline_path)
                return {
                    "success":  True,
                    "taken_at": snapshot["taken_at"],
                    "error":    None,
                }
            except OSError as exc:
                return {
                    "success":  False,
                    "taken_at": "",
                    "error":    str(exc),
                }

    def current_snapshot(self) -> dict:
        """
        Return a live snapshot of all persistence locations without comparing
        to any baseline.  Useful for an initial audit or UI display.

        Returns the full snapshot dict including all current Run keys,
        startup files, and scheduled tasks.
        """
        snapshot = _take_snapshot()
        snapshot.pop("_task_errors", None)
        return snapshot

    @property
    def baseline_exists(self) -> bool:
        """True if a baseline snapshot file exists on disk."""
        return os.path.isfile(self.baseline_path)
