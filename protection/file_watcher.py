"""
protection/file_watcher.py
============================
Real-time filesystem watchdog for drop-folder monitoring — Module 4 of
PredatorEye's active protection stack.

Academic rationale (for project report)
-----------------------------------------
Layers 1–3 run on-demand: the user initiates a scan and the engines examine
files that already exist on disk.  Layer 4 (this module) shifts the model
from *reactive* to *proactive*: it watches specific directories for newly
arriving files and scans them the moment they appear — before the user opens
or executes them.

This is the same architectural principle used by real-time protection in
commercial AV products (Windows Defender's "Real-time protection",
ClamAV's Clamonacc daemon, Sophos On-Access Scanner).  The key components:

  1. OS filesystem notification API  — the OS tells us a file appeared;
     we never poll (polling wastes CPU and adds latency).
  2. Debounce window  — files are written in multiple chunks; we wait for
     writes to settle before scanning the (now-complete) file.
  3. Scan in a daemon thread  — scanning happens off the notification thread
     so we never block the OS event queue.
  4. Detection queue  — thread-safe queue consumed by the Flask app or CLI
     to surface alerts without tight coupling.

Watchdog library
-----------------
`watchdog` wraps the native OS filesystem notification APIs:
  - Windows:  ReadDirectoryChangesW
  - Linux:    inotify
  - macOS:    FSEvents / kqueue

This means near-zero CPU overhead when directories are idle — far better
than a polling loop.

Install:  pip install watchdog

Graceful degradation
---------------------
If watchdog is not installed, FileWatcher initialises successfully but
start() immediately returns without monitoring.  An error is stored in
self.error and the rest of the protection stack continues to work.
"""

import os
import queue
import threading
import datetime
import platform
from typing import Optional, Callable, List


# ── Optional watchdog import with graceful fallback ───────────────────────────
# Using 'object' as the fallback base class lets _ThreatEventHandler be defined
# unconditionally — the Observer is never constructed when watchdog is absent.

try:
    from watchdog.observers import Observer as _Observer
    from watchdog.events import FileSystemEventHandler as _BaseHandler
    _WATCHDOG_AVAILABLE = True
except ImportError:
    _Observer    = None
    _BaseHandler = object
    _WATCHDOG_AVAILABLE = False


# ── Constants ──────────────────────────────────────────────────────────────────

# File extensions that should be scanned when they arrive in a watched folder.
# Restricted to executable/script types to avoid scanning media or documents
# that pose no direct execution risk — reduces CPU load and false positives.
WATCH_EXTENSIONS: set = {
    # Native executables and libraries
    ".exe", ".dll", ".com", ".scr", ".pif",
    # Scripts
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".wsf",
    # Installers and packages
    ".msi", ".msp",
    # Shortcuts (can point to malicious targets)
    ".lnk",
    # Archives frequently used to deliver payloads
    ".zip", ".rar", ".7z", ".gz", ".tar",
    # Java / cross-platform
    ".jar",
    # Office macro-enabled formats
    ".xlsm", ".docm", ".pptm",
}

# How long to wait after the last event on a path before scanning it.
# Most file-copy operations complete within 1 second.  Scanning a partially
# written file produces a wrong hash and may cause the engine to error.
_DEBOUNCE_SECS: float = 1.5

# Maximum entries to keep in the detection queue before discarding old ones.
# Prevents unbounded memory growth during a burst of drops.
_QUEUE_MAXSIZE: int = 500


# ── Severity ordering (for picking "worst" across multiple detections) ─────────

_SEVERITY_RANK: dict = {
    "Critical": 5,
    "High":     4,
    "Medium":   3,
    "Low":      2,
    "Info":     1,
    "Clean":    0,
}


def _worst_severity(severities: list) -> str:
    if not severities:
        return "Info"
    return max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0))


# ── Default watch directories ──────────────────────────────────────────────────

def _default_watch_dirs() -> List[str]:
    """
    Return the default drop-folder list for the current platform.

    These are the locations most commonly used by malware delivery mechanisms:
    browser downloads, email attachments saved to Desktop, temp directories
    used by exploit kits, and the Startup folder (persistence via drop).
    """
    home   = os.path.expanduser("~")
    dirs   = [
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
    ]

    if platform.system() == "Windows":
        dirs += [
            os.path.expandvars(r"%TEMP%"),
            os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
            # Startup folder — persistence drop-zone (T1547.001)
            os.path.expandvars(
                r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
            ),
        ]
    else:
        dirs.append("/tmp")

    # Return only paths that actually exist on this machine
    return [d for d in dirs if d and os.path.isdir(d)]


# ── Detection event constructor ────────────────────────────────────────────────

def _detection_event(
    path: str,
    event_type: str,
    watch_dir: str,
    detections: list,
) -> dict:
    """
    Build a standardised detection event dict for the queue.

    'detections' is a list of per-engine result dicts — one entry from
    SignatureEngine and/or one from YaraEngine, present only when matched=True.
    """
    severities = [d.get("severity", "Info") for d in detections]
    return {
        "path":        path,
        "filename":    os.path.basename(path),
        "event_type":  event_type,
        "watch_dir":   watch_dir,
        "severity":    _worst_severity(severities),
        "detections":  detections,
        "detected_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }


# ── Filesystem event handler ───────────────────────────────────────────────────

class _ThreatEventHandler(_BaseHandler):
    """
    watchdog event handler that scans each new / modified file.

    Registered once per watched directory.  All three event types (created,
    modified, moved-into) call the same _maybe_scan() entry point so we
    catch files regardless of how they were written.

    Debouncing
    ----------
    The OS raises multiple events for a single file write (at minimum:
    IN_CREATE then IN_CLOSE_WRITE on Linux; FileCreate + multiple FileModify
    on Windows).  Without debouncing we would scan an incomplete file on the
    first event, wasting cycles and potentially missing the full content.

    The debounce dict maps path → last_event_time.  Any repeat event within
    _DEBOUNCE_SECS is silently dropped; only the settled file is scanned.
    The dict is pruned periodically to avoid unbounded growth.
    """

    def __init__(
        self,
        scan_fn: Callable[[str], dict],
        extensions: set,
        detection_queue: queue.Queue,
        watch_dir: str,
        debounce_secs: float = _DEBOUNCE_SECS,
    ):
        if _BaseHandler is not object:
            super().__init__()
        self._scan_fn        = scan_fn
        self._extensions     = extensions
        self._queue          = detection_queue
        self._watch_dir      = watch_dir
        self._debounce_secs  = debounce_secs
        self._seen: dict     = {}    # path → last event timestamp
        self._lock           = threading.Lock()

    # ── watchdog callbacks ────────────────────────────────────────────────────

    def on_created(self, event):
        if not event.is_directory:
            self._maybe_scan(event.src_path, "file_created")

    def on_modified(self, event):
        if not event.is_directory:
            self._maybe_scan(event.src_path, "file_modified")

    def on_moved(self, event):
        # A file moved *into* a watched dir (e.g., browser completes a download
        # by renaming foo.crdownload → foo.exe).
        if not event.is_directory:
            self._maybe_scan(event.dest_path, "file_moved")

    # ── Debounce + dispatch ───────────────────────────────────────────────────

    def _maybe_scan(self, path: str, event_type: str) -> None:
        """
        Filter by extension, debounce, then dispatch a background scan thread.
        """
        if not path:
            return

        # Extension filter
        ext = os.path.splitext(path)[1].lower()
        if self._extensions and ext not in self._extensions:
            return

        # Debounce: skip if the same path was seen within the window
        now = datetime.datetime.now().timestamp()
        with self._lock:
            last = self._seen.get(path, 0.0)
            if now - last < self._debounce_secs:
                return
            self._seen[path] = now
            # Prune entries older than 60 s to keep the dict small
            if len(self._seen) > 1000:
                cutoff = now - 60.0
                self._seen = {p: t for p, t in self._seen.items() if t > cutoff}

        # Dispatch scan on a daemon thread so we never block the observer
        t = threading.Thread(
            target=self._scan_and_enqueue,
            args=(path, event_type),
            daemon=True,
        )
        t.start()

    def _scan_and_enqueue(self, path: str, event_type: str) -> None:
        """
        Wait briefly for the file to finish writing, then scan it.

        The extra sleep absorbs the tail of a multi-chunk write that slipped
        through the debounce window.  Commercial on-access scanners use a
        similar "hold-open" strategy.
        """
        import time
        time.sleep(0.3)

        if not os.path.isfile(path):
            return

        try:
            result = self._scan_fn(path)
        except Exception:
            return

        if not result:
            return

        # Collect the per-engine detections that actually matched
        detections = []

        # SignatureEngine result shape: {matched, threat_name, severity, ...}
        if result.get("matched"):
            detections.append({
                "source":      result.get("source", "signature"),
                "threat_name": result.get("threat_name", "Unknown"),
                "severity":    result.get("severity", "High"),
                "hash_sha256": result.get("hash_sha256", ""),
                "details":     result,
            })

        # YaraEngine result shape: {matched, matches: [{rule_name, severity}]}
        for m in result.get("matches", []):
            detections.append({
                "source":      "yara",
                "threat_name": m.get("rule_name", "Unknown Rule"),
                "severity":    m.get("severity", "High"),
                "mitre":       m.get("meta", {}).get("mitre_technique", ""),
                "details":     m,
            })

        if not detections:
            return

        event = _detection_event(path, event_type, self._watch_dir, detections)

        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Drop the oldest event to make room (FIFO replacement)
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(event)
            except queue.Empty:
                pass


# ── Main FileWatcher class ─────────────────────────────────────────────────────

class FileWatcher:
    """
    Real-time drop-folder monitor (Module 4 of PredatorEye protection).

    Watches a set of directories using OS-native filesystem notifications.
    When a file matching the configured extensions is created or modified,
    it is automatically scanned by the provided scan function and — if a
    threat is detected — placed in the detection queue.

    The scan function is injected by the caller so that FileWatcher remains
    decoupled from SignatureEngine and YaraEngine.  The recommended pattern::

        sig_engine  = SignatureEngine()
        yara_engine = YaraEngine()

        def combined_scan(path):
            # Try signature first (fast), then YARA (pattern)
            sig_result = sig_engine.scan_file(path)
            if sig_result["matched"]:
                sig_result["source"] = "signature"
                return sig_result
            yara_result = yara_engine.scan_file(path)
            return yara_result

        watcher = FileWatcher(scan_fn=combined_scan)
        watcher.start()

        # Later, drain detections (e.g., from a Flask route):
        events = watcher.get_detections()

    Thread safety
    -------------
    start() and stop() are not re-entrant.  Call start() once and stop() once.
    get_detections() and detection_count are safe to call from any thread.
    """

    def __init__(
        self,
        watch_dirs: Optional[List[str]] = None,
        scan_fn:    Optional[Callable[[str], dict]] = None,
        extensions: Optional[set] = None,
        on_detection: Optional[Callable[[dict], None]] = None,
    ):
        """
        Args:
            watch_dirs:   Directories to monitor.  Defaults to Downloads,
                          Desktop, and Temp.
            scan_fn:      Function that takes a file path and returns a result
                          dict.  Should return a dict that has at least a
                          'matched' key or a 'matches' list (compatible with
                          SignatureEngine.scan_file and YaraEngine.scan_file).
                          If None, every arriving file is recorded as an event
                          with severity "Info" (useful for audit-only mode).
            extensions:   Set of lowercase extensions to monitor.  Defaults to
                          WATCH_EXTENSIONS.
            on_detection: Optional callback invoked in the scan thread when a
                          threat is detected.  Receives the detection event dict.
                          Use get_detections() instead if polling from a UI.
        """
        self.watch_dirs:     List[str]   = watch_dirs or _default_watch_dirs()
        self._scan_fn:       Callable    = scan_fn or self._audit_only_scan
        self.extensions:     set         = extensions or WATCH_EXTENSIONS
        self._on_detection:  Optional[Callable] = on_detection

        self._queue:    queue.Queue  = queue.Queue(maxsize=_QUEUE_MAXSIZE)
        self._observer               = None
        self._running:   bool        = False
        self.error:      Optional[str] = None

        if not _WATCHDOG_AVAILABLE:
            self.error = (
                "watchdog is not installed. "
                "Run:  pip install watchdog"
            )

    # ── Scan function used when no scan_fn is provided ────────────────────────

    @staticmethod
    def _audit_only_scan(path: str) -> dict:
        """
        Audit-only mode: flag every arriving file as Info so FileWatcher can
        be used purely as a filesystem audit trail without a detection engine.
        """
        return {
            "matched":     True,
            "source":      "audit",
            "threat_name": "New File Arrived",
            "severity":    "Info",
            "hash_sha256": "",
        }

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Start the background watchdog observer.

        Non-existent directories are skipped with a warning in self.error
        rather than raising.  If watchdog is not installed, returns immediately.
        """
        if not _WATCHDOG_AVAILABLE:
            return

        if self._running:
            return

        self._observer = _Observer()
        scheduled_count = 0
        warnings = []

        for watch_dir in self.watch_dirs:
            if not os.path.isdir(watch_dir):
                warnings.append(f"Skipped (not found): {watch_dir}")
                continue

            handler = _ThreatEventHandler(
                scan_fn         = self._wrapped_scan,
                extensions      = self.extensions,
                detection_queue = self._queue,
                watch_dir       = watch_dir,
            )
            self._observer.schedule(handler, path=watch_dir, recursive=False)
            scheduled_count += 1

        if warnings:
            self.error = "; ".join(warnings)

        if scheduled_count == 0:
            self.error = (self.error or "") + " — no valid directories to watch"
            return

        self._observer.start()
        self._running = True

    def stop(self) -> None:
        """Stop the observer and wait for its thread to exit cleanly."""
        if self._observer and self._running:
            self._observer.stop()
            self._observer.join(timeout=5)
        self._running  = False
        self._observer = None

    # ── Detection queue API ───────────────────────────────────────────────────

    def get_detections(self) -> List[dict]:
        """
        Drain and return all pending detection events as a list.

        Safe to call from any thread (including the Flask request thread).
        Returns an empty list if no detections are queued.
        """
        events = []
        while True:
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return events

    @property
    def detection_count(self) -> int:
        """Number of queued (unconsumed) detections."""
        return self._queue.qsize()

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Internal ──────────────────────────────────────────────────────────────

    def _wrapped_scan(self, path: str) -> dict:
        """
        Calls self._scan_fn and additionally fires the on_detection callback
        when a threat is found.  Exceptions in the user-supplied scan function
        are suppressed so one bad file never stops the watcher.
        """
        try:
            result = self._scan_fn(path)
        except Exception as exc:
            return {"matched": False, "error": str(exc)}

        if self._on_detection and (
            result.get("matched") or result.get("matches")
        ):
            try:
                self._on_detection(result)
            except Exception:
                pass

        return result
