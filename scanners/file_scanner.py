"""
PredatorEye — File Threat Scanner
Static multi-layer analysis: files are NEVER executed.
Each file is analyzed in an isolated daemon thread with a hard timeout.
Six independent detection layers feed a weighted confidence score.
False-positive reduction: requires multiple indicators before flagging.
"""

import os
import math
import struct
import hashlib
import re
import subprocess
import threading
import time
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

# ── Detection constants ────────────────────────────────────────────────────────

# Dangerous Windows API imports that indicate hostile behaviour when clustered
_DANGEROUS_IMPORTS = {
    # Remote process injection
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    # Credential / secret access
    "LsaEnumerateLogonSessions", "SamQueryInformationUser",
    "CryptUnprotectData", "CredEnumerate", "LsaOpenPolicy",
    # Anti-analysis / sandbox evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetTickCount", "SleepEx",
    # Network (unusual for normal desktop apps)
    "URLDownloadToFile", "InternetOpenUrl", "WinHttpOpen",
    "WSASocket", "WSAStartup",
    # Keylogging / screen capture
    "SetWindowsHookEx", "GetAsyncKeyState", "GetClipboardData",
    "BitBlt", "GetDC", "CreateCompatibleBitmap",
    # Raw memory execution (shellcode loaders)
    "VirtualAlloc", "VirtualProtect", "HeapCreate",
    # Persistence
    "RegSetValueEx", "CreateService", "SHFileOperation",
}

# Regex patterns matched against extracted ASCII strings
_STRING_PATTERNS: List[tuple] = [
    (r'(?i)powershell[^\n]{0,50}-[eE][nN][cC]',              "Encoded PowerShell"),
    (r'(?i)\biex\b|\binvoke-expression\b',                    "PowerShell IEX"),
    (r'(?i)-[eE]xecution[pP]olicy\s+[bB]ypass',              "PS execution policy bypass"),
    (r'(?i)net\s+user\s+\w+\s+\w+\s*/add',                   "Hidden user creation"),
    (r'(?i)(mimikatz|sekurlsa|lsadump|wdigest)',              "Credential-dumping keyword"),
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',        "IP-based C2 URL"),
    (r'(?i)cmd\.exe[^\n]{0,20}/[cCkK]\s',                    "CMD shell execution"),
    (r'(?i)\b(regsvr32|rundll32|mshta|wscript|cscript)\b',   "LOLBin proxy execution"),
    (r'(?i)\b(whoami|ipconfig|net\s+share|tasklist)\s',       "Recon commands"),
    (r'(?i)(FromBase64String|base64\.b64decode|atob\s*\()',   "Base64 decode runtime"),
    (r'(?i)schtasks[^\n]{0,50}/create',                       "Scheduled task creation"),
    (r'(?i)netsh\s+(firewall|advfirewall)',                    "Firewall tampering"),
    (r'(?i)\bsc\s+(create|config|start)\s',                   "Service manipulation"),
]

HIGH_ENTROPY_THRESHOLD = 7.2   # PE sections above this are likely packed/encrypted
MAX_FILE_SIZE         = 50 * 1024 * 1024   # 50 MB read cap
MAX_SCAN_DEPTH        = 3                  # recursive folder depth
FILE_TIMEOUT_SEC      = 12                 # per-file analysis timeout
MAX_WORKERS           = 4                  # parallel analysis threads

EXECUTABLE_EXTENSIONS = {
    '.exe', '.dll', '.scr', '.sys', '.com', '.ocx',
    '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
    '.msi', '.msp', '.hta', '.pif',
}

# Paths that are implicitly trusted (signed system binaries)
_TRUSTED_PREFIXES = [
    os.environ.get("WINDIR", "C:\\Windows"),
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
    "C:\\Program Files\\Windows Defender",
    "C:\\Program Files\\Microsoft",
    "C:\\Program Files (x86)\\Microsoft",
]

# Default locations to scan (suspicious drop zones)
SCAN_LOCATIONS: Dict[str, str] = {
    "Downloads":   os.path.expanduser("~/Downloads"),
    "Desktop":     os.path.expanduser("~/Desktop"),
    "Temp":        os.environ.get("TEMP", ""),
    "AppData":     os.environ.get("APPDATA", ""),
    "Startup":     os.path.join(
                       os.environ.get("APPDATA", ""),
                       "Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
    "ProgramData": os.environ.get("PROGRAMDATA", "C:\\ProgramData"),
}

# Small curated hash set — extend with MalwareBazaar / CIRCL feeds in production
KNOWN_BAD_SHA256: Dict[str, str] = {}


# ── Result object ──────────────────────────────────────────────────────────────

@dataclass
class ThreatResult:
    path:        str
    filename:    str
    size:        int
    sha256:      str
    risk_level:  str        # clean | suspicious | likely_malicious | malicious
    confidence:  int        # 0–100
    indicators:  List[str] = field(default_factory=list)
    details:     Dict      = field(default_factory=dict)
    scan_time:   float     = 0.0

    def to_dict(self) -> dict:
        return {
            "path":        self.path,
            "filename":    self.filename,
            "size":        self.size,
            "size_kb":     round(self.size / 1024, 1),
            "sha256":      self.sha256[:20] + "...",
            "sha256_full": self.sha256,
            "risk_level":  self.risk_level,
            "confidence":  self.confidence,
            "indicators":  self.indicators,
            "details":     self.details,
            "scan_time":   round(self.scan_time, 2),
        }


# ── Pure analysis helpers (stateless, safe to run in any thread) ──────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * math.log2(f / n) for f in freq if f > 0)


def _is_pe(data: bytes) -> bool:
    """Check MZ magic and PE header without executing anything."""
    if len(data) < 64 or data[:2] != b'MZ':
        return False
    pe_off = struct.unpack_from('<I', data, 60)[0]
    return (pe_off + 4 <= len(data)) and data[pe_off:pe_off + 4] == b'PE\x00\x00'


def _pe_imports(data: bytes) -> List[str]:
    """
    Scan for dangerous function names as null-terminated ASCII strings in the
    PE import table region.  The null-terminator requirement means we only
    match real symbol entries, not incidental substrings — key FP reducer.
    """
    found = []
    for name in _DANGEROUS_IMPORTS:
        if (name.encode() + b'\x00') in data:
            found.append(name)
    return found


def _ascii_strings(data: bytes, min_len: int = 6) -> str:
    """Extract printable ASCII runs — used for pattern matching."""
    hits = re.findall(rb'[\x20-\x7E]{' + str(min_len).encode() + rb',}', data)
    return b'\n'.join(hits).decode('ascii', errors='replace')


def _is_signed(path: str) -> bool:
    """Query Authenticode signature via PowerShell — Valid = trusted publisher."""
    try:
        r = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command',
             f"(Get-AuthenticodeSignature -LiteralPath '{path}').Status"],
            capture_output=True, text=True, timeout=8,
            creationflags=0x08000000,   # CREATE_NO_WINDOW
        )
        return r.stdout.strip() == 'Valid'
    except Exception:
        return False


def _trusted(path: str) -> bool:
    p = path.lower()
    return any(t.lower() in p for t in _TRUSTED_PREFIXES if t)


# ── Core per-file analysis ─────────────────────────────────────────────────────

def _analyze(path: str) -> ThreatResult:
    """
    Six-layer static analysis.  Files are opened read-only and never executed.
    Each layer is independent; the final confidence is the weighted sum.
    """
    t0 = time.time()
    filename = os.path.basename(path)
    size = os.path.getsize(path)

    with open(path, 'rb') as fh:
        data = fh.read(MAX_FILE_SIZE)

    sha256     = hashlib.sha256(data).hexdigest()
    indicators = []
    details    = {}
    score      = 0

    # Layer 1 — known-bad hash (definitive)
    if sha256 in KNOWN_BAD_SHA256:
        indicators.append(f"Matched known malware hash: {KNOWN_BAD_SHA256[sha256]}")
        score += 100

    is_pe = _is_pe(data)
    ext   = os.path.splitext(filename)[1].lower()

    # Layer 2 — extension / magic mismatch
    pe_exts = {'.exe', '.dll', '.scr', '.sys', '.com', '.ocx', '.pif'}
    if is_pe and ext not in pe_exts:
        indicators.append(f"PE executable disguised with '{ext or 'no extension'}' extension")
        details['extension_mismatch'] = True
        score += 30

    # Layer 3 — entropy (packing / encryption)
    if len(data) > 2048:
        ent = _entropy(data)
        details['entropy'] = round(ent, 3)
        if ent > HIGH_ENTROPY_THRESHOLD:
            if is_pe:
                indicators.append(
                    f"High entropy ({ent:.2f}/8.0) in PE — likely packed or encrypted")
                score += 22
            elif ext in {'.ps1', '.vbs', '.js', '.bat'}:
                indicators.append(
                    f"High entropy ({ent:.2f}/8.0) in script — possible obfuscation")
                score += 18

    # Layer 4 — dangerous PE imports (require cluster of 3+ to penalise hard)
    if is_pe:
        bad_imports = _pe_imports(data)
        if bad_imports:
            details['dangerous_imports'] = bad_imports[:12]
            if len(bad_imports) >= 4:
                indicators.append(
                    f"Hostile API cluster ({len(bad_imports)}): "
                    + ', '.join(bad_imports[:5]))
                score += min(len(bad_imports) * 6, 35)
            elif len(bad_imports) >= 2:
                score += 8    # noted but not flagged as indicator yet

    # Layer 5 — suspicious string patterns
    strings_blob = _ascii_strings(data)
    matched = []
    for pattern, desc in _STRING_PATTERNS:
        if re.search(pattern, strings_blob):
            matched.append(desc)
    if matched:
        details['suspicious_strings'] = matched
        if len(matched) >= 2:
            indicators.append(
                f"Suspicious strings ({len(matched)}): {', '.join(matched[:3])}")
            score += min(len(matched) * 9, 28)
        elif len(matched) == 1 and ext in EXECUTABLE_EXTENSIONS:
            score += 5

    # Layer 6 — Authenticode signature (reduces score for legitimate software)
    if is_pe and size > 0:
        signed = _is_signed(path)
        details['digitally_signed'] = signed
        if signed:
            score = max(0, score - 25)   # valid signature is strong FP reducer

    # False-positive gate: suppress score if no concrete indicators were raised
    if not indicators:
        score = min(score, 18)

    confidence = min(100, score)

    if confidence >= 80:
        risk = "malicious"
    elif confidence >= 52:
        risk = "likely_malicious"
    elif confidence >= 22:
        risk = "suspicious"
    else:
        risk = "clean"

    return ThreatResult(
        path=path, filename=filename, size=size, sha256=sha256,
        risk_level=risk, confidence=confidence,
        indicators=indicators, details=details,
        scan_time=time.time() - t0,
    )


# ── Main scanner ───────────────────────────────────────────────────────────────

class FileThreatScanner:
    """
    Scans executable files across suspicious system locations for malware
    indicators.  Each file runs in an isolated daemon thread with a hard
    timeout — the main thread is never blocked or endangered.
    """

    def __init__(self, locations: Optional[List[str]] = None):
        self.locations = locations or [
            v for v in SCAN_LOCATIONS.values()
            if v and os.path.isdir(v)
        ]
        self._lock    = threading.Lock()
        self.progress = {"scanned": 0, "total": 0, "current": ""}
        self._running = True

    # ── Public ────────────────────────────────────────────────────────────────

    def scan(self) -> Dict:
        files = self._collect()
        with self._lock:
            self.progress["total"] = len(files)

        if not files:
            return self._summary([])

        results: List[ThreatResult] = []

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(self._isolated, f): f for f in files}
            for fut in futures:
                if not self._running:
                    break
                try:
                    r = fut.result(timeout=FILE_TIMEOUT_SEC + 5)
                    if r:
                        results.append(r)
                except Exception:
                    pass
                with self._lock:
                    self.progress["scanned"] += 1

        return self._summary(results)

    def stop(self):
        self._running = False

    # ── Internal ──────────────────────────────────────────────────────────────

    def _collect(self) -> List[str]:
        """Walk scan locations and return paths of executable files."""
        found = []
        for base in self.locations:
            if not os.path.isdir(base):
                continue
            for depth, (root, dirs, files) in enumerate(os.walk(base)):
                if depth >= MAX_SCAN_DEPTH:
                    dirs.clear()
                    continue
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in EXECUTABLE_EXTENSIONS:
                        continue
                    fpath = os.path.join(root, fname)
                    if _trusted(fpath):
                        continue
                    try:
                        if os.path.getsize(fpath) > MAX_FILE_SIZE:
                            continue
                    except OSError:
                        continue
                    found.append(fpath)
        return found

    def _isolated(self, path: str) -> Optional[ThreatResult]:
        """
        Run _analyze in a contained daemon thread with a timeout.
        If analysis hangs (malformed file), the thread is abandoned and we
        return None — the main scan continues unaffected.
        """
        with self._lock:
            self.progress["current"] = os.path.basename(path)

        result_box: List[Optional[ThreatResult]] = [None]
        error_box:  List[Optional[Exception]]     = [None]

        def worker():
            try:
                result_box[0] = _analyze(path)
            except Exception as exc:
                error_box[0] = exc

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=FILE_TIMEOUT_SEC)

        if t.is_alive() or error_box[0]:
            return None     # timed out or errored — skip silently
        return result_box[0]

    def _summary(self, results: List[ThreatResult]) -> Dict:
        buckets: Dict[str, List] = {
            "malicious": [], "likely_malicious": [], "suspicious": [], "clean": []
        }
        for r in results:
            buckets[r.risk_level].append(r.to_dict())

        threats = buckets["malicious"] + buckets["likely_malicious"]
        return {
            "total_scanned":    len(results),
            "threats_found":    len(threats),
            "malicious":        len(buckets["malicious"]),
            "likely_malicious": len(buckets["likely_malicious"]),
            "suspicious":       len(buckets["suspicious"]),
            "clean":            len(buckets["clean"]),
            "files": {
                "malicious":        buckets["malicious"],
                "likely_malicious": buckets["likely_malicious"],
                "suspicious":       buckets["suspicious"][:30],
            },
        }
