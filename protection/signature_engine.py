"""
protection/signature_engine.py
================================
Hash-based malware detection engine — Layer 1 of PredatorEye's three-layer
protection stack (hash  →  YARA pattern  →  behavioural heuristic).

Academic rationale (for project report)
----------------------------------------
Hash matching is the most *precise* detection method for known malware:
any file whose MD5 or SHA256 matches the database is definitively identified
with zero false positives.  Its fundamental weakness is trivial evasion —
a single bit-flip (benign padding, re-compilation, packing) produces a
completely different hash, defeating the lookup entirely.

This is why three complementary layers are required:
  - Layer 1 (this module): exact hash lookup — high precision, low recall
  - Layer 2 (yara_engine): regex/pattern matching — catches obfuscated variants
  - Layer 3 (behavior_monitor): runtime heuristics — catches novel/unknown threats

This layered architecture mirrors the design of production AV engines such as
ClamAV and Microsoft Defender, both of which use all three approaches.

Signature database format  (protection/signatures.json)
---------------------------------------------------------
{
  "version": "1.0",
  "updated": "YYYY-MM-DD",
  "entries": [
    {
      "sha256":   "<64-char hex>",   # primary match key (collision-resistant)
      "md5":      "<32-char hex>",   # secondary key for legacy feeds
      "name":     "Threat-Name",
      "family":   "FamilyName",
      "severity": "Critical|High|Medium|Low|Info",
      "source":   "feed name / URL"
    }
  ]
}

The operator populates this file from public hash feeds such as:
  - MalwareBazaar  https://bazaar.abuse.ch/export/
  - CIRCL MISP     https://www.misp-project.org/
  - VirusShare     https://virusshare.com/

This module only performs lookup — it never downloads or fetches hashes itself.
"""

import os
import hashlib
import json
import datetime
from typing import Optional


# ── Module constants ──────────────────────────────────────────────────────────

# Read cap prevents memory exhaustion on large archives or disk images.
# Commercial AV engines enforce a similar limit (typically 32–64 MB).
_MAX_READ_BYTES: int = 64 * 1024 * 1024   # 64 MB

# Default DB path: same directory as this file
_DEFAULT_DB: str = os.path.join(os.path.dirname(__file__), "signatures.json")


# ── Result constructor ────────────────────────────────────────────────────────

def _file_result(
    path: str,
    matched: bool,
    threat_name: Optional[str] = None,
    family: Optional[str] = None,
    severity: str = "Info",
    hash_md5: str = "",
    hash_sha256: str = "",
    error: Optional[str] = None,
) -> dict:
    """
    Build a standardised single-file result dict.

    Keeping results as plain dicts (not objects) makes them directly
    JSON-serialisable and consistent with the existing scanners/ contract,
    where every scanner returns a dict of dicts/lists with no custom classes.
    """
    return {
        "path":        path,
        "filename":    os.path.basename(path),
        "matched":     matched,
        "threat_name": threat_name,
        "family":      family,
        "severity":    severity,
        "hash_md5":    hash_md5,
        "hash_sha256": hash_sha256,
        "scanned_at":  datetime.datetime.now().isoformat(timespec="seconds"),
        "error":       error,
    }


# ── Hash computation ──────────────────────────────────────────────────────────

def _compute_hashes(path: str) -> tuple:
    """
    Return (md5_hex, sha256_hex) for a file in a single read pass.

    Why both MD5 and SHA256?
      - SHA256 is the primary key: modern feeds (MalwareBazaar, MISP) publish
        SHA256 exclusively because MD5 is cryptographically broken.
      - MD5 is retained as a fallback for legacy feeds (VirusShare, older MISP
        events) that only publish MD5.  Collision attacks against MD5 are
        irrelevant in a *lookup* context — we compute the hash ourselves from
        an untrusted file and compare it to a trusted database; an attacker
        cannot control our hash computation.

    A single read pass is used to avoid seeking back to the start of large
    files, which would double I/O on spinning disks.
    """
    md5_ctx    = hashlib.md5()
    sha256_ctx = hashlib.sha256()

    with open(path, "rb") as fh:
        data = fh.read(_MAX_READ_BYTES)

    md5_ctx.update(data)
    sha256_ctx.update(data)
    return md5_ctx.hexdigest(), sha256_ctx.hexdigest()


# ── Signature database ────────────────────────────────────────────────────────

class SignatureDB:
    """
    In-memory index of the local hash signature database.

    The JSON file is loaded once at construction and indexed into two O(1)
    lookup dicts — one keyed by SHA256, one by MD5.

    Design choice — JSON flat file vs SQLite
    -----------------------------------------
    A flat JSON file was chosen over SQLite for three reasons:
      1. Zero additional dependencies (SQLite requires the `sqlite3` stdlib
         module which is always present, but the schema management adds
         complexity with no benefit at the scale of a feed database).
      2. Human-inspectable: the examiner can open and verify the database
         contents directly without tooling.
      3. Atomic writes: the operator replaces the file in one operation
         when refreshing from a feed, with no partial-update risk.

    At scale (>1 M entries), a SQLite backend would be more appropriate;
    the architecture supports swapping the storage layer without changing
    any calling code, because SignatureDB is an internal implementation
    detail of SignatureEngine.
    """

    def __init__(self, db_path: str = _DEFAULT_DB):
        self.db_path: str = db_path
        self._by_sha256: dict = {}
        self._by_md5:    dict = {}
        self.version:    str  = "unknown"
        self.updated:    str  = "unknown"
        self._load()

    def _load(self) -> None:
        """Parse the JSON database and build lookup indices."""
        if not os.path.exists(self.db_path):
            # An absent database is not an error: the engine will still run
            # but will match nothing.  This allows the module to be imported
            # in environments where the DB has not yet been populated.
            return

        try:
            with open(self.db_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            # Corrupted DB: log silently and continue with empty indices
            # rather than crashing the entire protection stack.
            self.version = f"load-error: {exc}"
            return

        self.version = raw.get("version", "unknown")
        self.updated = raw.get("updated", "unknown")

        for entry in raw.get("entries", []):
            sha256 = entry.get("sha256", "").lower().strip()
            md5    = entry.get("md5",    "").lower().strip()
            if sha256:
                self._by_sha256[sha256] = entry
            if md5:
                self._by_md5[md5] = entry

    def lookup(self, md5_hex: str, sha256_hex: str) -> Optional[dict]:
        """
        Return the matching database entry or None.

        SHA256 is checked first (preferred key).
        MD5 is a fallback for entries that appear in the MD5-only index.
        """
        sha256_key = sha256_hex.lower()
        md5_key    = md5_hex.lower()
        return self._by_sha256.get(sha256_key) or self._by_md5.get(md5_key)

    @property
    def entry_count(self) -> int:
        """Number of unique SHA256 entries loaded."""
        # Using SHA256 as the canonical count to avoid double-counting entries
        # that appear in both indices (every entry with both hashes).
        return len(self._by_sha256)


# ── Main engine ───────────────────────────────────────────────────────────────

class SignatureEngine:
    """
    Hash-based malware detection engine (Layer 1 of PredatorEye protection).

    Instantiate once and reuse across multiple scans — the database is loaded
    at construction time and kept in memory.

    Example::

        engine = SignatureEngine()
        result = engine.scan_file(r"C:\\Users\\Bob\\Downloads\\suspicious.exe")
        if result["matched"]:
            print(f"Threat detected: {result['threat_name']}")

        report = engine.scan_directory(r"C:\\Users\\Bob\\Downloads")
        print(f"{len(report['threats'])} threat(s) found in {report['scanned']} files")
    """

    def __init__(self, db_path: str = _DEFAULT_DB):
        self.db = SignatureDB(db_path)

    # ── Single-file scan ──────────────────────────────────────────────────────

    def scan_file(self, path: str) -> dict:
        """
        Compute MD5 + SHA256 for *path* and look them up in the signature DB.

        Returns a result dict in all cases — never raises.  Errors (permission
        denied, file not found, I/O failure) are captured in the 'error' field
        so that a directory scan can continue past inaccessible files without
        losing the rest of the results.

        The file is opened in binary read mode only — it is never executed,
        interpreted, or passed to any subprocess.
        """
        if not os.path.isfile(path):
            return _file_result(
                path, matched=False,
                error="Path does not exist or is not a regular file",
            )

        try:
            md5_hex, sha256_hex = _compute_hashes(path)
        except PermissionError as exc:
            return _file_result(path, matched=False,
                                error=f"Permission denied: {exc}")
        except OSError as exc:
            return _file_result(path, matched=False,
                                error=f"I/O error: {exc}")

        hit = self.db.lookup(md5_hex, sha256_hex)

        if hit:
            return _file_result(
                path,
                matched=True,
                threat_name=hit.get("name"),
                family=hit.get("family"),
                severity=hit.get("severity", "High"),
                hash_md5=md5_hex,
                hash_sha256=sha256_hex,
            )

        return _file_result(
            path,
            matched=False,
            hash_md5=md5_hex,
            hash_sha256=sha256_hex,
        )

    # ── Directory scan ────────────────────────────────────────────────────────

    def scan_directory(
        self,
        dir_path: str,
        recursive: bool = True,
        extensions: Optional[set] = None,
    ) -> dict:
        """
        Scan every file in *dir_path* against the signature database.

        Args:
            dir_path:   Root path to scan.
            recursive:  Descend into sub-directories (default True).
            extensions: Optional set of lowercase extensions to scan, e.g.
                        {'.exe', '.dll', '.ps1'}.  None means scan all files.

        Returns an aggregate dict consistent with the scanners/ contract::

            {
                "scanned":    int,            # total files examined
                "threats":    [file_result],  # matched=True entries only
                "clean":      int,            # files with no match
                "errors":     [str],          # inaccessible / unreadable files
                "db_version": str,
                "db_entries": int,
            }

        The 'threats' list is what the RiskScorer and ThreatCorrelator consume.
        """
        if not os.path.isdir(dir_path):
            return {
                "scanned": 0, "threats": [], "clean": 0,
                "errors":  [f"Directory not found: {dir_path}"],
                "db_version": self.db.version,
                "db_entries": self.db.entry_count,
            }

        threats: list = []
        errors:  list = []
        clean_count = 0

        # os.walk yields (root, dirs, files); when non-recursive, stop after
        # the first iteration (only the top-level directory).
        walker = os.walk(dir_path)

        for root, _dirs, files in walker:
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if extensions and ext not in extensions:
                    continue

                full_path = os.path.join(root, fname)
                result    = self.scan_file(full_path)

                if result.get("error"):
                    errors.append(f"{full_path}: {result['error']}")
                elif result["matched"]:
                    threats.append(result)
                else:
                    clean_count += 1

            if not recursive:
                break   # stop after processing the top-level directory

        return {
            "scanned":    len(threats) + clean_count,
            "threats":    threats,
            "clean":      clean_count,
            "errors":     errors,
            "db_version": self.db.version,
            "db_entries": self.db.entry_count,
        }
