"""
protection/yara_engine.py
===========================
YARA pattern-matching engine — Layer 2 of PredatorEye's three-layer
protection stack (hash  →  YARA pattern  →  behavioural heuristic).

Academic rationale (for project report)
-----------------------------------------
Where hash-based detection (Layer 1) identifies *exact* known files, YARA
detection identifies *families* of malware by describing their structural or
behavioural patterns as rules.  This closes the most common evasion gap
against hash matching: a single byte-flip (padding, recompilation, packing)
produces an entirely different hash but typically does not change the embedded
command strings, API call sequences, or magic bytes that a YARA rule targets.

YARA is the industry standard for threat-intelligence rule exchange:
  - Used by VirusTotal, Mandiant, CrowdStrike, and law enforcement agencies
  - Open rule repositories: Neo23x0/signature-base, Elastic Detection Rules,
    YARA-Forge — any of these can be dropped into the rules/ directory.
  - Rules are human-readable, auditable, and can be mapped directly to
    MITRE ATT&CK techniques via rule metadata fields.

The three-layer combination (hash + YARA + heuristic) mirrors the
architecture used by production AV engines (ClamAV, Microsoft Defender)
and represents the minimum viable coverage for a defensible detection
platform in an academic or research context.

Graceful degradation
---------------------
yara-python requires a C extension.  If it is not installed, every scan
method returns results with yara_available=False and an informative error
message — the rest of PredatorEye's protection stack continues to function.

    Install:  pip install yara-python
    Pre-built wheels for Python 3.9–3.12 on Windows/Linux/macOS are available
    on PyPI, so a C compiler is not required in most cases.

Rule directory
--------------
Rules are loaded from <repo_root>/rules/ by default.  Every file with a
.yar or .yara extension is compiled into a single combined ruleset.  Each
file becomes a separate YARA namespace (the filename stem), which allows
categories of rules to be tracked independently in match results.
"""

import os
import datetime
from typing import Optional


# ── Module constants ──────────────────────────────────────────────────────────

# Default rule directory: <repo_root>/rules/
# __file__ = <repo_root>/protection/yara_engine.py  →  parent = <repo_root>
_DEFAULT_RULES_DIR: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules"
)

_RULE_EXTENSIONS: set = {".yar", ".yara"}

# Per-file scan timeout (seconds).  Prevents the engine from hanging on
# specially crafted files that trigger catastrophic backtracking in YARA
# string matchers — a known denial-of-service vector against AV scanners.
_SCAN_TIMEOUT: int = 30


# ── Result constructor ────────────────────────────────────────────────────────

def _file_result(
    path: str,
    matched: bool,
    matches: Optional[list] = None,
    error: Optional[str] = None,
    yara_available: bool = True,
) -> dict:
    """
    Build a standardised per-file YARA result dict.

    The 'matches' list contains one entry per triggered rule, each with
    the rule's name, namespace, tags, metadata, and the specific strings
    that caused the match — giving enough context for the ThreatCorrelator
    to escalate severity and map to MITRE techniques.
    """
    return {
        "path":           path,
        "filename":       os.path.basename(path),
        "matched":        matched,
        "matches":        matches or [],
        "scanned_at":     datetime.datetime.now().isoformat(timespec="seconds"),
        "error":          error,
        "yara_available": yara_available,
    }


# ── String normalisation ──────────────────────────────────────────────────────

def _normalise_strings(raw_strings) -> list:
    """
    Convert yara-python string match objects to JSON-serialisable dicts.

    yara-python changed its string-match API between major versions:
      v4+:  list of yara.StringMatch objects  (item.identifier, item.instances)
      v3:   list of (offset, identifier, data) tuples

    Supporting both versions means the engine works regardless of which
    yara-python release is installed — important for reproducibility across
    different project environments.
    """
    result = []
    for item in raw_strings:
        if isinstance(item, tuple):
            # yara-python v3 API
            offset, identifier, data = item
            result.append({
                "identifier": identifier,
                "offset":     offset,
                "data":       repr(data),
            })
        else:
            # yara-python v4+ API: StringMatch with .instances list
            for inst in getattr(item, "instances", []):
                result.append({
                    "identifier": item.identifier,
                    "offset":     inst.offset,
                    "data":       repr(bytes(inst.matched_data)),
                })
    return result


# ── Main engine ───────────────────────────────────────────────────────────────

class YaraEngine:
    """
    YARA pattern-matching engine (Layer 2 of PredatorEye protection).

    Compiles all .yar/.yara rules from a directory into a single combined
    ruleset and scans files or directories for matches.

    Each rule file becomes a separate namespace in the compiled ruleset,
    so match results record which rule file the triggering rule came from —
    useful for categorising detections (e.g., "eicar_test vs common_threats").

    Usage::

        engine = YaraEngine()                   # loads from default rules/ dir
        result = engine.scan_file(r"C:\\suspect.exe")
        if result["matched"]:
            for m in result["matches"]:
                print(m["rule_name"], m["severity"])

        report = engine.scan_directory(r"C:\\Users\\Bob\\Downloads")
        print(f"{report['detections']} file(s) matched YARA rules")
    """

    def __init__(self, rules_dir: str = _DEFAULT_RULES_DIR):
        self.rules_dir:     str  = rules_dir
        self._rules              = None   # compiled yara.Rules object (or None)
        self._yara_available:bool = False
        self._load_error: Optional[str] = None
        self._rules_loaded:  int = 0
        self._load()

    # ── Initialisation ────────────────────────────────────────────────────────

    def _load(self) -> None:
        """
        Import yara-python and compile all rule files from self.rules_dir.

        Errors are captured in self._load_error rather than raised, so that
        an unavailable yara-python installation does not crash the entire
        protection stack on import.
        """
        # Step 1: check whether yara-python is importable
        try:
            import yara   # noqa: F401 — import test only
            self._yara_available = True
        except ImportError:
            self._load_error = (
                "yara-python is not installed. "
                "Run:  pip install yara-python"
            )
            return

        # Step 2: verify the rules directory exists
        if not os.path.isdir(self.rules_dir):
            self._load_error = f"Rules directory not found: {self.rules_dir}"
            return

        # Step 3: collect all rule files
        filepaths: dict = {}
        for fname in sorted(os.listdir(self.rules_dir)):
            ext = os.path.splitext(fname)[1].lower()
            if ext in _RULE_EXTENSIONS:
                # Namespace = filename stem; allows per-category tracking in results
                namespace = os.path.splitext(fname)[0]
                filepaths[namespace] = os.path.join(self.rules_dir, fname)

        if not filepaths:
            self._load_error = (
                f"No .yar/.yara rule files found in: {self.rules_dir}"
            )
            return

        # Step 4: compile all rules into one combined ruleset
        # yara.compile(filepaths={namespace: path}) merges all files while
        # preserving per-namespace tracking — if one file has a syntax error,
        # compilation fails for all.  In production, compile per-file and
        # skip invalid ones; for academic scope a combined compile is fine.
        try:
            import yara
            self._rules = yara.compile(filepaths=filepaths)
            self._rules_loaded = len(filepaths)
        except Exception as exc:    # yara.SyntaxError is a subclass of Exception
            self._load_error = f"Failed to compile YARA rules: {exc}"

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def available(self) -> bool:
        """True if yara-python is installed and at least one rule compiled."""
        return self._rules is not None

    # ── Single-file scan ──────────────────────────────────────────────────────

    def scan_file(self, path: str) -> dict:
        """
        Scan a single file against all compiled YARA rules.

        Returns a result dict regardless of outcome — never raises.

        Result shape::

            {
                "path":           str,
                "filename":       str,
                "matched":        bool,
                "matches": [
                    {
                        "rule_name":       str,   # e.g. "Credential_Dump_Mimikatz"
                        "namespace":       str,   # e.g. "common_threats" (source file)
                        "tags":            [str],
                        "meta":            {str: str},  # from rule metadata block
                        "severity":        str,   # pulled from meta, default "High"
                        "strings_matched": [{"identifier", "offset", "data"}],
                    },
                    ...
                ],
                "scanned_at":     str,
                "error":          str | None,
                "yara_available": bool,
            }

        The per-rule 'meta' dict is intentionally passed through unmodified
        so that the ThreatCorrelator can read arbitrary metadata fields
        (mitre_tactic, mitre_technique, severity, reference) without this
        module needing to know their schema.
        """
        if not self._yara_available:
            return _file_result(
                path, matched=False,
                error=self._load_error,
                yara_available=False,
            )

        if self._rules is None:
            return _file_result(
                path, matched=False,
                error=self._load_error or "No rules compiled",
            )

        if not os.path.isfile(path):
            return _file_result(
                path, matched=False,
                error="Path does not exist or is not a regular file",
            )

        try:
            raw_matches = self._rules.match(path, timeout=_SCAN_TIMEOUT)
        except Exception as exc:
            # Catches yara.TimeoutError, yara.Error, and any other YARA failure
            return _file_result(path, matched=False, error=str(exc))

        if not raw_matches:
            return _file_result(path, matched=False)

        matches = []
        for m in raw_matches:
            matches.append({
                "rule_name":       m.rule,
                "namespace":       m.namespace,
                "tags":            list(m.tags),
                "meta":            dict(m.meta),
                # Severity is stored in rule metadata for human readability
                # and machine consumption by the ThreatCorrelator.
                "severity":        m.meta.get("severity", "High"),
                "strings_matched": _normalise_strings(m.strings),
            })

        return _file_result(path, matched=True, matches=matches)

    # ── Directory scan ────────────────────────────────────────────────────────

    def scan_directory(
        self,
        dir_path: str,
        recursive: bool = True,
        extensions: Optional[set] = None,
    ) -> dict:
        """
        Scan all files in dir_path against the compiled YARA ruleset.

        Args:
            dir_path:   Root path to scan.
            recursive:  Descend into sub-directories (default True).
            extensions: Optional set of lowercase extensions to include,
                        e.g. {'.exe', '.ps1'}.  None means scan all files.

        Returns an aggregate dict consistent with the scanners/ contract::

            {
                "scanned":        int,   # total files examined
                "detections":     int,   # files with ≥1 rule match
                "matches":        [file_result_dict, ...],
                "clean":          int,
                "errors":         [str, ...],
                "rules_loaded":   int,
                "yara_available": bool,
            }
        """
        summary: dict = {
            "scanned":        0,
            "detections":     0,
            "matches":        [],
            "clean":          0,
            "errors":         [],
            "rules_loaded":   self._rules_loaded,
            "yara_available": self._yara_available,
        }

        if not self._yara_available or self._rules is None:
            summary["errors"].append(self._load_error or "YARA unavailable")
            return summary

        if not os.path.isdir(dir_path):
            summary["errors"].append(f"Directory not found: {dir_path}")
            return summary

        walker = os.walk(dir_path)

        for root, _dirs, files in walker:
            for fname in files:
                if extensions:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in extensions:
                        continue

                full_path = os.path.join(root, fname)
                result    = self.scan_file(full_path)
                summary["scanned"] += 1

                if result.get("error"):
                    summary["errors"].append(f"{full_path}: {result['error']}")
                elif result["matched"]:
                    summary["matches"].append(result)
                    summary["detections"] += 1
                else:
                    summary["clean"] += 1

            if not recursive:
                break   # only process the top-level directory

        return summary
