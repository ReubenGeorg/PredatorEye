"""
tests/test_yara_engine.py
===========================
Unit tests for protection/yara_engine.py — Layer 2 (YARA pattern matching).

Test structure
--------------
YaraEngine tests are split into two classes:

  TestYaraEngineAvailable
    Requires yara-python to be installed.  Skipped automatically when the
    package is absent (CI environments without a C compiler, for example).
    Tests actual YARA rule compilation, string matching, and result schema.

  TestYaraEngineDegradation
    Always runs.  Verifies that YaraEngine initialises without crashing when
    pointed at a non-existent rules directory or when yara is unavailable.

EICAR marker note
------------------
Tests that need a "malicious" file use the string
    EICAR-STANDARD-ANTIVIRUS-TEST-FILE
written to a .txt temp file.  This is just the marker substring from our
YARA rule — NOT the full EICAR executable string — so Windows Defender will
not quarantine it.

Mimikatz simulation note
-------------------------
The Credential_Dump_Mimikatz rule requires 2 of 6 strings.  Tests use
"sekurlsa::logonpasswords" and "privilege::debug" — both of which appear
extensively in public security documentation and are not executable code,
so they pose no security risk and Defender will not flag a .txt file containing
them.
"""

import importlib.util
import os
import tempfile
import pytest

# ── Module-level skip when yara-python is absent ─────────────────────────────

_YARA_AVAILABLE = importlib.util.find_spec("yara") is not None

_skip_no_yara = pytest.mark.skipif(
    not _YARA_AVAILABLE,
    reason="yara-python is not installed — pip install yara-python",
)

from protection.yara_engine import YaraEngine, _DEFAULT_RULES_DIR


# ── Shared helpers ────────────────────────────────────────────────────────────

def _write_temp(content: str, suffix: str = ".txt") -> str:
    """Write content to a NamedTemporaryFile and return its path."""
    fh = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    fh.write(content)
    fh.close()
    return fh.name


def _cleanup(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def eicar_marker_file():
    """Temp file containing only the EICAR marker substring (NOT the full EICAR exe)."""
    path = _write_temp("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", suffix=".txt")
    yield path
    _cleanup(path)


@pytest.fixture(scope="module")
def clean_file():
    """Temp file with benign content that should match no rules."""
    path = _write_temp("Hello, world! This is a clean test file.", suffix=".txt")
    yield path
    _cleanup(path)


@pytest.fixture(scope="module")
def mimikatz_file():
    """
    Temp file with Mimikatz-associated command strings (documentation strings,
    not executable code) — satisfies the 2-of-6 condition in the rule.
    """
    content = (
        "This is a simulated Mimikatz detection test.\n"
        "Command: sekurlsa::logonpasswords\n"
        "Command: privilege::debug\n"
    )
    path = _write_temp(content, suffix=".txt")
    yield path
    _cleanup(path)


@pytest.fixture(scope="module")
def powershell_encoded_file():
    """File that matches the Evasion_PowerShell_Encoded rule."""
    # Contains 'powershell' AND '-EncodedCommand' to satisfy the rule
    content = "powershell.exe -EncodedCommand dABlAHMAdABpAG4AZwA="
    path = _write_temp(content, suffix=".txt")
    yield path
    _cleanup(path)


@pytest.fixture(scope="module")
def default_engine():
    """YaraEngine loaded from the real rules/ directory."""
    return YaraEngine()


@pytest.fixture(scope="module")
def mixed_dir(tmp_path_factory, eicar_marker_file):
    """Directory with one matching file and one clean file."""
    d = tmp_path_factory.mktemp("yara_mixed")
    import shutil
    shutil.copy(eicar_marker_file, str(d / "eicar_marker.txt"))
    (d / "benign.txt").write_text("nothing suspicious here", encoding="utf-8")
    return str(d)


# ── Tests: YaraEngine initialisation ─────────────────────────────────────────

class TestYaraEngineInit:

    def test_instantiates_without_error(self):
        engine = YaraEngine()
        assert engine is not None

    def test_default_rules_dir_is_set(self):
        engine = YaraEngine()
        assert engine.rules_dir == _DEFAULT_RULES_DIR

    @_skip_no_yara
    def test_available_is_true_when_rules_exist(self, default_engine):
        assert default_engine.available is True

    @_skip_no_yara
    def test_rules_loaded_count_is_positive(self, default_engine):
        assert default_engine._rules_loaded >= 1

    def test_nonexistent_rules_dir_sets_error(self):
        engine = YaraEngine(rules_dir="/no/such/rules/dir")
        assert engine.available is False
        assert engine._load_error is not None


# ── Tests: scan_file ──────────────────────────────────────────────────────────

@_skip_no_yara
class TestScanFile:

    def test_eicar_marker_triggers_rule(self, default_engine, eicar_marker_file):
        result = default_engine.scan_file(eicar_marker_file)

        assert result["matched"] is True
        assert result["yara_available"] is True
        assert len(result["matches"]) >= 1
        rule_names = [m["rule_name"] for m in result["matches"]]
        assert any("EICAR" in n for n in rule_names), (
            f"Expected EICAR rule to fire, got: {rule_names}"
        )

    def test_clean_file_has_no_matches(self, default_engine, clean_file):
        result = default_engine.scan_file(clean_file)

        assert result["matched"]        is False
        assert result["yara_available"] is True
        assert result["matches"]        == []
        assert result["error"]          is None

    def test_missing_file_returns_error_not_exception(self, default_engine, tmp_path):
        result = default_engine.scan_file(str(tmp_path / "ghost.exe"))

        assert result["matched"] is False
        assert result["error"]   is not None

    def test_mimikatz_rule_fires(self, default_engine, mimikatz_file):
        result = default_engine.scan_file(mimikatz_file)

        assert result["matched"] is True
        rule_names = [m["rule_name"] for m in result["matches"]]
        assert any("Mimikatz" in n or "Credential" in n for n in rule_names), (
            f"Mimikatz rule did not fire. Rules matched: {rule_names}"
        )

    def test_powershell_encoded_rule_fires(self, default_engine, powershell_encoded_file):
        result = default_engine.scan_file(powershell_encoded_file)

        assert result["matched"] is True
        rule_names = [m["rule_name"] for m in result["matches"]]
        assert any("PowerShell" in n or "Encoded" in n for n in rule_names), (
            f"PowerShell_Encoded rule did not fire. Rules matched: {rule_names}"
        )

    def test_match_result_has_required_keys(self, default_engine, eicar_marker_file):
        result = default_engine.scan_file(eicar_marker_file)
        required = {"path", "filename", "matched", "matches", "scanned_at",
                    "error", "yara_available"}
        assert required.issubset(result.keys())

    def test_match_entry_has_required_keys(self, default_engine, eicar_marker_file):
        result = default_engine.scan_file(eicar_marker_file)
        assert result["matches"], "Expected at least one match"
        m = result["matches"][0]
        required = {"rule_name", "namespace", "tags", "meta", "severity",
                    "strings_matched"}
        assert required.issubset(m.keys()), f"Missing keys: {required - m.keys()}"

    def test_severity_comes_from_rule_metadata(self, default_engine, eicar_marker_file):
        result = default_engine.scan_file(eicar_marker_file)
        assert result["matches"][0]["severity"] == "Info"

    def test_namespace_is_rule_file_stem(self, default_engine, eicar_marker_file):
        result  = default_engine.scan_file(eicar_marker_file)
        ns      = result["matches"][0]["namespace"]
        assert ns == "eicar_test", f"Expected namespace 'eicar_test', got '{ns}'"

    def test_meta_dict_contains_mitre_tactic(self, default_engine, mimikatz_file):
        result = default_engine.scan_file(mimikatz_file)
        for m in result["matches"]:
            if "Mimikatz" in m["rule_name"] or "Credential" in m["rule_name"]:
                assert "mitre_tactic" in m["meta"]
                assert "mitre_technique" in m["meta"]
                break

    def test_filename_is_basename(self, default_engine, eicar_marker_file):
        result = default_engine.scan_file(eicar_marker_file)
        assert result["filename"] == os.path.basename(eicar_marker_file)


# ── Tests: scan_directory ─────────────────────────────────────────────────────

@_skip_no_yara
class TestScanDirectory:

    def test_detects_matching_file_in_dir(self, default_engine, mixed_dir):
        report = default_engine.scan_directory(mixed_dir, recursive=False)

        assert report["yara_available"] is True
        assert report["detections"]     == 1
        assert len(report["matches"])   == 1
        assert report["clean"]          == 1

    def test_scanned_count_is_total_files(self, default_engine, mixed_dir):
        report = default_engine.scan_directory(mixed_dir, recursive=False)
        assert report["scanned"] == report["detections"] + report["clean"]

    def test_nonexistent_dir_returns_error(self, default_engine):
        report = default_engine.scan_directory("/no/such/directory/at/all")
        assert report["scanned"]        == 0
        assert len(report["errors"])    >= 1

    def test_recursive_finds_nested_match(self, default_engine, tmp_path,
                                          eicar_marker_file):
        import shutil
        nested = tmp_path / "sub"
        nested.mkdir()
        shutil.copy(eicar_marker_file, str(nested / "marker.txt"))

        non_rec = default_engine.scan_directory(str(tmp_path), recursive=False)
        rec     = default_engine.scan_directory(str(tmp_path), recursive=True)

        assert non_rec["detections"] == 0
        assert rec["detections"]     == 1

    def test_extension_filter_limits_scan(self, default_engine, tmp_path,
                                          eicar_marker_file):
        import shutil
        shutil.copy(eicar_marker_file, str(tmp_path / "marker.txt"))
        shutil.copy(eicar_marker_file, str(tmp_path / "marker.ps1"))

        txt_only = default_engine.scan_directory(str(tmp_path), extensions={".txt"})
        ps1_only = default_engine.scan_directory(str(tmp_path), extensions={".ps1"})

        assert txt_only["scanned"] == 1
        assert ps1_only["scanned"] == 1

    def test_report_includes_rules_loaded(self, default_engine, mixed_dir):
        report = default_engine.scan_directory(mixed_dir)
        assert "rules_loaded" in report
        assert report["rules_loaded"] >= 1


# ── Tests: graceful degradation (always run) ──────────────────────────────────

class TestYaraEngineDegradation:

    def test_scan_file_returns_dict_when_no_rules(self, tmp_path):
        """
        YaraEngine with a missing rules dir returns a well-formed result dict
        rather than raising an exception — the protection stack must stay up.
        """
        engine = YaraEngine(rules_dir=str(tmp_path / "empty_rules"))
        path   = tmp_path / "test.txt"
        path.write_text("some content", encoding="utf-8")

        result = engine.scan_file(str(path))

        assert isinstance(result, dict)
        assert result["matched"]  is False
        assert result["error"]    is not None
        assert result["matches"]  == []

    def test_scan_directory_returns_dict_when_no_rules(self, tmp_path):
        engine = YaraEngine(rules_dir=str(tmp_path / "empty_rules"))
        report = engine.scan_directory(str(tmp_path))

        assert isinstance(report, dict)
        assert report["scanned"]    == 0
        assert len(report["errors"]) >= 1

    def test_engine_with_empty_rules_dir(self, tmp_path):
        """An empty (but existing) rules directory results in engine being unavailable."""
        engine = YaraEngine(rules_dir=str(tmp_path))
        assert engine.available is False
        assert engine._load_error is not None
        # When yara-python is installed: error mentions "No .yar" files found.
        # When yara-python is absent: error mentions yara not installed.
        # Either way, the engine must be unavailable with a non-empty error string.
        assert len(engine._load_error) > 0
