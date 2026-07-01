"""
tests/test_signature_engine.py
================================
Unit tests for protection/signature_engine.py — Layer 1 (hash-based detection).

Test strategy
--------------
Rather than creating a real EICAR file (which Windows Defender may quarantine),
most tests use a custom in-memory signature database (temp JSON) containing a
known-good test hash.  This makes every test hermetic and deterministic.

The EICAR-specific tests only verify that the hash is present in the DB and
that the result schema is correct — they do NOT write the EICAR executable
string to disk.  One optional test (marked @pytest.mark.eicar) DOES write the
EICAR content to a .txt temp file to prove end-to-end detection.  This test
is skipped if the env var SKIP_EICAR=1 is set (useful in environments with
aggressive real-time AV).
"""

import os
import json
import hashlib
import tempfile
import pytest

from protection.signature_engine import (
    SignatureEngine,
    SignatureDB,
    _compute_hashes,
    _DEFAULT_DB,
)

# ── Shared test data ──────────────────────────────────────────────────────────

_TEST_CONTENT  = b"PredatorEye test payload - not malware"
_TEST_MD5      = hashlib.md5(_TEST_CONTENT).hexdigest()
_TEST_SHA256   = hashlib.sha256(_TEST_CONTENT).hexdigest()

_CLEAN_CONTENT = b"This is a clean benign file with no threat signatures."
_CLEAN_MD5     = hashlib.md5(_CLEAN_CONTENT).hexdigest()
_CLEAN_SHA256  = hashlib.sha256(_CLEAN_CONTENT).hexdigest()

# Real EICAR hashes (from eicar.org) — used for DB lookup tests only
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5    = "44d88612fea8a8f36de82e1278abb02f"

_SKIP_EICAR = os.getenv("SKIP_EICAR", "0") == "1"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def temp_db_path(tmp_path_factory):
    """Temporary signatures.json containing one known-threat entry."""
    db_dir = tmp_path_factory.mktemp("db")
    db_file = db_dir / "signatures.json"
    db_data = {
        "version": "test-1.0",
        "updated": "2026-07-01",
        "entries": [
            {
                "sha256":   _TEST_SHA256,
                "md5":      _TEST_MD5,
                "name":     "Test.Threat.Alpha",
                "family":   "TestFamily",
                "severity": "High",
                "source":   "pytest fixture",
            }
        ],
    }
    db_file.write_text(json.dumps(db_data), encoding="utf-8")
    return str(db_file)


@pytest.fixture(scope="module")
def test_file(tmp_path_factory):
    """Temp file whose hash IS in the test database."""
    d = tmp_path_factory.mktemp("files")
    p = d / "threat.txt"
    p.write_bytes(_TEST_CONTENT)
    return str(p)


@pytest.fixture(scope="module")
def clean_file(tmp_path_factory):
    """Temp file whose hash is NOT in the test database."""
    d = tmp_path_factory.mktemp("clean")
    p = d / "clean.txt"
    p.write_bytes(_CLEAN_CONTENT)
    return str(p)


@pytest.fixture(scope="module")
def mixed_dir(tmp_path_factory):
    """Directory with one threat file and one clean file."""
    d = tmp_path_factory.mktemp("mixed")
    (d / "threat.txt").write_bytes(_TEST_CONTENT)
    (d / "clean.txt").write_bytes(_CLEAN_CONTENT)
    return str(d)


# ── _compute_hashes ───────────────────────────────────────────────────────────

class TestComputeHashes:

    def test_returns_two_element_tuple(self, test_file):
        result = _compute_hashes(test_file)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_md5_is_correct(self, test_file):
        md5, _ = _compute_hashes(test_file)
        assert md5 == _TEST_MD5

    def test_sha256_is_correct(self, test_file):
        _, sha256 = _compute_hashes(test_file)
        assert sha256 == _TEST_SHA256

    def test_hashes_are_lowercase_hex(self, test_file):
        md5, sha256 = _compute_hashes(test_file)
        assert md5   == md5.lower()
        assert sha256 == sha256.lower()
        assert len(md5)    == 32
        assert len(sha256) == 64

    def test_missing_file_raises_os_error(self, tmp_path):
        with pytest.raises(OSError):
            _compute_hashes(str(tmp_path / "ghost.bin"))

    def test_different_files_have_different_hashes(self, test_file, clean_file):
        md5_a, sha_a = _compute_hashes(test_file)
        md5_b, sha_b = _compute_hashes(clean_file)
        assert md5_a   != md5_b
        assert sha_a   != sha_b


# ── SignatureDB ───────────────────────────────────────────────────────────────

class TestSignatureDB:

    def test_loads_entry_count(self, temp_db_path):
        db = SignatureDB(temp_db_path)
        assert db.entry_count == 1

    def test_version_is_loaded(self, temp_db_path):
        db = SignatureDB(temp_db_path)
        assert db.version == "test-1.0"

    def test_lookup_by_sha256(self, temp_db_path):
        db    = SignatureDB(temp_db_path)
        entry = db.lookup("", _TEST_SHA256)
        assert entry is not None
        assert entry["name"]     == "Test.Threat.Alpha"
        assert entry["severity"] == "High"

    def test_lookup_by_md5_fallback(self, temp_db_path):
        """MD5 lookup succeeds when SHA256 doesn't match."""
        db    = SignatureDB(temp_db_path)
        bogus_sha = "f" * 64
        entry = db.lookup(_TEST_MD5, bogus_sha)
        assert entry is not None

    def test_lookup_sha256_preferred_over_md5(self, temp_db_path):
        """SHA256 match wins even when an MD5 for a different entry exists."""
        db    = SignatureDB(temp_db_path)
        entry = db.lookup(_TEST_MD5, _TEST_SHA256)
        assert entry is not None
        assert entry["name"] == "Test.Threat.Alpha"

    def test_lookup_miss_returns_none(self, temp_db_path):
        db = SignatureDB(temp_db_path)
        assert db.lookup("a" * 32, "b" * 64) is None

    def test_missing_db_file_gives_empty_db(self, tmp_path):
        db = SignatureDB(str(tmp_path / "nonexistent.json"))
        assert db.entry_count == 0

    def test_corrupt_db_file_gives_empty_db(self, tmp_path):
        bad = tmp_path / "corrupt.json"
        bad.write_text("not json {{{ broken")
        db = SignatureDB(str(bad))
        assert db.entry_count == 0

    def test_eicar_is_in_default_db(self):
        """The default signatures.json ships with the EICAR test-file entry."""
        db    = SignatureDB(_DEFAULT_DB)
        entry = db.lookup(EICAR_MD5, EICAR_SHA256)
        assert entry is not None, (
            "EICAR entry missing from protection/signatures.json — "
            "add it back as the canonical engine-validation entry"
        )
        assert "EICAR" in entry.get("name", "").upper()


# ── SignatureEngine ───────────────────────────────────────────────────────────

class TestSignatureEngine:

    def test_scan_file_returns_match(self, temp_db_path, test_file):
        engine = SignatureEngine(temp_db_path)
        result = engine.scan_file(test_file)

        assert result["matched"]     is True
        assert result["threat_name"] == "Test.Threat.Alpha"
        assert result["severity"]    == "High"
        assert result["error"]       is None
        assert result["hash_sha256"] == _TEST_SHA256

    def test_scan_clean_file_returns_no_match(self, temp_db_path, clean_file):
        engine = SignatureEngine(temp_db_path)
        result = engine.scan_file(clean_file)

        assert result["matched"] is False
        assert result["error"]   is None
        # Hashes are still computed and returned for audit purposes
        assert result["hash_sha256"] == _CLEAN_SHA256

    def test_scan_missing_file_returns_error_not_exception(self, temp_db_path, tmp_path):
        engine = SignatureEngine(temp_db_path)
        result = engine.scan_file(str(tmp_path / "ghost.exe"))

        assert result["matched"] is False
        assert result["error"]   is not None
        assert "not exist" in result["error"].lower() or "not a regular" in result["error"].lower()

    def test_scan_file_result_has_all_required_keys(self, temp_db_path, test_file):
        engine   = SignatureEngine(temp_db_path)
        result   = engine.scan_file(test_file)
        required = {"path", "filename", "matched", "threat_name", "family",
                    "severity", "hash_md5", "hash_sha256", "scanned_at", "error"}
        assert required.issubset(result.keys())

    def test_scan_file_filename_is_basename(self, temp_db_path, test_file):
        engine = SignatureEngine(temp_db_path)
        result = engine.scan_file(test_file)
        assert result["filename"] == os.path.basename(test_file)

    def test_scan_directory_counts_correctly(self, temp_db_path, mixed_dir):
        engine = SignatureEngine(temp_db_path)
        report = engine.scan_directory(mixed_dir, recursive=False)

        assert report["scanned"]        == 2
        assert len(report["threats"])   == 1
        assert report["clean"]          == 1
        assert report["threats"][0]["threat_name"] == "Test.Threat.Alpha"

    def test_scan_directory_recursive_finds_nested(self, temp_db_path, tmp_path):
        nested = tmp_path / "sub"
        nested.mkdir()
        (nested / "deep.txt").write_bytes(_TEST_CONTENT)

        engine = SignatureEngine(temp_db_path)

        non_rec = engine.scan_directory(str(tmp_path), recursive=False)
        rec     = engine.scan_directory(str(tmp_path), recursive=True)

        assert len(non_rec["threats"]) == 0
        assert len(rec["threats"])     == 1

    def test_scan_nonexistent_directory_returns_error(self, temp_db_path):
        engine = SignatureEngine(temp_db_path)
        report = engine.scan_directory("/no/such/directory/at/all")
        assert report["scanned"] == 0
        assert len(report["errors"]) >= 1

    def test_scan_directory_extension_filter(self, temp_db_path, tmp_path):
        (tmp_path / "threat.exe").write_bytes(_TEST_CONTENT)
        (tmp_path / "threat.pdf").write_bytes(_TEST_CONTENT)

        engine = SignatureEngine(temp_db_path)
        report = engine.scan_directory(str(tmp_path), extensions={".exe"})

        # Only .exe should be scanned
        assert report["scanned"] == 1
        assert len(report["threats"]) == 1

    def test_scan_directory_includes_db_metadata(self, temp_db_path, mixed_dir):
        engine = SignatureEngine(temp_db_path)
        report = engine.scan_directory(mixed_dir)
        assert "db_version" in report
        assert "db_entries" in report
        assert report["db_version"] == "test-1.0"
        assert report["db_entries"] == 1

    @pytest.mark.eicar
    @pytest.mark.skipif(_SKIP_EICAR, reason="SKIP_EICAR=1 set in environment")
    def test_eicar_content_detected_end_to_end(self):
        """
        Write the EICAR test string to a .txt temp file and verify the engine
        matches it via the SHA256 in the default signatures.json.

        Uses .txt suffix — .com triggers Windows Defender real-time deletion.
        Wrapped in try/finally so temp file is cleaned up even if Defender
        quarantines it (in which case os.unlink raises FileNotFoundError).
        """
        eicar_bytes = (
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}"
            b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        )
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as fh:
                fh.write(eicar_bytes)
                tmp = fh.name

            engine = SignatureEngine()   # uses default signatures.json
            result = engine.scan_file(tmp)

            assert result["matched"] is True, (
                f"EICAR not detected. Hash: {result.get('hash_sha256','?')}"
            )
            assert "EICAR" in (result.get("threat_name") or "").upper()
            assert result["severity"] == "Info"
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass   # Defender may have already removed it
