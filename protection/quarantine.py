"""
protection/quarantine.py
==========================
Safe file isolation with manifest tracking, restore, and permanent delete
— Module 5 of PredatorEye's active protection stack.

Academic rationale (for project report)
-----------------------------------------
When a threat is detected, the correct response is *not* immediate deletion.
Deletion is irreversible: if the detection is a false positive, the legitimate
file is gone.  Instead, production AV engines (Defender, Malwarebytes, Norton)
quarantine the file:

  1. Move the file out of its original location so it cannot execute.
  2. Obfuscate the content so the OS cannot accidentally run it and so
     real-time AV scanners stop re-triggering on it.
  3. Record the original path and detection context in a manifest so the
     file can be restored if the detection turns out to be wrong.

This module implements that exact workflow.

Obfuscation (not encryption)
------------------------------
File content is XOR-obfuscated with a rotating 16-byte key before being
written to the quarantine store.  This is *not* cryptographic encryption:
the key is stored in source code.  It serves two purposes:

  1. Prevents Windows from treating the quarantine folder as a threat —
     Defender's real-time scanner cannot match signatures against
     XOR-scrambled content.
  2. Prevents accidental execution — the quarantined copy is not a valid
     PE/script file; any attempt to run it will fail immediately.

Production AV engines use AES-256 with a per-installation key stored in
a protected registry hive.  The XOR approach chosen here is appropriate
for an academic project because it demonstrates the concept without adding
a cryptography dependency.

The `_xor_file()` function is its own inverse — XOR(XOR(data, key), key) == data
— so the same function is used for both quarantine and restore.

Manifest
---------
`<quarantine_dir>/manifest.json` is the source of truth for every quarantined
file.  It records:
  - The original path (needed for restore)
  - The quarantine file path
  - Detection metadata (threat name, severity, source, hash)
  - Lifecycle timestamps (quarantined_at, restored_at, deleted_at)
  - Current status: "quarantined" | "restored" | "deleted"

The manifest is loaded at construction and written atomically (write to
.tmp then rename) so a power-loss or crash mid-write never corrupts it.

Thread safety
--------------
A threading.Lock guards all manifest read/write operations.  Multiple
watchdog scan threads can call quarantine_file() concurrently without
corrupting the manifest.
"""

import os
import json
import uuid
import shutil
import datetime
import threading
from typing import Optional, List


# ── Quarantine store defaults ──────────────────────────────────────────────────

# Default quarantine directory: <repo_root>/quarantine/
_DEFAULT_QUARANTINE_DIR: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "quarantine"
)

_MANIFEST_FILENAME: str = "manifest.json"
_QUARANTINE_EXTENSION: str = ".quar"

# Maximum file size to quarantine (files larger than this are not moved —
# moving a 4 GB archive would be impractical and the threat is likely a
# false positive on a compressed archive).
_MAX_QUARANTINE_SIZE: int = 100 * 1024 * 1024   # 100 MB

# Entry statuses
STATUS_QUARANTINED = "quarantined"
STATUS_RESTORED    = "restored"
STATUS_DELETED     = "deleted"


# ── XOR obfuscation ────────────────────────────────────────────────────────────

# 16-byte rotating XOR key.  Must never be changed after deployment
# (existing quarantine files would become unreadable).
# For a production build, generate a per-installation key and store it in
# a protected OS credential store (e.g., Windows DPAPI / macOS Keychain).
_OBFUSCATION_KEY: bytes = (
    b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE"
    b"\x00\x11\x22\x33\x44\x55\x66\x77"
)
_KEY_LEN: int = len(_OBFUSCATION_KEY)

_CHUNK_SIZE: int = 65_536   # 64 KB — keeps memory usage flat on large files


def _xor_file(src_path: str, dst_path: str) -> None:
    """
    Copy src to dst with a rotating XOR applied to every byte.

    XOR is its own inverse: calling this function twice returns the original
    content, so the same function is used for both quarantine (obfuscate)
    and restore (de-obfuscate).

    Processes the file in 64 KB chunks to avoid loading large files into RAM.
    """
    offset = 0
    with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
        while True:
            chunk = src.read(_CHUNK_SIZE)
            if not chunk:
                break
            out = bytearray(len(chunk))
            for i, byte in enumerate(chunk):
                out[i] = byte ^ _OBFUSCATION_KEY[(offset + i) % _KEY_LEN]
            dst.write(bytes(out))
            offset += len(chunk)


# ── QID generation ─────────────────────────────────────────────────────────────

def _new_qid() -> str:
    """
    Generate a unique quarantine ID.
    Format: Q-YYYYMMDD-HHMMSS-XXXXXXXX  (8 random hex chars for uniqueness)

    Human-readable timestamps make the manifest auditable without tooling.
    """
    ts  = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    uid = uuid.uuid4().hex[:8].upper()
    return f"Q-{ts}-{uid}"


# ── Manifest helpers ───────────────────────────────────────────────────────────

def _empty_manifest() -> dict:
    return {
        "version": "1.0",
        "entries": [],
    }


def _load_manifest(path: str) -> dict:
    if not os.path.isfile(path):
        return _empty_manifest()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if "entries" not in data:
            return _empty_manifest()
        return data
    except (json.JSONDecodeError, OSError):
        return _empty_manifest()


def _save_manifest(manifest: dict, path: str) -> None:
    """
    Atomic write: write to a .tmp file then rename.

    On POSIX, os.replace() is atomic at the filesystem level.
    On Windows, os.replace() is NOT atomic but is still safer than
    truncating the target in place — a crash during truncation would leave
    a zero-byte manifest.  os.replace() leaves the original intact until
    the new file is fully written.
    """
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


# ── Main Quarantine class ──────────────────────────────────────────────────────

class Quarantine:
    """
    Safe file isolation store with manifest tracking, restore, and delete.

    Usage::

        q = Quarantine()

        # Quarantine a detected file
        result = q.quarantine_file(
            r"C:\\Users\\Bob\\Downloads\\payload.exe",
            threat_info={
                "threat_name":      "Trojan.GenericKD",
                "severity":         "Critical",
                "detection_source": "signature",
                "hash_sha256":      "abc123...",
            }
        )
        qid = result["qid"]

        # List all quarantined files
        entries = q.list_entries()

        # Restore if false positive
        q.restore_file(qid)

        # Or permanently delete
        q.delete_file(qid)
    """

    def __init__(self, quarantine_dir: str = _DEFAULT_QUARANTINE_DIR):
        self.quarantine_dir:  str  = quarantine_dir
        self._manifest_path:  str  = os.path.join(quarantine_dir, _MANIFEST_FILENAME)
        self._lock:           threading.Lock = threading.Lock()
        self._ensure_dir()

    # ── Setup ─────────────────────────────────────────────────────────────────

    def _ensure_dir(self) -> None:
        """Create the quarantine directory if it does not exist."""
        os.makedirs(self.quarantine_dir, exist_ok=True)

    # ── Quarantine a file ─────────────────────────────────────────────────────

    def quarantine_file(
        self,
        path:        str,
        threat_info: Optional[dict] = None,
    ) -> dict:
        """
        Move a file into the quarantine store.

        Steps:
          1. Validate path and size.
          2. Generate a quarantine ID (QID) and destination path.
          3. XOR-obfuscate content and write to quarantine store.
          4. Delete the original file.
          5. Record the entry in the manifest.

        Returns::

            {
                "success":    bool,
                "qid":        str | None,
                "error":      str | None,
                "entry":      dict | None,   # the manifest entry, if successful
            }

        The original file is only deleted *after* the quarantine copy is
        confirmed written — minimising the risk of data loss if the write fails.
        """
        info = threat_info or {}

        if not os.path.isfile(path):
            return {"success": False, "qid": None, "error": f"File not found: {path}", "entry": None}

        try:
            file_size = os.path.getsize(path)
        except OSError as exc:
            return {"success": False, "qid": None, "error": str(exc), "entry": None}

        if file_size > _MAX_QUARANTINE_SIZE:
            return {
                "success": False,
                "qid":     None,
                "error":   (
                    f"File too large to quarantine "
                    f"({file_size / 1_048_576:.1f} MB > "
                    f"{_MAX_QUARANTINE_SIZE // 1_048_576} MB limit)"
                ),
                "entry":   None,
            }

        qid           = _new_qid()
        quar_filename = qid + _QUARANTINE_EXTENSION
        quar_path     = os.path.join(self.quarantine_dir, quar_filename)
        original_path = os.path.abspath(path)
        now           = datetime.datetime.now().isoformat(timespec="seconds")

        # Step 1: XOR-obfuscate the file into the quarantine directory
        try:
            _xor_file(path, quar_path)
        except OSError as exc:
            return {"success": False, "qid": qid, "error": f"Write failed: {exc}", "entry": None}

        # Step 2: Remove the original (only after successful quarantine write)
        try:
            os.remove(path)
        except OSError as exc:
            # Quarantine copy succeeded but original couldn't be removed.
            # Clean up the quarantine copy to avoid a duplicate, then report.
            try:
                os.remove(quar_path)
            except OSError:
                pass
            return {
                "success": False,
                "qid":     qid,
                "error":   f"Original could not be removed: {exc}",
                "entry":   None,
            }

        # Step 3: Record in manifest
        entry: dict = {
            "qid":              qid,
            "original_path":    original_path,
            "original_filename": os.path.basename(original_path),
            "quarantine_path":  quar_path,
            "file_size_bytes":  file_size,
            "threat_name":      info.get("threat_name",      "Unknown"),
            "severity":         info.get("severity",          "High"),
            "detection_source": info.get("detection_source",  "manual"),
            "hash_sha256":      info.get("hash_sha256",       ""),
            "hash_md5":         info.get("hash_md5",          ""),
            "quarantined_at":   now,
            "restored_at":      None,
            "deleted_at":       None,
            "status":           STATUS_QUARANTINED,
            "notes":            info.get("notes", ""),
        }

        with self._lock:
            manifest = _load_manifest(self._manifest_path)
            manifest["entries"].append(entry)
            _save_manifest(manifest, self._manifest_path)

        return {"success": True, "qid": qid, "error": None, "entry": entry}

    # ── Restore a file ────────────────────────────────────────────────────────

    def restore_file(self, qid: str) -> dict:
        """
        De-obfuscate and move a quarantined file back to its original path.

        Returns::

            {"success": bool, "restored_to": str | None, "error": str | None}

        If the original path no longer exists (parent directory was deleted),
        the restore will fail with an OSError.  The manifest entry remains
        STATUS_QUARANTINED so the operator can retry with a different path.
        """
        with self._lock:
            manifest = _load_manifest(self._manifest_path)
            entry    = self._find_entry(manifest, qid)

            if entry is None:
                return {"success": False, "restored_to": None, "error": f"QID not found: {qid}"}

            if entry["status"] != STATUS_QUARANTINED:
                return {
                    "success":     False,
                    "restored_to": None,
                    "error":       f"Cannot restore: file status is '{entry['status']}'",
                }

            quar_path     = entry["quarantine_path"]
            original_path = entry["original_path"]

            if not os.path.isfile(quar_path):
                return {
                    "success":     False,
                    "restored_to": None,
                    "error":       f"Quarantine file missing: {quar_path}",
                }

            # Ensure the target directory exists
            target_dir = os.path.dirname(original_path)
            if not os.path.isdir(target_dir):
                return {
                    "success":     False,
                    "restored_to": None,
                    "error":       (
                        f"Original directory no longer exists: {target_dir}. "
                        "Recreate the directory first or use restore_to()."
                    ),
                }

            # De-obfuscate back to the original path
            try:
                _xor_file(quar_path, original_path)
            except OSError as exc:
                return {"success": False, "restored_to": None, "error": f"Restore write failed: {exc}"}

            # Remove the quarantine copy
            try:
                os.remove(quar_path)
            except OSError:
                pass   # restored copy is good; missing quarantine copy is acceptable

            # Update manifest
            now = datetime.datetime.now().isoformat(timespec="seconds")
            entry["status"]       = STATUS_RESTORED
            entry["restored_at"]  = now
            _save_manifest(manifest, self._manifest_path)

        return {"success": True, "restored_to": original_path, "error": None}

    def restore_to(self, qid: str, target_path: str) -> dict:
        """
        Restore to an alternative path (used when the original directory is gone).

        Updates 'original_path' in the manifest entry to target_path.
        """
        with self._lock:
            manifest = _load_manifest(self._manifest_path)
            entry    = self._find_entry(manifest, qid)

            if entry is None:
                return {"success": False, "restored_to": None, "error": f"QID not found: {qid}"}

            if entry["status"] != STATUS_QUARANTINED:
                return {"success": False, "restored_to": None,
                        "error": f"Cannot restore: status is '{entry['status']}'"}

            quar_path = entry["quarantine_path"]
            if not os.path.isfile(quar_path):
                return {"success": False, "restored_to": None,
                        "error": f"Quarantine file missing: {quar_path}"}

            target_dir = os.path.dirname(os.path.abspath(target_path))
            os.makedirs(target_dir, exist_ok=True)

            try:
                _xor_file(quar_path, target_path)
            except OSError as exc:
                return {"success": False, "restored_to": None, "error": str(exc)}

            try:
                os.remove(quar_path)
            except OSError:
                pass

            now = datetime.datetime.now().isoformat(timespec="seconds")
            entry["status"]        = STATUS_RESTORED
            entry["restored_at"]   = now
            entry["original_path"] = os.path.abspath(target_path)
            _save_manifest(manifest, self._manifest_path)

        return {"success": True, "restored_to": target_path, "error": None}

    # ── Permanently delete ────────────────────────────────────────────────────

    def delete_file(self, qid: str) -> dict:
        """
        Permanently delete a quarantined file.

        The obfuscated file is deleted from the quarantine store.  The
        manifest entry is kept (status=deleted) as an audit trail — you
        should always be able to see *that* a threat existed and was removed,
        even after the file itself is gone.

        Returns::

            {"success": bool, "error": str | None}
        """
        with self._lock:
            manifest = _load_manifest(self._manifest_path)
            entry    = self._find_entry(manifest, qid)

            if entry is None:
                return {"success": False, "error": f"QID not found: {qid}"}

            if entry["status"] == STATUS_DELETED:
                return {"success": False, "error": "File has already been deleted"}

            if entry["status"] == STATUS_RESTORED:
                # File was restored — nothing to delete from quarantine store;
                # just mark the manifest entry as deleted for audit completeness.
                now = datetime.datetime.now().isoformat(timespec="seconds")
                entry["status"]     = STATUS_DELETED
                entry["deleted_at"] = now
                _save_manifest(manifest, self._manifest_path)
                return {"success": True, "error": None}

            quar_path = entry["quarantine_path"]

            if os.path.isfile(quar_path):
                try:
                    os.remove(quar_path)
                except OSError as exc:
                    return {"success": False, "error": f"Delete failed: {exc}"}

            now = datetime.datetime.now().isoformat(timespec="seconds")
            entry["status"]     = STATUS_DELETED
            entry["deleted_at"] = now
            _save_manifest(manifest, self._manifest_path)

        return {"success": True, "error": None}

    # ── Manifest queries ──────────────────────────────────────────────────────

    def list_entries(self, status: Optional[str] = None) -> List[dict]:
        """
        Return all manifest entries, optionally filtered by status.

        Args:
            status: One of STATUS_QUARANTINED, STATUS_RESTORED, STATUS_DELETED,
                    or None to return all entries.

        Returns a shallow copy of each entry so callers cannot mutate the
        in-memory manifest cache.
        """
        with self._lock:
            manifest = _load_manifest(self._manifest_path)

        entries = manifest.get("entries", [])
        if status:
            entries = [e for e in entries if e.get("status") == status]
        return [dict(e) for e in entries]

    def get_entry(self, qid: str) -> Optional[dict]:
        """Return a single manifest entry by QID, or None if not found."""
        with self._lock:
            manifest = _load_manifest(self._manifest_path)
        entry = self._find_entry(manifest, qid)
        return dict(entry) if entry else None

    @property
    def quarantine_count(self) -> int:
        """Number of files currently in quarantine (status=quarantined)."""
        return len(self.list_entries(status=STATUS_QUARANTINED))

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _find_entry(manifest: dict, qid: str) -> Optional[dict]:
        """Return the manifest entry dict for a given QID (mutable reference)."""
        for entry in manifest.get("entries", []):
            if entry.get("qid") == qid:
                return entry
        return None
