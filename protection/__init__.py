"""
protection/
===========
PredatorEye's active protection stack — a three-layer malware detection
engine that complements the existing vulnerability assessment pipeline.

Layers
------
1. SignatureEngine    — exact hash lookup (MD5 + SHA256)
2. YaraEngine         — pattern/rule-based matching  [module 2]
3. BehaviorMonitor    — runtime heuristics via psutil [module 3]

Supporting components
---------------------
FileWatcher          — real-time drop-folder monitoring   [module 4]
Quarantine           — safe isolation + manifest + restore [module 5]
PersistenceMonitor   — registry / startup delta detection  [module 6]
"""

from .signature_engine import SignatureEngine, SignatureDB
from .yara_engine import YaraEngine
from .behavior_monitor import BehaviorMonitor
from .file_watcher import FileWatcher, WATCH_EXTENSIONS
from .quarantine import Quarantine, STATUS_QUARANTINED, STATUS_RESTORED, STATUS_DELETED
from .persistence_monitor import PersistenceMonitor

__all__ = [
    "SignatureEngine",
    "SignatureDB",
    "YaraEngine",
    "BehaviorMonitor",
    "FileWatcher",
    "WATCH_EXTENSIONS",
    "Quarantine",
    "STATUS_QUARANTINED",
    "STATUS_RESTORED",
    "STATUS_DELETED",
    "PersistenceMonitor",
]
