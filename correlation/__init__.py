"""
correlation/
=============
Cross-references vulnerability assessment findings from the existing
PredatorEye VA pipeline with active threat detections from the protection/
stack, producing correlated findings that have significantly higher
evidential weight than either source alone.
"""

from .threat_correlator import ThreatCorrelator

__all__ = ["ThreatCorrelator"]
