"""
Writes a JSON report of all scan results, findings, attack paths, recommendations,
and — when --protect is used — active threats and correlated findings.
"""

import json
import datetime
import os


class JSONReporter:
    def __init__(
        self,
        prediction:          dict,
        findings:            list,
        recommendations:     dict,
        scan_results:        dict,
        protection_results:  dict = None,
        corr_results:        dict = None,
    ):
        self.prediction         = prediction
        self.findings           = findings
        self.recommendations    = recommendations
        self.scan_results       = scan_results
        self.protection_results = protection_results or {}
        self.corr_results       = corr_results       or {}

    def write(self, output_path: str) -> str:
        report = {
            "generated_at":   datetime.datetime.now().isoformat(),
            "tool":           "PredatorEye v1.0.0",
            "prediction":     self.prediction,
            "findings":       [f.to_dict() if hasattr(f, "to_dict") else f
                               for f in self.findings],
            "recommendations": self.recommendations,
            "raw_scan":       self.scan_results,
        }

        if self.protection_results:
            report["active_threats"] = self._summarise_protection()

        if self.corr_results.get("correlated_findings"):
            report["correlated_findings"] = {
                "summary":              self.corr_results.get("correlation_summary", ""),
                "total_correlations":   self.corr_results.get("total_correlations", 0),
                "rules_evaluated":      self.corr_results.get("rules_evaluated", 0),
                "findings":             self.corr_results.get("correlated_findings", []),
            }

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        return output_path

    def _summarise_protection(self) -> dict:
        pr = self.protection_results
        return {
            "scan_dirs":          pr.get("scan_dirs", []),
            "signature": {
                "detections":     len(pr.get("signature", {}).get("threats", [])),
                "scanned":        pr.get("signature", {}).get("scanned", 0),
                "threats":        pr.get("signature", {}).get("threats", []),
            },
            "yara": {
                "detections":     pr.get("yara", {}).get("detections", 0),
                "matches":        pr.get("yara", {}).get("matches", []),
            },
            "behavior": {
                "suspicious_processes": pr.get("behavior", {}).get("suspicious", 0),
                "scanned":              pr.get("behavior", {}).get("scanned", 0),
                "findings":             pr.get("behavior", {}).get("findings", []),
            },
            "persistence": {
                "is_baseline_run":  pr.get("persistence", {}).get("is_baseline_run", False),
                "total_changes":    pr.get("persistence", {}).get("total_changes", 0),
                "findings":         pr.get("persistence", {}).get("findings", []),
                "changes":          pr.get("persistence", {}).get("changes", {}),
            },
        }
