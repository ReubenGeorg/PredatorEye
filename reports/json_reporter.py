"""
Writes a JSON report of all scan results, findings, attack paths, and recommendations.
"""

import json
import datetime
import os


class JSONReporter:
    def __init__(self, prediction: dict, findings: list, recommendations: dict, scan_results: dict):
        self.prediction = prediction
        self.findings = findings
        self.recommendations = recommendations
        self.scan_results = scan_results

    def write(self, output_path: str) -> str:
        report = {
            "generated_at": datetime.datetime.now().isoformat(),
            "tool": "AttackPath v1.0.0",
            "prediction": self.prediction,
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": self.recommendations,
            "raw_scan": self.scan_results,
        }
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        return output_path
