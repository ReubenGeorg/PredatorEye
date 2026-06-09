"""
Synthesises findings and attack paths into a prioritised prediction summary.
Assigns each attack path a confidence tier and an overall system risk level.
"""

from config import SEVERITY_SCORES


class PathPredictor:
    def __init__(self, findings: list, attack_paths: list):
        self.findings = findings
        self.attack_paths = attack_paths

    def predict(self) -> dict:
        overall_score = self._overall_risk_score()
        risk_level, risk_color = self._risk_level(overall_score)
        top_paths = self._top_paths()
        critical_findings = [f for f in self.findings if f.severity == "Critical"]
        high_findings = [f for f in self.findings if f.severity == "High"]
        stats = self._stats()

        return {
            "overall_score": overall_score,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "top_attack_paths": [p.to_dict() for p in top_paths],
            "critical_count": len(critical_findings),
            "high_count": len(high_findings),
            "medium_count": len([f for f in self.findings if f.severity == "Medium"]),
            "low_count": len([f for f in self.findings if f.severity == "Low"]),
            "total_findings": len(self.findings),
            "total_attack_paths": len(self.attack_paths),
            "stats": stats,
            "most_likely_attacker": self._most_likely_attacker(top_paths),
        }

    # ------------------------------------------------------------------
    def _overall_risk_score(self) -> float:
        if not self.findings:
            return 0.0
        # Weighted: criticals count 4x, highs 2x, mediums 1x
        weights = {"Critical": 4, "High": 2, "Medium": 1, "Low": 0.5, "Info": 0}
        total = sum(weights.get(f.severity, 0) * f.score for f in self.findings)
        # Normalise to 0–100
        max_possible = len(self.findings) * 4 * 10
        normalised = (total / max_possible) * 100 if max_possible else 0
        # Cap and round
        return round(min(normalised, 100), 1)

    def _risk_level(self, score: float) -> tuple:
        if score >= 70:
            return "Critical", "#c0392b"
        if score >= 50:
            return "High", "#e67e22"
        if score >= 25:
            return "Medium", "#f1c40f"
        if score > 0:
            return "Low", "#2ecc71"
        return "Minimal", "#27ae60"

    def _top_paths(self) -> list:
        return sorted(self.attack_paths, key=lambda p: p.risk_score, reverse=True)[:5]

    def _stats(self) -> dict:
        categories = {}
        for f in self.findings:
            categories[f.category] = categories.get(f.category, 0) + 1
        return {
            "findings_by_category": categories,
            "findings_by_severity": {
                sev: len([f for f in self.findings if f.severity == sev])
                for sev in ("Critical", "High", "Medium", "Low", "Info")
            },
        }

    def _most_likely_attacker(self, top_paths: list) -> dict:
        if not top_paths:
            return {"profile": "Unknown", "motivation": "Unknown", "techniques": []}

        top = top_paths[0]
        name = top.name.lower()

        if "ransomware" in name:
            return {
                "profile": "Ransomware Operator / Cybercriminal",
                "motivation": "Financial — ransom payment",
                "techniques": ["EternalBlue (MS17-010)", "Lateral SMB movement", "Payload deployment", "Shadow copy deletion"],
            }
        if "rdp" in name or "brute" in name:
            return {
                "profile": "Remote Access Threat Actor",
                "motivation": "Persistent access / data theft / ransomware staging",
                "techniques": ["Credential brute-force", "RDP session hijacking", "Keylogging", "Lateral movement"],
            }
        if "credential" in name:
            return {
                "profile": "Credential Thief / Insider Threat",
                "motivation": "Account takeover / data theft / corporate espionage",
                "techniques": ["Credential dumping", "Pass-the-Hash", "Token impersonation"],
            }
        if "lateral" in name:
            return {
                "profile": "APT / Nation-State Actor",
                "motivation": "Long-term access / intelligence gathering",
                "techniques": ["NTLM relay", "Lateral movement", "Persistence via WMI", "Living-off-the-land"],
            }
        return {
            "profile": "Opportunistic Attacker",
            "motivation": "Exploitation of easy vulnerabilities",
            "techniques": ["Vulnerability scanning", "Exploit known CVEs", "Default credential attacks"],
        }
