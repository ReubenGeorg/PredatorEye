"""
correlation/threat_correlator.py
===================================
Cross-reference engine that combines vulnerability assessment findings with
active threat detections to produce correlated, high-confidence alerts.

Academic rationale (for project report)
-----------------------------------------
A vulnerability assessment and an antivirus scanner each produce useful but
independent signals:

  - VA finds that PowerShell execution policy is Unrestricted.
    On its own: a configuration risk, not proof of attack.
  - AV detects a PowerShell process with a -EncodedCommand argument.
    On its own: suspicious but could be a legitimate admin script.

Together, the two observations tell a coherent attack story: an attacker
has identified and is actively exploiting the weak PowerShell policy.
The correlated severity is higher than either individual finding.

This is the foundational idea behind Security Information and Event
Management (SIEM) systems and Endpoint Detection and Response (EDR)
platforms — individual signals are weak; correlated signals are
actionable.  The six rules implemented here mirror the correlation logic
used in open-source SIEM rule sets (Sigma rules, Elastic Detection Rules).

Six correlation rules
----------------------
┌──┬──────────────────────────────────────────────────────┬─────────────────────┐
│# │ Rule                                                 │ MITRE               │
├──┼──────────────────────────────────────────────────────┼─────────────────────┤
│1 │ Credential Exposure + Active Credential Dump         │ T1003 + T1552       │
│2 │ Unpatched System + Active Exploit Drop               │ T1190 + T1203       │
│3 │ AV Disabled + Active Malware Detection               │ T1562.001           │
│4 │ PowerShell Policy Weak + Encoded Payload in Flight   │ T1059.001 + T1027   │
│5 │ Startup/Registry Weakness + New Persistence Entry    │ T1547.001           │
│6 │ Firewall Disabled + Active C2 Connections            │ T1071 + T1562.004   │
└──┴──────────────────────────────────────────────────────┴─────────────────────┘

Input contract
---------------
The correlator accepts:
  va_findings       : list of finding dicts (or Finding objects) from the VA
                      pipeline.  Expected keys: fid, title, description,
                      category, severity, details.
  protection_results: dict aggregating outputs from all protection engines:
    {
      "signature":   SignatureEngine.scan_directory() result dict,
      "yara":        YaraEngine.scan_directory() result dict,
      "behavior":    BehaviorMonitor.scan_processes() result dict,
      "persistence": PersistenceMonitor.scan() result dict,
      "file_watcher": {"detections": [event, ...]},  # from FileWatcher.get_detections()
    }
  Any key may be absent — missing engines are treated as "no detections".

Output contract
----------------
    {
      "correlated_findings": [correlated_finding_dict, ...],
      "total_correlations":  int,
      "correlation_summary": str,   # one-line human summary for report headers
      "rules_evaluated":     int,
    }

Each correlated_finding_dict::

    {
      "correlation_id":   "COR-001",
      "rule_name":        str,
      "title":            str,
      "description":      str,
      "severity":         str,          # always Critical or High
      "mitre_techniques": [str, ...],
      "mitre_tactic":     str,
      "evidence": {
        "va_findings":         [finding_dict, ...],
        "active_detections":   [detection_dict, ...],
      },
      "risk_amplification": str,        # why combined evidence is worse
      "recommendation":     str,
    }
"""

from typing import Any, Optional


# ── Finding accessor (handles both dict and object) ───────────────────────────

def _get(finding: Any, key: str, default: str = "") -> str:
    """
    Safely read a field from a finding that may be a dict or an object.

    The VA pipeline historically used Finding namedtuples/dataclasses in some
    versions and plain dicts in others.  This helper normalises both.
    """
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _finding_to_dict(finding: Any) -> dict:
    """Convert a Finding object to a plain dict for JSON-serialisable output."""
    if isinstance(finding, dict):
        return finding
    return {
        "fid":         getattr(finding, "fid",         ""),
        "title":       getattr(finding, "title",       ""),
        "description": getattr(finding, "description", ""),
        "category":    getattr(finding, "category",    ""),
        "severity":    getattr(finding, "severity",    ""),
        "details":     getattr(finding, "details",     {}),
    }


# ── Keyword matching helpers ──────────────────────────────────────────────────

def _va_matches_keywords(finding: Any, *keyword_groups: tuple) -> bool:
    """
    Return True if the finding's title, description, or category contains
    at least one keyword from every group.

    Calling _va_matches_keywords(f, ("password", "credential"), ("exposed", "stored"))
    requires the finding to contain BOTH a group-1 keyword AND a group-2 keyword.
    A single group acts as an OR across its keywords.
    """
    searchable = " ".join([
        _get(finding, "title").lower(),
        _get(finding, "description").lower(),
        _get(finding, "category").lower(),
    ])
    for group in keyword_groups:
        if not any(kw in searchable for kw in group):
            return False
    return True


def _yara_has_rule(yara_result: dict, *name_fragments: str) -> list:
    """
    Return YARA file matches where any triggered rule name contains one of
    the given fragments (case-insensitive).
    """
    hits = []
    for file_result in yara_result.get("matches", []):
        for m in file_result.get("matches", []):
            rule = m.get("rule_name", "").lower()
            if any(frag.lower() in rule for frag in name_fragments):
                hits.append({**m, "path": file_result.get("path", "")})
    return hits


def _behavior_has_rule(behavior_result: dict, *rule_names: str) -> list:
    """
    Return behavior proc_result entries where any triggered_rule name matches.
    """
    hits = []
    lower_names = {r.lower() for r in rule_names}
    for proc in behavior_result.get("findings", []):
        for rule in proc.get("triggered_rules", []):
            if rule.get("rule", "").lower() in lower_names:
                hits.append(proc)
                break
    return hits


def _behavior_has_technique(behavior_result: dict, *techniques: str) -> list:
    """
    Return behavior proc_result entries where any triggered_rule references
    one of the given MITRE technique IDs.
    """
    hits = []
    lower_techs = {t.lower() for t in techniques}
    for proc in behavior_result.get("findings", []):
        for rule in proc.get("triggered_rules", []):
            if rule.get("mitre_technique", "").lower() in lower_techs:
                hits.append(proc)
                break
    return hits


def _sig_has_threats(sig_result: dict) -> list:
    """Return all signature matches (matched=True entries)."""
    return sig_result.get("threats", [])


def _persistence_has_changes(pers_result: dict, change_type: str) -> list:
    """
    Return persistence findings whose category matches change_type.
    change_type: "registry" | "startup" | "tasks"
    """
    changes = pers_result.get("changes", {})
    section = changes.get(change_type, {})
    return section.get("added", []) + section.get("modified", [])


def _watcher_detections(watcher_result: dict) -> list:
    return watcher_result.get("detections", [])


# ── Correlated finding builder ────────────────────────────────────────────────

_corr_counter: list = [0]   # mutable counter avoids a global statement


def _make_correlated(
    rule_name:        str,
    title:            str,
    description:      str,
    severity:         str,
    mitre_techniques: list,
    mitre_tactic:     str,
    va_findings:      list,
    active_detections:list,
    risk_amplification: str,
    recommendation:   str,
) -> dict:
    _corr_counter[0] += 1
    cid = f"COR-{_corr_counter[0]:03d}"
    return {
        "correlation_id":    cid,
        "rule_name":         rule_name,
        "title":             title,
        "description":       description,
        "severity":          severity,
        "mitre_techniques":  mitre_techniques,
        "mitre_tactic":      mitre_tactic,
        "evidence": {
            "va_findings":       [_finding_to_dict(f) for f in va_findings],
            "active_detections": active_detections,
        },
        "risk_amplification": risk_amplification,
        "recommendation":    recommendation,
    }


# ── The six correlation rules ─────────────────────────────────────────────────

def _rule_credential_exposure_plus_dump(
    va_findings: list, protection: dict
) -> list:
    """
    Rule 1: Credential Exposure + Active Credential Dumping

    VA signal: finding about credentials stored insecurely, weak password
    policy, exposed NTLM hashes, or SAM/LSASS access.

    Protection signal: YARA matched Mimikatz strings, or behavioral heuristic
    detected a process with T1003-mapped technique.

    Why combined evidence is worse: an attacker has both the motivation
    (known-exposed credentials) AND an active tool to harvest them.
    The window of compromise is open RIGHT NOW.
    """
    # VA: credential-related findings
    va_hits = [
        f for f in va_findings
        if _va_matches_keywords(f,
            ("credential", "password", "ntlm", "hash", "sam", "lsass",
             "kerberos", "plaintext", "cleartext"))
    ]
    if not va_hits:
        return []

    # Protection: Mimikatz YARA match OR T1003 behavioral technique
    yara_hits = _yara_has_rule(
        protection.get("yara", {}),
        "credential", "mimikatz", "dcsync", "logonpassword",
    )
    behav_hits = _behavior_has_technique(
        protection.get("behavior", {}),
        "T1003",
    )
    active = yara_hits + behav_hits
    if not active:
        return []

    return [_make_correlated(
        rule_name         = "Credential_Exposure_Plus_Active_Dump",
        title             = "Active credential dumping on a system with exposed credentials",
        description       = (
            f"{len(va_hits)} vulnerability finding(s) indicate credentials are "
            f"stored or configured insecurely.  Simultaneously, {len(active)} "
            f"active detection(s) match known credential-dumping tool patterns "
            f"(e.g., Mimikatz sekurlsa / lsadump modules).  The attacker is "
            f"likely harvesting credentials right now."
        ),
        severity          = "Critical",
        mitre_techniques  = ["T1003", "T1552"],
        mitre_tactic      = "Credential Access",
        va_findings       = va_hits,
        active_detections = active,
        risk_amplification= (
            "Credential exposure (a static risk) combined with an in-flight "
            "credential-dumping tool confirms active exploitation.  Hashes "
            "exfiltrated now can be used for lateral movement (Pass-the-Hash) "
            "long after the initial tool is removed."
        ),
        recommendation    = (
            "1. Isolate the host from the network immediately.\n"
            "2. Quarantine the offending process using the Quarantine module.\n"
            "3. Rotate all domain and local account passwords.\n"
            "4. Enable Credential Guard / Protected Users group.\n"
            "5. Review VA findings for hardcoded or cached credentials."
        ),
    )]


def _rule_unpatched_plus_exploit_drop(
    va_findings: list, protection: dict
) -> list:
    """
    Rule 2: Unpatched System + Active Exploit Delivery

    VA signal: missing patches, outdated software versions, known CVEs.
    Protection signal: file watcher or signature engine detected a new
    executable dropped to Temp/Downloads/Desktop.

    Why combined evidence is worse: an attacker has identified an unpatched
    vulnerability AND is delivering a payload to exploit it.
    """
    va_hits = [
        f for f in va_findings
        if _va_matches_keywords(f,
            ("patch", "update", "outdated", "cve", "vulnerability",
             "unpatched", "old version", "end of life"))
    ]
    if not va_hits:
        return []

    # File watcher detections of dropped executables
    watcher_hits = [
        d for d in _watcher_detections(protection.get("file_watcher", {}))
        if d.get("severity") in ("Critical", "High", "Medium")
    ]
    # Signature matches (any matched=True file in a suspicious location)
    sig_hits = [
        t for t in _sig_has_threats(protection.get("signature", {}))
    ]
    # Behavior: execution from writable path (T1204)
    behav_hits = _behavior_has_rule(
        protection.get("behavior", {}),
        "Execution_From_Writable_Path",
    )

    active = watcher_hits + sig_hits + behav_hits
    if not active:
        return []

    return [_make_correlated(
        rule_name         = "Unpatched_System_Plus_Exploit_Drop",
        title             = "Exploit payload detected on an unpatched system",
        description       = (
            f"{len(va_hits)} VA finding(s) show unpatched or outdated software. "
            f"Concurrently, {len(active)} active detection(s) identified a "
            f"suspicious executable being dropped or executed.  This pattern "
            f"is consistent with targeted exploitation of a known vulnerability."
        ),
        severity          = "Critical",
        mitre_techniques  = ["T1190", "T1203"],
        mitre_tactic      = "Initial Access / Execution",
        va_findings       = va_hits,
        active_detections = active,
        risk_amplification= (
            "An unpatched CVE gives the attacker a known entry point.  A "
            "concurrent payload drop confirms they are actively using it.  "
            "Without patching, re-infection after remediation is trivial."
        ),
        recommendation    = (
            "1. Apply all outstanding patches immediately.\n"
            "2. Quarantine the dropped file via the Quarantine module.\n"
            "3. Identify the delivery vector (email attachment, browser download, "
            "   drive-by) and block it.\n"
            "4. Check for lateral movement — if the exploit succeeded, assume "
            "   the host is fully compromised."
        ),
    )]


def _rule_av_disabled_plus_malware(
    va_findings: list, protection: dict
) -> list:
    """
    Rule 3: AV Disabled + Active Malware Detection

    VA signal: Windows Defender disabled or no AV installed.
    Protection signal: any signature or YARA match (the AV that was supposed
    to catch this missed it because it was disabled).

    Why combined evidence is worse: the primary defence was removed, allowing
    malware to execute undetected.  This is often step 1 of a multi-stage
    attack (T1562.001 disables AV so later stages go undetected).
    """
    va_hits = [
        f for f in va_findings
        if _va_matches_keywords(f,
            ("antivirus", "defender", "real-time", "av disabled",
             "no antivirus", "protection disabled", "security center"))
        and _get(f, "severity") in ("Critical", "High")
    ]
    if not va_hits:
        return []

    sig_hits  = _sig_has_threats(protection.get("signature", {}))
    yara_hits = [
        r for r in protection.get("yara", {}).get("matches", [])
    ]
    active = sig_hits + yara_hits
    if not active:
        return []

    return [_make_correlated(
        rule_name         = "AV_Disabled_Plus_Active_Malware",
        title             = "Malware active on a system with antivirus disabled",
        description       = (
            f"AV is disabled or absent (flagged by {len(va_hits)} VA "
            f"finding(s)), and {len(active)} active malware detection(s) "
            f"were made by PredatorEye's signature/YARA engines.  Without "
            f"real-time protection, the malware has been running unhindered."
        ),
        severity          = "Critical",
        mitre_techniques  = ["T1562.001"],
        mitre_tactic      = "Defense Evasion",
        va_findings       = va_hits,
        active_detections = active,
        risk_amplification= (
            "Disabling AV is the attacker's first move precisely so subsequent "
            "malware stages are not caught.  The window between AV being turned "
            "off and this scan may represent unbounded dwell time."
        ),
        recommendation    = (
            "1. Re-enable Windows Defender / install a third-party AV.\n"
            "2. Run a full scan with PredatorEye's file scanner immediately.\n"
            "3. Quarantine all detected files.\n"
            "4. Investigate how AV was disabled — this action itself requires "
            "   administrator privilege and may indicate prior compromise."
        ),
    )]


def _rule_powershell_policy_plus_encoded(
    va_findings: list, protection: dict
) -> list:
    """
    Rule 4: PowerShell Execution Policy Weak + Encoded Payload in Flight

    VA signal: PowerShell ExecutionPolicy is Unrestricted, Bypass, or
    RemoteSigned in a permissive configuration.
    Protection signal: behavior monitor detected a PowerShell process with
    -EncodedCommand; or YARA matched an encoded-PowerShell script on disk.

    Why combined evidence is worse: a weak execution policy is necessary
    for unsigned/encoded scripts to run.  The attacker is exploiting the
    gap the policy creates.
    """
    va_hits = [
        f for f in va_findings
        if _va_matches_keywords(f,
            ("powershell", "execution policy", "unrestricted",
             "bypass", "remotesigned", "script execution"))
    ]
    if not va_hits:
        return []

    behav_hits = _behavior_has_rule(
        protection.get("behavior", {}),
        "PowerShell_EncodedCommand",
        "PowerShell_Hidden_Window",
        "PowerShell_ExecutionPolicy_Bypass",
    )
    yara_hits = _yara_has_rule(
        protection.get("yara", {}),
        "PowerShell_Encoded", "Evasion_PowerShell",
    )
    active = behav_hits + yara_hits
    if not active:
        return []

    return [_make_correlated(
        rule_name         = "PowerShell_Policy_Plus_Encoded_Payload",
        title             = "Encoded PowerShell payload exploiting a weak execution policy",
        description       = (
            f"{len(va_hits)} VA finding(s) show a permissive PowerShell "
            f"execution policy.  {len(active)} active detection(s) found a "
            f"PowerShell process or script using -EncodedCommand or hidden-window "
            f"flags — a pattern exclusively associated with malicious or "
            f"unauthorized code execution."
        ),
        severity          = "Critical",
        mitre_techniques  = ["T1059.001", "T1027"],
        mitre_tactic      = "Execution / Defense Evasion",
        va_findings       = va_hits,
        active_detections = active,
        risk_amplification= (
            "Base64-encoded PowerShell bypasses content inspection at the "
            "shell level.  Combined with a permissive policy, the attacker "
            "can run arbitrary unsigned code without any user prompt.  "
            "Encoded payloads are also harder to attribute post-incident."
        ),
        recommendation    = (
            "1. Set PowerShell ExecutionPolicy to AllSigned or Restricted.\n"
            "2. Enable PowerShell Script Block Logging (Event ID 4104) to "
            "   decode and audit what the payload did.\n"
            "3. Investigate the decoded payload — use CyberChef / From Base64.\n"
            "4. Enable AMSI (Antimalware Scan Interface) if disabled.\n"
            "5. Consider Constrained Language Mode for non-admin users."
        ),
    )]


def _rule_startup_weakness_plus_persistence(
    va_findings: list, protection: dict
) -> list:
    """
    Rule 5: Startup / Registry Weakness + New Persistence Entry

    VA signal: weak permissions on startup folders or Run keys, or a finding
    about autorun / boot persistence configuration.
    Protection signal: PersistenceMonitor detected a new Run key or startup
    file since the last baseline.

    Why combined evidence is worse: the attacker has written to the exact
    location the VA identified as misconfigured.
    """
    va_hits = [
        f for f in va_findings
        if _va_matches_keywords(f,
            ("startup", "run key", "autorun", "autostart", "persistence",
             "registry run", "boot", "logon", "current version\\run"))
    ]
    if not va_hits:
        return []

    reg_changes = _persistence_has_changes(
        protection.get("persistence", {}), "registry"
    )
    startup_changes = _persistence_has_changes(
        protection.get("persistence", {}), "startup"
    )
    active = reg_changes + startup_changes
    if not active:
        return []

    entry_count = len(active)
    return [_make_correlated(
        rule_name         = "Startup_Weakness_Plus_New_Persistence",
        title             = f"New persistence mechanism installed via a known-weak location",
        description       = (
            f"{len(va_hits)} VA finding(s) identified misconfigured startup "
            f"or autorun locations.  The PersistenceMonitor has since detected "
            f"{entry_count} new or modified persistence entry(ies) — the "
            f"attacker has used the misconfiguration to establish a foothold "
            f"that survives reboots."
        ),
        severity          = "Critical",
        mitre_techniques  = ["T1547.001"],
        mitre_tactic      = "Persistence",
        va_findings       = va_hits,
        active_detections = active,
        risk_amplification= (
            "Persistence means the threat actor regains access after each "
            "reboot, giving them unlimited time to escalate privileges or "
            "exfiltrate data.  Re-imaging without removing the persistence "
            "entry leads to immediate re-infection."
        ),
        recommendation    = (
            "1. Remove the identified Run key / startup file immediately.\n"
            "2. Use Autoruns (Sysinternals) to audit all persistence points.\n"
            "3. Harden Run key permissions (remove write access for non-admins).\n"
            "4. Reset the PersistenceMonitor baseline after cleanup.\n"
            "5. Check for additional persistence mechanisms (scheduled tasks, "
            "   services, WMI subscriptions)."
        ),
    )]


def _rule_firewall_disabled_plus_c2(
    va_findings: list, protection: dict
) -> list:
    """
    Rule 6: Firewall Disabled + Active C2 Connections

    VA signal: Windows Firewall is off for one or more profiles.
    Protection signal: BehaviorMonitor detected a process with an unusually
    high number of external outbound connections (T1071 indicator).

    Why combined evidence is worse: with the firewall off, there is no
    network-level control to block C2 egress, and the beaconing process
    confirms C2 activity is already underway.
    """
    va_hits = [
        f for f in va_findings
        if _va_matches_keywords(f,
            ("firewall", "network protection", "windows firewall",
             "domain profile", "private profile", "public profile",
             "inbound", "outbound", "network filter"))
        and _get(f, "severity") in ("Critical", "High")
    ]
    if not va_hits:
        return []

    behav_hits = _behavior_has_rule(
        protection.get("behavior", {}),
        "Excessive_Network_Connections",
    )
    if not behav_hits:
        return []

    # Summarise the most-connected process for the description
    top = max(behav_hits, key=lambda p: p.get("connections", 0))
    top_name = top.get("name", "unknown")
    top_conns = top.get("connections", 0)

    return [_make_correlated(
        rule_name         = "Firewall_Disabled_Plus_Active_C2",
        title             = "Suspected C2 beaconing with no firewall to block egress",
        description       = (
            f"{len(va_hits)} VA finding(s) show the Windows Firewall is "
            f"disabled for one or more network profiles.  The BehaviorMonitor "
            f"detected {len(behav_hits)} process(es) with excessive outbound "
            f"connections — the most active is '{top_name}' with {top_conns} "
            f"established external connections.  This is consistent with "
            f"command-and-control (C2) beaconing."
        ),
        severity          = "Critical",
        mitre_techniques  = ["T1071", "T1562.004"],
        mitre_tactic      = "Command and Control / Defense Evasion",
        va_findings       = va_hits,
        active_detections = behav_hits,
        risk_amplification= (
            "A disabled firewall removes the last network-level defence.  "
            "With C2 traffic flowing freely, the attacker can exfiltrate data, "
            "receive new payloads, and move laterally without any egress "
            "filtering to trigger alerts."
        ),
        recommendation    = (
            "1. Re-enable Windows Firewall on all profiles immediately.\n"
            "2. Capture a packet trace (Wireshark / netsh trace) to identify "
            "   C2 destination IPs and domains.\n"
            "3. Block the identified C2 endpoints at the network perimeter.\n"
            "4. Investigate the beaconing process — terminate and quarantine.\n"
            "5. Check for firewall policy via GPO that may re-disable it."
        ),
    )]


# ── All rules, in evaluation order ────────────────────────────────────────────

_ALL_RULES = [
    _rule_credential_exposure_plus_dump,
    _rule_unpatched_plus_exploit_drop,
    _rule_av_disabled_plus_malware,
    _rule_powershell_policy_plus_encoded,
    _rule_startup_weakness_plus_persistence,
    _rule_firewall_disabled_plus_c2,
]


# ── Main correlator class ──────────────────────────────────────────────────────

class ThreatCorrelator:
    """
    Cross-reference engine: combines VA findings with protection detections
    to generate correlated, high-confidence threat alerts.

    Each of the six rules independently checks whether a VA weakness AND a
    matching active detection are present simultaneously.  When both are,
    a correlated finding is emitted with actionable remediation guidance.

    The correlator is stateless and can be called any number of times with
    different inputs.

    Usage::

        corr = ThreatCorrelator()
        result = corr.correlate(
            va_findings       = risk_scorer.findings,
            protection_results = {
                "signature":   sig_engine.scan_directory(path),
                "yara":        yara_engine.scan_directory(path),
                "behavior":    monitor.scan_processes(),
                "persistence": persistence_monitor.scan(),
                "file_watcher": {"detections": watcher.get_detections()},
            }
        )

        for cf in result["correlated_findings"]:
            print(cf["severity"], cf["title"])
    """

    def correlate(
        self,
        va_findings:        list,
        protection_results: Optional[dict] = None,
    ) -> dict:
        """
        Evaluate all six correlation rules and return combined results.

        Args:
            va_findings:        List of finding dicts from the VA pipeline.
            protection_results: Dict of protection engine results.
                                Missing engines are treated as "no detections".

        Returns::

            {
                "correlated_findings": [correlated_finding_dict, ...],
                "total_correlations":  int,
                "correlation_summary": str,
                "rules_evaluated":     int,
            }
        """
        # Reset the counter for each correlate() call so IDs restart at COR-001
        _corr_counter[0] = 0

        protection = protection_results or {}
        va_list    = va_findings or []

        correlated: list = []

        for rule_fn in _ALL_RULES:
            try:
                hits = rule_fn(va_list, protection)
                correlated.extend(hits)
            except Exception:
                # A broken correlation rule must not silence all other rules
                pass

        total = len(correlated)

        if total == 0:
            summary = (
                "No correlations found — VA findings and active detections "
                "do not overlap at this time."
            )
        elif total == 1:
            summary = (
                f"1 correlated finding ({correlated[0]['severity']}): "
                f"{correlated[0]['title']}"
            )
        else:
            severities = [cf["severity"] for cf in correlated]
            critical_n = severities.count("Critical")
            high_n     = severities.count("High")
            summary    = (
                f"{total} correlated findings: "
                f"{critical_n} Critical, {high_n} High — "
                "active exploitation confirmed by cross-engine evidence."
            )

        return {
            "correlated_findings": correlated,
            "total_correlations":  total,
            "correlation_summary": summary,
            "rules_evaluated":     len(_ALL_RULES),
        }
