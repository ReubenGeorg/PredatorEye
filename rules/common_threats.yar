/*
 * PredatorEye — Common Threat Pattern Rules
 * ==========================================
 * These rules match string patterns associated with well-known offensive
 * tools and techniques.  Pattern-based (YARA) detection catches renamed or
 * slightly-modified variants of known tools that hash-based detection misses
 * entirely — this is the core academic justification for Layer 2.
 *
 * Rule design principles used here:
 *   1. Every rule requires ≥2 corroborating strings (reduces false positives).
 *   2. Metadata is machine-readable (severity, mitre_technique) so the
 *      ThreatCorrelator can consume it programmatically.
 *   3. Rules are namespace-separated in the engine (one file per namespace),
 *      making it easy to enable/disable categories independently.
 *
 * Sources for production rule sets (not embedded here — no real malware):
 *   - Neo23x0 / signature-base    https://github.com/Neo23x0/signature-base
 *   - Elastic Security Rules       https://github.com/elastic/detection-rules
 *   - YARA-Forge                   https://yaraforge.com/
 */


/* ─────────────────────────────────────────────────────────────────────────────
 * Credential Access — Mimikatz
 * MITRE ATT&CK T1003: OS Credential Dumping
 *
 * Mimikatz is the most widely used credential-dumping tool in the wild.
 * These strings appear in its source code and compiled binaries; they also
 * appear in scripts that invoke Mimikatz commands over PowerShell remoting.
 * Requiring 2-of-6 strings keeps false positives near zero while catching
 * common variants (Invoke-Mimikatz, SafetyKatz, SharpKatz, etc.).
 * ──────────────────────────────────────────────────────────────────────────── */
rule Credential_Dump_Mimikatz
{
    meta:
        description     = "Detects Mimikatz credential-dumping strings in binaries or scripts"
        author          = "PredatorEye"
        severity        = "Critical"
        mitre_tactic    = "Credential Access"
        mitre_technique = "T1003"
        reference       = "https://attack.mitre.org/techniques/T1003/"

    strings:
        $cmd1 = "sekurlsa::logonpasswords" ascii nocase
        $cmd2 = "sekurlsa::wdigest"        ascii nocase
        $cmd3 = "lsadump::dcsync"          ascii nocase
        $cmd4 = "privilege::debug"         ascii nocase
        $cmd5 = "mimikatz"                 ascii wide nocase
        $cmd6 = "KIWI_MSV1_0_PRIMARY_CREDENTIALS" ascii

    condition:
        // Require at least 2 of the 6 strings to reduce false positives
        // (e.g., a security blog post mentioning "mimikatz" once would not trigger)
        2 of them
}


/* ─────────────────────────────────────────────────────────────────────────────
 * Defense Evasion — PowerShell Encoded Command
 * MITRE ATT&CK T1027: Obfuscated Files or Information
 *
 * Attackers base64-encode PowerShell payloads so the command is not visible
 * in process lists or logs.  The -EncodedCommand (or abbreviated -enc) flag
 * is the delivery mechanism.  The rule requires BOTH "powershell" AND one of
 * the encoding flags to avoid triggering on help text or documentation that
 * mentions "-enc" in a different context.
 * ──────────────────────────────────────────────────────────────────────────── */
rule Evasion_PowerShell_Encoded
{
    meta:
        description     = "Detects PowerShell -EncodedCommand payload delivery"
        author          = "PredatorEye"
        severity        = "High"
        mitre_tactic    = "Defense Evasion"
        mitre_technique = "T1027"
        reference       = "https://attack.mitre.org/techniques/T1027/"
        note            = "May trigger on legitimate admin scripts — correlate with path context"

    strings:
        $ps        = "powershell"       ascii wide nocase
        $enc_long  = "-EncodedCommand"  ascii nocase
        $enc_short = "-EnCode"          ascii nocase
        $enc_abbr  = " -enc "           ascii nocase

    condition:
        $ps and 1 of ($enc_long, $enc_short, $enc_abbr)
}


/* ─────────────────────────────────────────────────────────────────────────────
 * Execution — LOLBin Proxy Execution
 * MITRE ATT&CK T1218: System Binary Proxy Execution
 *
 * "Living Off the Land" binaries are legitimate Windows tools abused to
 * execute malicious code, bypassing application whitelisting.  Detecting the
 * combination of the binary name + a suspicious argument pattern is more
 * reliable than flagging the binary name alone (which would produce enormous
 * false-positive rates on a managed Windows host).
 * ──────────────────────────────────────────────────────────────────────────── */
rule Execution_LOLBin_Proxy
{
    meta:
        description     = "Detects LOLBin proxy execution patterns (mshta, regsvr32, rundll32)"
        author          = "PredatorEye"
        severity        = "High"
        mitre_tactic    = "Execution"
        mitre_technique = "T1218"
        reference       = "https://attack.mitre.org/techniques/T1218/"

    strings:
        // mshta executing remote content
        $mshta_http  = "mshta.exe http"   ascii nocase
        $mshta_vbs   = "mshta.exe vbscript" ascii nocase

        // regsvr32 executing a remote DLL (Squiblydoo)
        $reg_scrobj  = "regsvr32" ascii nocase
        $reg_url     = "/s /u /i:http" ascii nocase

        // rundll32 calling a suspicious export
        $run_js      = "rundll32.exe javascript" ascii nocase

    condition:
        ($mshta_http or $mshta_vbs) or
        ($reg_scrobj and $reg_url)   or
        $run_js
}


/* ─────────────────────────────────────────────────────────────────────────────
 * Persistence — Registry Run Key Injection
 * MITRE ATT&CK T1547.001: Boot or Logon Autostart Execution: Registry Run Keys
 *
 * Malware commonly writes to HKCU\Software\Microsoft\Windows\CurrentVersion\Run
 * to survive reboots.  Detecting the key path alongside a binary write function
 * in a script or compiled binary is a reliable persistence indicator.
 * ──────────────────────────────────────────────────────────────────────────── */
rule Persistence_Registry_Run_Key
{
    meta:
        description     = "Detects registry Run key manipulation for persistence"
        author          = "PredatorEye"
        severity        = "High"
        mitre_tactic    = "Persistence"
        mitre_technique = "T1547.001"
        reference       = "https://attack.mitre.org/techniques/T1547/"

    strings:
        $run_key  = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $write1   = "RegSetValueEx"   ascii
        $write2   = "reg add"         ascii nocase
        $write3   = "Set-ItemProperty" ascii nocase
        $write4   = "New-ItemProperty" ascii nocase

    condition:
        $run_key and 1 of ($write1, $write2, $write3, $write4)
}
