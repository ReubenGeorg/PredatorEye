/*
 * EICAR Anti-Malware Test File Detector
 * ========================================
 * The EICAR test string is a safe, industry-standard string that every
 * antivirus product is required to detect as a validation mechanism.
 * It contains no executable code and poses no security risk.
 *
 * This rule exists solely to verify that the PredatorEye YARA engine
 * can successfully compile rules, match strings in a target file, and
 * return metadata — without needing real malware samples.
 *
 * Reference : https://www.eicar.org/download-anti-malware-testfile/
 * SHA256    : 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
 * MD5       : 44d88612fea8a8f36de82e1278abb02f
 */

rule EICAR_Test_File
{
    meta:
        description     = "Detects the EICAR standard antivirus test file"
        author          = "PredatorEye"
        severity        = "Info"
        mitre_tactic    = "N/A — validation rule only, not a real threat"
        reference       = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        // The canonical marker present in every EICAR test file variant.
        // Matching the marker string (not the whole content) means this rule
        // also catches EICAR-based variants (e.g., EICAR embedded in a ZIP).
        $eicar_marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

    condition:
        $eicar_marker
}
