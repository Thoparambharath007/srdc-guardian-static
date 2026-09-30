/*
  basic_rules.yar
  Basic YARA signatures for common ransomware indicators.
  Add more rules as needed.
*/

rule ransomware_extension_list
{
    meta:
        description = "Common ransomware target extension lists"
        severity    = "high"
    strings:
        $ext1 = ".docx.encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $ext4 = "HOW_TO_DECRYPT" nocase
        $ext5 = "DECRYPT_INSTRUCTIONS" nocase
        $ext6 = "README_FOR_DECRYPT" nocase
        $ext7 = "RANSOM_NOTE" nocase
    condition:
        any of them
}

rule wannacry_indicator
{
    meta:
        description = "WannaCry ransomware indicators"
        severity    = "critical"
    strings:
        $s1 = "WannaDecryptor" nocase
        $s2 = "WANNACRY" nocase
        $s3 = "wncry" nocase
        $s4 = "tasksche.exe" nocase
        $s5 = "@WanaDecryptor@" nocase
    condition:
        2 of them
}

rule locky_indicator
{
    meta:
        description = "Locky ransomware indicators"
        severity    = "critical"
    strings:
        $s1 = "_HELP_instructions" nocase
        $s2 = ".locky" nocase
        $s3 = "locky" nocase
    condition:
        2 of them
}

rule crypto_ransom_generic
{
    meta:
        description = "Crypto-ransomware: known family names, or a ransom note combined with Windows crypto APIs"
        severity    = "high"
    strings:
        // High-signal: known ransomware family / product names
        $fam1 = "CryptoWall" nocase
        $fam2 = "TeslaCrypt" nocase
        $fam3 = "Cerber" nocase
        $fam4 = "Ryuk" nocase
        $fam5 = "CryptoLocker" nocase
        $fam6 = "WannaCry" nocase
        // Ransom-note indicators (only count when a crypto API is also present)
        $note1 = "your files have been encrypted" nocase
        $note2 = "your files are encrypted" nocase
        $note3 = "to decrypt" nocase
        $note4 = "decrypt your files" nocase
        // Windows cryptographic APIs commonly used by crypto-ransomware
        $api1 = "CryptEncrypt" nocase
        $api2 = "CryptGenKey" nocase
        $api3 = "CryptDeriveKey" nocase
        $api4 = "CryptAcquireContext" nocase
        $api5 = "CryptImportKey" nocase
    condition:
        any of ($fam*) or (1 of ($note*) and 1 of ($api*))
}

rule suspicious_base64_in_json
{
    meta:
        description = "Suspiciously long base64 blob in JSON/text file"
        severity    = "low"
    strings:
        // 500+ char base64 blob. (A 100+ char threshold was far too noisy — it
        // fired on legitimate binaries, embedded certificates and resources.)
        $b64 = /[A-Za-z0-9+\/]{500,}={0,2}/
    condition:
        $b64
}

rule double_extension_exe
{
    meta:
        description = "Possible double-extension executable"
        severity    = "high"
    strings:
        $pe = { 4D 5A }          // MZ header
        $ext1 = ".pdf.exe" nocase
        $ext2 = ".doc.exe" nocase
        $ext3 = ".jpg.exe" nocase
        $ext4 = ".mp3.exe" nocase
        $ext5 = ".txt.exe" nocase
    condition:
        $pe at 0 and any of ($ext*)
}
