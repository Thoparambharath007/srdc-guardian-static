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
        description = "Generic crypto-ransomware behavior strings"
        severity    = "medium"
    strings:
        $a1 = "bitcoin" nocase
        $a2 = "decrypt" nocase
        $a3 = "encrypt" nocase wide ascii
        $a4 = "CryptoWall" nocase
        $a5 = "TeslaCrypt" nocase
        $a6 = "Cerber" nocase
        $a7 = "Ryuk" nocase
        $b1 = "AES-256" nocase
        $b2 = "RSA-2048" nocase
        $b3 = "CryptEncrypt" nocase
        $b4 = "CryptGenKey" nocase
    condition:
        (2 of ($a*)) or (2 of ($b*)) or (1 of ($a*) and 1 of ($b*))
}

rule suspicious_base64_in_json
{
    meta:
        description = "Suspiciously long base64 blob in JSON/text file"
        severity    = "low"
    strings:
        // 100+ char base64 string
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
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
