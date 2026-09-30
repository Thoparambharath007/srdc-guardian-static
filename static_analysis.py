"""
static_analysis.py
Instant checks that run without executing the file:
  - Magic byte check  (is extension lying?)
  - VirusTotal hash lookup
  - Entropy check     (hidden encrypted payload?)
  - File size anomaly
  - YARA scan         (known bad patterns)
"""

import os
import math
import hashlib
import requests
from collections import Counter

from config import VT_API_KEY, ENTROPY_THRESHOLD

# ─── MAGIC BYTES ─────────────────────────────────────────────────────────────

_MAGIC = {
    b"\x4d\x5a":               "exe",      # MZ  → PE executable
    b"\x7f\x45\x4c\x46":       "elf",      # ELF → Linux binary
    b"\x25\x50\x44\x46":       "pdf",      # %PDF
    b"\x50\x4b\x03\x04":       "zip",      # PK  → ZIP/docx/xlsx/jar
    b"\xd0\xcf\x11\xe0":       "ole",      # OLE → doc/xls/ppt (old Office)
    b"\x52\x61\x72\x21":       "rar",      # Rar!
    b"\x1f\x8b":               "gz",       # gzip
    b"\x37\x7a\xbc\xaf":       "7z",       # 7-Zip
    b"\xca\xfe\xba\xbe":       "class",    # Java class
    b"\xff\xfb":               "mp3",
    b"\x49\x44\x33":           "mp3",      # ID3
    b"\xff\xd8\xff":           "jpg",
    b"\x89\x50\x4e\x47":       "png",
    b"\x47\x49\x46\x38":       "gif",
}

_EXPECTED_EXTS = {
    "exe":   {".exe", ".dll", ".scr", ".com", ".sys", ".drv"},
    "elf":   {".elf", ".so", ""},
    "pdf":   {".pdf"},
    "zip":   {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt"},
    "ole":   {".doc", ".xls", ".ppt", ".msg"},
    "rar":   {".rar"},
    "gz":    {".gz", ".tgz"},
    "7z":    {".7z"},
    "class": {".class", ".jar"},
    "mp3":   {".mp3"},
    "jpg":   {".jpg", ".jpeg"},
    "png":   {".png"},
    "gif":   {".gif"},
}


def check_magic_bytes(file_path: str) -> dict:
    """
    Returns:
      { "real_type": str, "extension_ok": bool, "flag": bool, "detail": str }
    """
    ext = os.path.splitext(file_path)[1].lower()
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)
    except Exception:
        return {"real_type": "unknown", "extension_ok": True, "flag": False,
                "detail": "could not read file"}

    real_type = "unknown"
    for magic, ftype in _MAGIC.items():
        if header.startswith(magic):
            real_type = ftype
            break

    expected = _EXPECTED_EXTS.get(real_type, set())
    ext_ok   = (real_type == "unknown") or (ext in expected)
    flag     = not ext_ok

    detail = ""
    if flag:
        detail = (f"Extension '{ext}' does not match detected type '{real_type}'. "
                  "Possible double-extension or disguised executable.")

    return {"real_type": real_type, "extension_ok": ext_ok,
            "flag": flag, "detail": detail}


# ─── HASH ─────────────────────────────────────────────────────────────────────

def compute_hashes(file_path: str) -> dict:
    md5  = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    except Exception:
        # Returning the digest of *empty input* here would be indistinguishable
        # from a genuinely empty file and gets shipped to VirusTotal, which has
        # a real record for the empty hash — silently producing a false "clean"
        # signal. Empty strings let the caller know hashing failed.
        return {"md5": "", "sha1": "", "sha256": ""}
    return {
        "md5":    md5.hexdigest(),
        "sha1":   sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


# ─── VIRUSTOTAL ───────────────────────────────────────────────────────────────

def virustotal_lookup(sha256: str) -> dict:
    """
    Returns { "vt_flag": bool, "positives": int, "total": int, "detail": str }
    """
    if not VT_API_KEY or VT_API_KEY == "PASTE_YOUR_VT_API_KEY_HERE":
        return {"vt_flag": False, "positives": 0, "total": 0,
                "detail": "VT API key not configured"}
    if not sha256:
        return {"vt_flag": False, "positives": 0, "total": 0,
                "detail": "File could not be read for hashing (VirusTotal lookup skipped)"}
    url     = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return {"vt_flag": False, "positives": 0, "total": 0,
                    "detail": "Hash not found in VirusTotal database (new file)"}
        if resp.status_code in (401, 403):
            return {"vt_flag": False, "positives": 0, "total": 0,
                    "detail": "VirusTotal rejected the API key (401/403) — it may be "
                              "expired or invalid; check Settings. Local analysis still ran."}
        if resp.status_code == 429:
            return {"vt_flag": False, "positives": 0, "total": 0,
                    "detail": "VirusTotal rate limit reached — try again in a minute."}
        resp.raise_for_status()
        stats    = resp.json()["data"]["attributes"]["last_analysis_stats"]
        pos      = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total    = sum(stats.values())
        flag     = pos > 0
        detail   = f"{pos}/{total} engines flagged this file" if flag else "Clean"
        return {"vt_flag": flag, "positives": pos, "total": total, "detail": detail}
    except Exception as e:
        return {"vt_flag": False, "positives": 0, "total": 0,
                "detail": f"VT lookup error: {e}"}


# ─── ENTROPY ─────────────────────────────────────────────────────────────────

# Formats that are compressed or encoded by design — their bytes are near-
# random, so high entropy is EXPECTED and is not a malicious signal.
_HIGH_ENTROPY_EXPECTED_EXTS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".jar", ".apk", ".ipa",
    ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".webm", ".flac",
    ".docx", ".xlsx", ".pptx", ".odt", ".odp",
    ".pdf",
}


def compute_entropy(file_path: str) -> dict:
    """Shannon entropy of file bytes. >7.2 suggests encrypted/compressed payload
    — but only for formats where that is NOT expected (e.g. .exe, .txt, .dll)."""
    ext = os.path.splitext(file_path)[1].lower()

    # C-speed byte counting (collections.Counter) — orders of magnitude
    # faster than a Python per-byte loop on large files.
    counts = Counter()
    size   = 0
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                size += len(chunk)
                counts.update(chunk)
    except Exception:
        return {"entropy": 0.0, "flag": False, "detail": "could not read file"}

    if size == 0:
        return {"entropy": 0.0, "flag": False, "detail": "empty file"}

    entropy = 0.0
    for count in counts.values():
        if count:
            p = count / size
            entropy -= p * math.log2(p)

    high = entropy >= ENTROPY_THRESHOLD
    expected = ext in _HIGH_ENTROPY_EXPECTED_EXTS
    flag = high and not expected

    if high and expected:
        detail = f"Entropy {entropy:.2f} — normal for compressed {ext} format"
    elif flag:
        detail = f"Entropy {entropy:.2f} — possible encrypted/hidden payload"
    else:
        detail = f"Entropy {entropy:.2f} — normal"

    return {"entropy": round(entropy, 2), "flag": flag, "detail": detail}


# ─── SIZE ANOMALY ─────────────────────────────────────────────────────────────

# Rough expected max sizes in bytes for common types
_EXPECTED_MAX_SIZE = {
    ".jpg":  15 * 1024 * 1024,   # 15 MB
    ".jpeg": 15 * 1024 * 1024,
    ".png":  20 * 1024 * 1024,
    ".gif":   5 * 1024 * 1024,
    ".mp3":  20 * 1024 * 1024,
    ".json":  5 * 1024 * 1024,
    ".txt":   2 * 1024 * 1024,
    ".xml":  10 * 1024 * 1024,
}


def check_size_anomaly(file_path: str) -> dict:
    ext      = os.path.splitext(file_path)[1].lower()
    max_size = _EXPECTED_MAX_SIZE.get(ext)
    try:
        size = os.path.getsize(file_path)
    except Exception:
        return {"flag": False, "size_bytes": 0, "detail": "could not stat file"}

    if max_size is None:
        return {"flag": False, "size_bytes": size, "detail": "No size baseline for this type"}

    flag   = size > max_size
    detail = (f"File {size//1024} KB — unusually large for '{ext}' (max ~{max_size//1024} KB)"
              if flag else f"File size {size//1024} KB — normal")
    return {"flag": flag, "size_bytes": size, "detail": detail}


# ─── YARA ────────────────────────────────────────────────────────────────────

# Compiled rules are cached at module level — recompiling them on every scan
# is wasteful. "IMPORT_ERROR" means yara-python is missing; None means no rules.
_YARA_RULES = None
_YARA_RULES_TRIED = False


def _load_yara_rules():
    """Compile the YARA rules once and cache the result for reuse."""
    global _YARA_RULES, _YARA_RULES_TRIED
    if _YARA_RULES_TRIED:
        return _YARA_RULES
    _YARA_RULES_TRIED = True
    try:
        import yara
        import glob
        rule_files = glob.glob(
            os.path.join(os.path.dirname(__file__), "yara_rules", "*.yar"))
        if rule_files:
            _YARA_RULES = yara.compile(
                filepaths={str(i): p for i, p in enumerate(rule_files)})
    except ImportError:
        _YARA_RULES = "IMPORT_ERROR"
    except Exception:
        _YARA_RULES = None
    return _YARA_RULES


def yara_scan(file_path: str) -> dict:
    """
    Scan with YARA rules from yara_rules/ folder.
    Returns { "flag": bool, "matches": list[str], "detail": str }
    """
    rules = _load_yara_rules()
    if rules == "IMPORT_ERROR":
        return {"flag": False, "matches": [],
                "detail": "yara-python not installed — skipping YARA scan"}
    if rules is None:
        return {"flag": False, "matches": [], "detail": "No YARA rule files found"}
    try:
        matches = rules.match(file_path)
        names   = [m.rule for m in matches]
        flag    = len(names) > 0
        detail  = f"YARA matched: {', '.join(names)}" if flag else "No YARA matches"
        return {"flag": flag, "matches": names, "detail": detail}
    except Exception as e:
        return {"flag": False, "matches": [], "detail": f"YARA error: {e}"}


# ─── DIGITAL SIGNATURE (Authenticode) ────────────────────────────────────────
# When VirusTotal has never seen a file ("new file"), a valid Authenticode
# signature from a trusted publisher is the strongest remaining trust signal.

_SIGNABLE_EXTS = {".exe", ".dll", ".sys", ".msi", ".scr", ".com", ".ocx", ".cab", ".jar"}


def check_digital_signature(file_path: str) -> dict:
    """
    Verify the Authenticode signature of a file (via PowerShell's
    Get-AuthenticodeSignature, which uses the OS trust store).
    Returns { "applicable", "signed", "trusted", "signer", "detail" }
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in _SIGNABLE_EXTS:
        return {"applicable": False, "signed": False, "trusted": False,
                "signer": "", "detail": "not applicable for this file type"}

    try:
        import subprocess
        script = (
            "$s = Get-AuthenticodeSignature -LiteralPath '{p}'; "
            "$n = ''; "
            "if ($s.SignerCertificate) {{ $n = $s.SignerCertificate.Subject }}; "
            "Write-Output ($s.Status.ToString() + '|' + $n)"
        ).format(p=file_path.replace("'", "''"))

        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        lines = [l for l in (out.stdout or "").strip().splitlines() if l.strip()]
        if not lines:
            raise RuntimeError(out.stderr.strip() or "no output")
        status, _, subject = lines[-1].partition("|")
        status  = status.strip()
        subject = subject.strip()

        signer = ""
        if "CN=" in subject:
            signer = subject.split("CN=")[1].split(",")[0].strip()

        if status == "Valid":
            return {"applicable": True, "signed": True, "trusted": True,
                    "signer": signer or subject,
                    "detail": f"Valid — signed by {signer or subject}"}
        if status in ("NotSigned", "UnknownError"):
            return {"applicable": True, "signed": False, "trusted": False,
                    "signer": "",
                    "detail": "No digital signature" if status == "NotSigned"
                              else "No valid signature (corrupt or non-standard file)"}
        return {"applicable": True, "signed": True, "trusted": False,
                "signer": "", "detail": f"{status} signature"}
    except Exception as e:
        return {"applicable": True, "signed": False, "trusted": False,
                "signer": "", "detail": f"signature check failed: {e}"}


# ─── COMBINED RUNNER ─────────────────────────────────────────────────────────

def run_all(file_path: str) -> dict:
    """Run all static checks and return combined results."""
    hashes  = compute_hashes(file_path)
    magic   = check_magic_bytes(file_path)
    vt      = virustotal_lookup(hashes["sha256"])
    entropy = compute_entropy(file_path)
    size    = check_size_anomaly(file_path)
    yara_r  = yara_scan(file_path)
    sig     = check_digital_signature(file_path)

    any_flag = magic["flag"] or vt["vt_flag"] or entropy["flag"] or \
               size["flag"] or yara_r["flag"]

    return {
        "hashes":    hashes,
        "magic":     magic,
        "vt":        vt,
        "entropy":   entropy,
        "size":      size,
        "yara":      yara_r,
        "signature": sig,
        "any_flag":  any_flag,
    }
