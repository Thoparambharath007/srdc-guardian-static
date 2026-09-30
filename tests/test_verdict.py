"""
test_verdict.py
Unit tests for the verdict engine (verdict.py).

Run with either:
    python -m pytest tests/ -v
or, without pytest installed (e.g. the project venv):
    python tests/test_verdict.py
"""

import os
import sys

# Make the project root importable when run as a plain script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import verdict


def base(**over):
    """A fully-clean static-analysis result; override sub-dicts with keyword args."""
    d = {
        "hashes":    {"md5": "", "sha1": "", "sha256": ""},
        "magic":     {"real_type": "exe", "extension_ok": True,
                      "flag": False, "detail": ""},
        "vt":        {"vt_flag": False, "positives": 0, "total": 0,
                      "detail": "VT API key not configured"},
        "entropy":   {"entropy": 4.5, "flag": False, "detail": "normal"},
        "size":      {"flag": False, "size_bytes": 1024, "detail": "normal"},
        "yara":      {"flag": False, "matches": [], "detail": "No YARA matches"},
        "signature": {"applicable": False, "signed": False, "trusted": False,
                      "signer": "", "detail": "not applicable"},
    }
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(d.get(k), dict):
            d[k].update(v)
        else:
            d[k] = v
    return d


# ─── False-positive regression tests (the #1 flaw this project had) ──────────

def test_single_yara_without_reputation_is_clean():
    """A single generic YARA hit on a file VirusTotal has never seen
    must NOT be called malicious (this used to flag clean installers)."""
    v = verdict.compute_verdict(base(
        yara={"flag": True, "matches": ["crypto_ransom_generic"],
              "detail": "YARA matched"}))
    assert v["label"] == "Clean"
    assert v["is_malicious"] is False


def test_corroborated_weak_signals_are_suspicious():
    """Two independent weak signals (YARA + high entropy) corroborate each
    other → Suspicious even without VirusTotal reputation."""
    v = verdict.compute_verdict(base(
        yara={"flag": True, "matches": ["rule_x"], "detail": "match"},
        entropy={"entropy": 7.8, "flag": True, "detail": "high"}))
    assert v["label"] == "Suspicious"
    assert v["is_malicious"] is True


def test_magic_mismatch_is_suspicious_even_without_reputation():
    """A lying extension is a strong local indicator on its own."""
    v = verdict.compute_verdict(base(
        magic={"real_type": "exe", "extension_ok": False,
               "flag": True, "detail": "Extension mismatch"}))
    assert v["label"] == "Suspicious"
    assert v["is_malicious"] is True


# ─── Trust-signal tests ───────────────────────────────────────────────────────

def test_vt_clean_broad_consensus_is_high_confidence():
    v = verdict.compute_verdict(base(
        vt={"vt_flag": False, "positives": 0, "total": 70, "detail": "Clean"}))
    assert v["label"] == "Clean"
    assert v["confidence"] == "High"


def test_broad_vt_flag_reaches_ransomware():
    v = verdict.compute_verdict(base(
        vt={"vt_flag": True, "positives": 50, "total": 70,
            "detail": "50/70 engines flagged"}))
    assert v["label"] == "Ransomware"
    assert v["confidence"] == "High"


def test_trusted_signature_overrides_noise_to_clean():
    """A valid signature from a trusted publisher outweighs generic YARA noise."""
    v = verdict.compute_verdict(base(
        yara={"flag": True, "matches": ["generic_noise"], "detail": "match"},
        signature={"applicable": True, "signed": True, "trusted": True,
                   "signer": "Test Corp", "detail": "Valid"}))
    assert v["label"] == "Clean"
    assert v["is_malicious"] is False


# ─── Honest uncertainty: no reputation available ─────────────────────────────

def test_no_reputation_clean_is_low_confidence():
    """With no VT key and no local hits: verdict is Clean, but confidence must
    be Low (not pretending to have reputation we don't have)."""
    v = verdict.compute_verdict(base())
    assert v["label"] == "Clean"
    assert v["confidence"] == "Low"
    assert any("reputation unavailable" in r for r in v["reasons"])


# ─── Standalone runner (no pytest required) ───────────────────────────────────

if __name__ == "__main__":
    import traceback
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except Exception:
                failed += 1
                print(f"FAIL  {name}")
                traceback.print_exc()
    total = sum(1 for n in globals() if n.startswith("test_") and callable(globals()[n]))
    print(f"\n{total - failed}/{total} tests passed")
    sys.exit(1 if failed else 0)
