"""
test_static_analysis.py
Unit tests for the instant static checks (static_analysis.py).

Run with either:
    python -m pytest tests/ -v
or, without pytest installed (e.g. the project venv):
    python tests/test_static_analysis.py
"""

import os
import sys
import tempfile

# Make the project root importable when run as a plain script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import static_analysis as sa


def _write(suffix: str, data: bytes) -> str:
    """Write data to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


# ─── Hashes ───────────────────────────────────────────────────────────────────

def test_hashes_known_values():
    p = _write(".bin", b"abc")
    try:
        h = sa.compute_hashes(p)
        assert h["md5"] == "900150983cd24fb0d6963f7d28e17f72"
        assert h["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
        assert h["sha256"].startswith("ba7816bf")
    finally:
        os.remove(p)


# ─── Magic bytes / extension mismatch ─────────────────────────────────────────

def test_magic_disguised_exe():
    """An MZ executable wearing a .jpg costume must be flagged."""
    p = _write(".jpg", b"MZ" + b"\x00" * 64)
    try:
        r = sa.check_magic_bytes(p)
        assert r["real_type"] == "exe"
        assert r["flag"] is True
    finally:
        os.remove(p)


def test_magic_ok_pdf():
    p = _write(".pdf", b"%PDF-1.4\n% test document")
    try:
        r = sa.check_magic_bytes(p)
        assert r["real_type"] == "pdf"
        assert r["flag"] is False
    finally:
        os.remove(p)


# ─── Entropy ──────────────────────────────────────────────────────────────────

def test_entropy_low_vs_high():
    low  = _write(".bin", b"a" * 10000)
    high = _write(".bin", os.urandom(20000))
    try:
        r_low = sa.compute_entropy(low)
        assert r_low["entropy"] < 1.0
        assert r_low["flag"] is False

        r_high = sa.compute_entropy(high)
        assert r_high["entropy"] > 7.0
        # .bin is NOT a compressed format, so high entropy IS suspicious here.
        assert r_high["flag"] is True
    finally:
        os.remove(low)
        os.remove(high)


def test_entropy_expected_for_zip():
    """Same random bytes, but as a .zip: high entropy is normal → no flag."""
    p = _write(".zip", os.urandom(20000))
    try:
        r = sa.compute_entropy(p)
        assert r["entropy"] > 7.0
        assert r["flag"] is False
    finally:
        os.remove(p)


# ─── Size anomaly ─────────────────────────────────────────────────────────────

def test_size_anomaly():
    """A 3 MB .txt blows the 2 MB baseline → flagged."""
    p = _write(".txt", b"0" * (3 * 1024 * 1024))
    try:
        assert sa.check_size_anomaly(p)["flag"] is True
    finally:
        os.remove(p)


# ─── YARA ─────────────────────────────────────────────────────────────────────

def test_yara_scan_runs():
    bad = _write(".bin", b"this is a WannaCry payload")
    ok  = _write(".bin", b"hello world, a normal file")
    try:
        r = sa.yara_scan(bad)
        if r["detail"].startswith("yara-python not installed"):
            print("  (skip) yara-python not installed in this environment")
            return
        assert r["flag"] is True
        assert sa.yara_scan(ok)["flag"] is False
    finally:
        os.remove(bad)
        os.remove(ok)


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
