"""
test_storage.py
Unit tests for scan history (history_store.py) and quarantine
(quarantine_manager.py). All paths are redirected into a throwaway temp
sandbox, so the real scan_history.json and quarantine/ folder are never
touched.

Run with either:
    python -m pytest tests/ -v
or, without pytest installed (e.g. the project venv):
    python tests/test_storage.py
"""

import os
import sys
import tempfile

# Make the project root importable when run as a plain script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import history_store as hs
import quarantine_manager as qm


_VERDICT = {"label": "Suspicious", "confidence": "Medium",
            "family": "N/A", "mal_score": 3}
_STATIC = {
    "vt":      {"positives": 0, "total": 0},
    "entropy": {"entropy": 4.5},
    "magic":   {"flag": False},
    "yara":    {"matches": []},
}


def _setup_sandbox() -> str:
    """Point history_store / quarantine_manager at a fresh temp directory."""
    sandbox = tempfile.mkdtemp(prefix="srdc_test_")
    hs.HISTORY_FILE = os.path.join(sandbox, "scan_history.json")
    qm.QUARANTINE_DIR = os.path.join(sandbox, "quarantine")
    qm.INDEX_FILE = os.path.join(sandbox, "quarantine", "_index.json")
    os.makedirs(qm.QUARANTINE_DIR, exist_ok=True)
    return sandbox


def _make_file(sandbox: str, name: str, data: bytes = b"x" * 16) -> str:
    path = os.path.join(sandbox, name)
    with open(path, "wb") as f:
        f.write(data)
    return path


# ─── Scan history ─────────────────────────────────────────────────────────────

def test_history_add_and_stats():
    sandbox = _setup_sandbox()
    f1 = _make_file(sandbox, "file1.bin", b"x" * 1024)
    f2 = _make_file(sandbox, "file2.bin", b"y" * 1024)
    hs.add_entry(f1, _VERDICT, _STATIC)
    hs.add_entry(f2, dict(_VERDICT, label="Clean"), _STATIC)
    entries = hs.get_all()
    assert len(entries) == 2
    assert entries[0]["filename"] == "file2.bin"      # newest first
    stats = hs.get_stats()
    assert stats["total"] == 2
    assert stats["threats"] == 1
    assert stats["ransomware"] == 0
    assert stats["clean"] == 1


def test_history_capped_at_500():
    sandbox = _setup_sandbox()
    f = _make_file(sandbox, "cap.bin")
    for _ in range(502):
        hs.add_entry(f, _VERDICT, _STATIC)
    assert len(hs.get_all()) == 500


def test_history_csv_export():
    sandbox = _setup_sandbox()
    f = _make_file(sandbox, "csv.bin")
    out = os.path.join(sandbox, "export.csv")
    hs.add_entry(f, _VERDICT, _STATIC)
    assert hs.export_csv(out) is True
    with open(out, encoding="utf-8") as fh:
        lines = fh.read().strip().splitlines()
    assert lines[0].startswith("timestamp")
    assert len(lines) == 2                            # header + 1 row
    assert "csv.bin" in lines[1]


# ─── Quarantine lifecycle ─────────────────────────────────────────────────────

def test_quarantine_restore_delete():
    sandbox = _setup_sandbox()
    f = _make_file(sandbox, "victim.exe", b"MZ fake exe")

    # quarantine: file leaves its original spot, lands in quarantine
    entry = qm.quarantine_file(f, "Ransomware")
    assert entry is not None
    assert not os.path.exists(f)
    assert os.path.exists(entry["quarantine_path"])
    assert qm.get_count() == 1

    # restore: file is back where it started
    assert qm.restore_file(entry["id"]) is True
    assert os.path.exists(f)
    assert qm.get_count() == 0

    # quarantine again, then delete permanently
    entry = qm.quarantine_file(f, "Ransomware")
    assert qm.delete_permanently(entry["id"]) is True
    assert not os.path.exists(f)
    assert not os.path.exists(entry["quarantine_path"])
    assert qm.get_count() == 0


def test_quarantine_missing_file_is_noop():
    _setup_sandbox()
    assert qm.quarantine_file(r"C:\does\not\exist.exe", "Ransomware") is None
    assert qm.restore_file("no_such_id") is False
    assert qm.delete_permanently("no_such_id") is False


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
