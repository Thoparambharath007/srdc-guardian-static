"""
quarantine_manager.py
Move files to quarantine, restore, delete permanently.
"""

import os
import json
import shutil
import time
from config import QUARANTINE_DIR

INDEX_FILE = os.path.join(QUARANTINE_DIR, "_index.json")


def _load_index() -> list:
    if not os.path.exists(INDEX_FILE):
        return []
    try:
        with open(INDEX_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save_index(data: list):
    with open(INDEX_FILE, "w") as f:
        json.dump(data, f, indent=2)


def quarantine_file(filepath: str, verdict: str) -> dict | None:
    """Move file to quarantine folder. Returns index entry or None on fail."""
    if not os.path.exists(filepath):
        return None
    fname    = os.path.basename(filepath)
    ts       = time.strftime("%Y%m%d_%H%M%S")
    safe_name = f"{ts}_{fname}.quarantine"
    dest     = os.path.join(QUARANTINE_DIR, safe_name)
    try:
        shutil.move(filepath, dest)
        entry = {
            "id":           safe_name,
            "original_name": fname,
            "original_path": filepath,
            "quarantine_path": dest,
            "verdict":      verdict,
            "timestamp":    time.strftime("%Y-%m-%d %H:%M:%S"),
            "size_kb":      round(os.path.getsize(dest) / 1024, 1),
        }
        idx = _load_index()
        idx.insert(0, entry)
        _save_index(idx)
        return entry
    except Exception as e:
        print(f"[Quarantine] Failed: {e}")
        return None


def restore_file(item_id: str) -> bool:
    """Restore quarantined file to original location."""
    idx = _load_index()
    entry = next((e for e in idx if e["id"] == item_id), None)
    if not entry:
        return False
    try:
        shutil.move(entry["quarantine_path"], entry["original_path"])
        idx = [e for e in idx if e["id"] != item_id]
        _save_index(idx)
        return True
    except Exception as e:
        print(f"[Quarantine] Restore failed: {e}")
        return False


def delete_permanently(item_id: str) -> bool:
    """Permanently delete quarantined file."""
    idx = _load_index()
    entry = next((e for e in idx if e["id"] == item_id), None)
    if not entry:
        return False
    try:
        if os.path.exists(entry["quarantine_path"]):
            os.remove(entry["quarantine_path"])
        idx = [e for e in idx if e["id"] != item_id]
        _save_index(idx)
        return True
    except Exception as e:
        print(f"[Quarantine] Delete failed: {e}")
        return False


def get_all() -> list:
    return _load_index()


def get_count() -> int:
    return len(_load_index())