"""
history_store.py
Saves and loads scan history as JSON.
Each entry = one scanned file.
"""

import json
import os
import time
import threading
from config import HISTORY_FILE

# Thread lock to prevent concurrent file access
_lock = threading.Lock()


def _load() -> list:
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[History] Load error: {e}")
        return []


def _save(data: list):
    try:
        # Write to temp file first, then atomic rename
        temp_file = HISTORY_FILE + ".tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        
        # Atomic rename (Windows safe)
        if os.path.exists(HISTORY_FILE):
            os.replace(temp_file, HISTORY_FILE)
        else:
            os.rename(temp_file, HISTORY_FILE)
    except Exception as e:
        print(f"[History] Save error: {e}")
        # Clean up temp file if it exists
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass


def add_entry(filepath: str, verdict: dict, static: dict):
    with _lock:  # Thread-safe
        try:
            data  = _load()
            entry = {
                "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
                "filename":    os.path.basename(filepath),
                "filepath":    filepath,
                "size_kb":     round(os.path.getsize(filepath) / 1024, 1) if os.path.exists(filepath) else 0,
                "verdict":     verdict["label"],
                "confidence":  verdict["confidence"],
                "family":      verdict["family"],
                "mal_score":   verdict["mal_score"],
                "vt_hits":     f"{static['vt']['positives']}/{static['vt']['total']}",
                "entropy":     static["entropy"]["entropy"],
                "magic_ok":    not static["magic"]["flag"],
                "yara_hits":   static["yara"]["matches"],
            }
            data.insert(0, entry)     # newest first
            data = data[:500]         # keep last 500
            _save(data)
            return entry
        except Exception as e:
            print(f"[History] Add entry error: {e}")
            return None


def get_all() -> list:
    with _lock:  # Thread-safe
        return _load()


def get_stats() -> dict:
    with _lock:  # Thread-safe
        data  = _load()
        total = len(data)
        threats   = sum(1 for e in data if e["verdict"] in ("Ransomware", "Suspicious"))
        ransomware = sum(1 for e in data if e["verdict"] == "Ransomware")
        clean     = sum(1 for e in data if e["verdict"] == "Clean")
        return {
            "total":      total,
            "threats":    threats,
            "ransomware": ransomware,
            "clean":      clean,
        }


def export_csv(out_path: str):
    with _lock:  # Thread-safe
        import csv
        data = _load()
        if not data:
            return False
        keys = ["timestamp", "filename", "verdict", "confidence",
                "family", "vt_hits", "entropy", "mal_score"]
        try:
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                w.writeheader()
                w.writerows(data)
            return True
        except Exception as e:
            print(f"[History] Export error: {e}")
            return False