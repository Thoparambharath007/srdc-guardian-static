"""
test_imports.py
Regression guard: importing any project module must be side-effect-free.

In particular, importing `main` must NOT trigger the UAC self-elevation —
that may only happen when main.py is *run* as a script. (This locked in a
real bug that existed: require_admin() was called at module level, so any
`import main` popped a UAC dialog.)

Run with either:
    python -m pytest tests/ -v
or, without pytest installed (e.g. the project venv):
    python tests/test_imports.py
"""

import importlib
import os
import sys

# Make the project root importable when run as a plain script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_importing_main_does_not_exit():
    try:
        importlib.import_module("main")
    except SystemExit as e:
        raise AssertionError(
            f"importing 'main' called sys.exit({e.code}) — a module-level "
            "side effect (e.g. require_admin() at import time). It must only "
            "run inside the `if __name__ == '__main__'` block."
        )


def test_all_core_modules_import():
    for m in ("config", "static_analysis", "verdict", "history_store",
              "quarantine_manager", "process_monitor", "scan_file"):
        importlib.import_module(m)   # raises on failure


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
