"""
process_monitor.py
Watches for .exe launches via WMI and intercepts only "foreign" files:
  - files downloaded from the internet (Mark-of-the-Web / Zone.Identifier)
  - files the user selected for scanning
  - files the folder watcher saw arrive
Trusted local dependencies (app helpers, runtimes, installers' child processes)
are allowed to run without interruption.
Requires: pip install wmi pywin32
"""

import os, re, json, time, ctypes, threading, hashlib
from pathlib import Path

_LOCAL_APPDATA = os.environ.get("LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local"))
APP_DIR       = os.path.dirname(os.path.abspath(__file__))
TRUSTED_FILE  = os.path.join(APP_DIR, "trusted_files.json")

# ─── Win32 API ───────────────────────────────────────────────────────────────
kernel32 = ctypes.windll.kernel32
ntdll    = ctypes.windll.ntdll

PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_TERMINATE      = 0x0001

# ─── SKIP LISTS (dynamic OS paths — works on any install drive) ──────────────
_SYSTEM_ROOT       = os.environ.get("SystemRoot", r"C:\Windows")
_PROGRAM_FILES     = os.environ.get("ProgramFiles", r"C:\Program Files")
_PROGRAM_FILES_X86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

_SKIP_PATHS = [
    os.path.join(_SYSTEM_ROOT, ""),
    os.path.join(_PROGRAM_FILES, "WindowsApps") + "\\",
    os.path.join(_PROGRAM_FILES, "Common Files", "microsoft shared") + "\\",
    os.path.join(_PROGRAM_FILES, "Google", "Chrome") + "\\",
    os.path.join(_PROGRAM_FILES_X86, "Google") + "\\",
    os.path.join(_LOCAL_APPDATA, "Google", "Chrome") + "\\",
    # ─── Brave ───────────────────────────────────────────────────────────────
    os.path.join(_PROGRAM_FILES, "BraveSoftware") + "\\",
    os.path.join(_PROGRAM_FILES_X86, "BraveSoftware") + "\\",
    os.path.join(_LOCAL_APPDATA, "BraveSoftware") + "\\",
    # ─── VS Code ─────────────────────────────────────────────────────────────
    os.path.join(_PROGRAM_FILES, "Microsoft VS Code") + "\\",
    os.path.join(_PROGRAM_FILES_X86, "Microsoft VS Code") + "\\",
    os.path.join(_LOCAL_APPDATA, "Programs", "Microsoft VS Code") + "\\",
]

_SKIP_NAMES = {
    "python.exe","python3.exe","pythonw.exe","py.exe","AGSService.exe",
    "svchost.exe","explorer.exe","csrss.exe","lsass.exe","wslrelay.exe",
    "winlogon.exe","services.exe","smss.exe","wininit.exe","Service.exe",
    "spoolsv.exe","taskhostw.exe","dwm.exe","fontdrvhost.exe",
    "conhost.exe","cmd.exe","powershell.exe","SearchHost.exe",
    "SearchIndexer.exe","MsMpEng.exe","NisSrv.exe","SecurityHealthService.exe",
    "audiodg.exe","dllhost.exe","sihost.exe","ctfmon.exe",
    "RuntimeBroker.exe","ShellExperienceHost.exe","StartMenuExperienceHost.exe",
    "TextInputHost.exe","UserOOBEBroker.exe","WmiPrvSE.exe",
    # ─── Browsers & Apps ───────────────────────────────────────────────────
    "chrome.exe","brave.exe","firefox.exe","msedge.exe","opera.exe",
    "whatsapp.exe","whatsappdesktop.exe","msedgewebview2.exe",
    "updater.exe","googleupdate.exe","git.exe","msrdc.exe",
    # ─── Dev Tools ────────────────────────────────────────────────────────────
    "code.exe","kiro.exe",
    # ─── VirtualBox / WSL ──────────────────────────────────────────────────────
    "VirtualBoxVM.exe","VBoxSVC.exe","VBoxSDS.exe","VBoxManage.exe","VBoxNetDHCP.exe",
    "VBoxHeadless.exe","VBoxWebSrv.exe","VBoxBalloonCtrl.exe",
    "wsl.exe","wslhost.exe","wslservice.exe","Antigravity.exe",
    # ─── Adobe / Other Tools ───────────────────────────────────────────────────
    "CCXProcess.exe","node.exe","npm.exe",
}

_seen: set[str] = set()   # deduplicate by path


# ─── SMART INTERCEPTION (foreign-file policy) ────────────────────────────────
# A launched .exe is intercepted only when it is "foreign":
#   1. it carries Mark-of-the-Web (Zone.Identifier zone 3/4), i.e. it was
#      downloaded from the internet or saved by a messenger app, OR
#   2. the user selected it for scanning / the folder watcher saw it arrive,
#      OR
#   3. it is not in the persistent trusted list.
# Everything else (local app dependencies, helpers, runtimes) runs untouched.

_foreign_paths: set[str] = set()          # session registry (user-picked / newly arrived)
_trusted: dict[str, list] = {"paths": [], "hashes": []}


def _load_trusted():
    try:
        with open(TRUSTED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        _trusted["paths"]  = list(data.get("paths", []))
        _trusted["hashes"] = list(data.get("hashes", []))
    except Exception:
        pass


def _save_trusted():
    try:
        with open(TRUSTED_FILE, "w", encoding="utf-8") as f:
            json.dump(_trusted, f, indent=2)
    except Exception as e:
        print(f"[Trust] Save error: {e}")


_load_trusted()


def _sha256_of(path: str) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                digest.update(chunk)
    except Exception:
        return None
    return digest.hexdigest()


def mark_foreign(path: str):
    """Register a user-selected or newly-arrived file so its launches are intercepted."""
    if path:
        _foreign_paths.add(os.path.abspath(path))


def trust_file(path: str) -> bool:
    """Persistently trust a file: future launches will not be intercepted."""
    ap = os.path.abspath(path)
    if ap not in _trusted["paths"]:
        _trusted["paths"].append(ap)
    digest = _sha256_of(ap)
    if digest and digest not in _trusted["hashes"]:
        _trusted["hashes"].append(digest)
    _save_trusted()
    _foreign_paths.discard(ap)
    return True


def is_trusted(path: str) -> bool:
    return os.path.abspath(path) in _trusted["paths"]


def _has_internet_zone(path: str) -> bool:
    """Mark-of-the-Web check via the Zone.Identifier alternate data stream.
    Browsers and messenger apps (WhatsApp, Telegram, etc.) tag downloaded
    files with zone 3 (Internet) or 4 (Restricted)."""
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
        m = re.search(r"ZoneId\s*=\s*(\d+)", data)
        return bool(m and m.group(1) in {"3", "4"})
    except Exception:
        return False


# MotW can propagate from a downloaded installer to the files it extracts.
# Such files are established local programs, not fresh downloads, so a
# Zone.Identifier only counts as "foreign" while the file is young.
_MOTW_MAX_AGE_S = 24 * 3600


def _is_fresh(path: str) -> bool:
    try:
        age = time.time() - os.path.getctime(path)
        return 0 <= age <= _MOTW_MAX_AGE_S
    except Exception:
        return True   # cannot tell → err on the safe side and intercept


def is_foreign(path: str) -> bool:
    """Decide whether a launched executable should be intercepted."""
    try:
        ap = os.path.abspath(path)
    except Exception:
        return False
    if is_trusted(ap):
        return False
    if ap in _foreign_paths:
        return True
    if _has_internet_zone(ap):
        return _is_fresh(ap)
    return False


def _skip(path: str) -> bool:
    if not path:
        return True
    name = Path(path).name
    if name.lower() in {n.lower() for n in _SKIP_NAMES}:
        return True
    for p in _SKIP_PATHS:
        if path.upper().startswith(p.upper()):
            return True
    return False


# ─── PROCESS CONTROL ─────────────────────────────────────────────────────────

def suspend_process(pid: int) -> bool:
    h = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if h:
        ntdll.NtSuspendProcess(h)
        kernel32.CloseHandle(h)
        return True
    return False


def resume_process(pid: int):
    h = kernel32.OpenProcess(PROCESS_SUSPEND_RESUME, False, pid)
    if h:
        ntdll.NtResumeProcess(h)
        kernel32.CloseHandle(h)


def kill_process(pid: int):
    h = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if h:
        kernel32.TerminateProcess(h, 1)
        kernel32.CloseHandle(h)


def is_running(pid: int) -> bool:
    h = kernel32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return False
    kernel32.CloseHandle(h)
    return True


# ─── WMI MONITOR ─────────────────────────────────────────────────────────────

def start(app, on_new_process):
    """
    Start monitor in daemon thread.
    on_new_process(filepath, pid) called for each new FOREIGN .exe
    (internet-downloaded, user-selected, or newly arrived).
    Trusted local dependencies are allowed to run without interruption.
    """
    def _loop():
        try:
            import wmi
            c       = wmi.WMI()
            watcher = c.Win32_Process.watch_for("creation")
            app.after(0, lambda: app.log("Process monitor active (foreign-file policy)"))

            while True:
                try:
                    proc = watcher()
                    pid  = proc.ProcessId
                    path = proc.ExecutablePath or ""

                    if not path.lower().endswith(".exe"):
                        continue
                    if _skip(path):
                        continue
                    if not os.path.exists(path):
                        continue
                    if not is_foreign(path):
                        app.after(0, lambda n=Path(path).name:
                                  app.log(f"Allowed (trusted local file): {n}"))
                        continue

                    # Deduplicate same path within 60 s
                    key = path.lower()
                    if key in _seen:
                        continue
                    _seen.add(key)
                    threading.Timer(60, lambda k=key: _seen.discard(k)).start()

                    app.after(0, lambda n=Path(path).name, i=pid:
                              app.log(f"Execution detected: {n} (PID {i})"))
                    on_new_process(path, pid)

                except Exception:
                    time.sleep(0.5)

        except ImportError:
            app.after(0, lambda: app.log(
                "⚠ wmi not installed — process monitor OFF. Run: pip install wmi pywin32"))
        except Exception as e:
            app.after(0, lambda: app.log(f"Process monitor error: {e}"))

    threading.Thread(target=_loop, daemon=True).start()