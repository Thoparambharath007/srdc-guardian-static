"""
SRDC Guardian - Configuration
"""
import os

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*_args, **_kwargs):
        return False


APP_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(APP_DIR, ".env"))


DEFAULT_WATCH_FOLDERS = [
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "OneDrive", "Desktop"),
    os.path.join(os.path.expanduser("~"), "OneDrive", "Documents"),
    os.path.join(os.path.expanduser("~"), "OneDrive", "Pictures"),
    os.path.join(os.path.expanduser("~"), "Videos"),
    os.path.join(os.path.expanduser("~"), "Music"),
]

custom_watch_folders = os.environ.get("WATCH_FOLDERS", "")
WATCH_FOLDERS = (
    [p.strip() for p in custom_watch_folders.split(os.pathsep) if p.strip()]
    if custom_watch_folders else DEFAULT_WATCH_FOLDERS
)
WATCH_FOLDERS = [f for f in WATCH_FOLDERS if os.path.exists(f)]


def save_watch_folders(folders: list[str]) -> list[str]:
    """Persist the monitored folders and update the running application list."""
    unique: list[str] = []
    seen: set[str] = set()
    for folder in folders:
        path = os.path.abspath(os.path.expanduser(folder.strip()))
        key = os.path.normcase(path)
        if path and os.path.isdir(path) and key not in seen:
            unique.append(path)
            seen.add(key)

    env_file = os.path.join(APP_DIR, ".env")
    try:
        from dotenv import set_key
        set_key(env_file, "WATCH_FOLDERS", os.pathsep.join(unique), quote_mode="auto")
    except Exception as exc:
        raise RuntimeError(f"Could not save monitored folders: {exc}") from exc

    WATCH_FOLDERS[:] = unique
    return WATCH_FOLDERS

QUARANTINE_DIR = os.path.join(APP_DIR, "quarantine")
HISTORY_FILE   = os.path.join(APP_DIR, "scan_history.json")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

VT_API_KEY = os.environ.get("VT_API_KEY", "")

ENTROPY_THRESHOLD    = 7.2
