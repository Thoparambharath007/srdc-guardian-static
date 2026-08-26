"""
main.py  –  SRDC Guardian v2
Advanced Windows desktop app with:
  - Sidebar navigation (Dashboard / History / Quarantine / Settings)
  - Stats dashboard
  - Scan history table with CSV export
  - Quarantine management
  - Toast notifications
  - System tray (requires: pip install pystray pillow)
  - Sound alerts (built-in winsound)

Run: python main.py
"""
import ctypes, sys

def require_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            res = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                " ".join(f'"{a}"' for a in sys.argv), None, 1)
            if int(res) > 32:
                # Successfully launched elevated process, exit this un-elevated instance
                sys.exit(0)
    except Exception as e:
        print(f"[Admin Check] Warning: {e}")

require_admin()

import os, sys, time, threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import static_analysis
import verdict as verdict_mod
import history_store, quarantine_manager as qm
import process_monitor as pm
from config import WATCH_FOLDERS, QUARANTINE_DIR, save_watch_folders

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── THEME ───────────────────────────────────────────────────────────────────
BG       = "#0d1117";  PANEL   = "#161b22";  CARD    = "#1c2128"
BORDER   = "#30363d";  SIDEBAR = "#010409"
RED      = "#f85149";  YLW     = "#d29922";  GRN     = "#3fb950"
BLU      = "#58a6ff";  PRP     = "#bc8cff";  CYN     = "#39d353"
TXT      = "#e6edf3";  DIM     = "#8b949e";  FAINT   = "#484f58"
FT_HEAD  = ("Segoe UI", 13, "bold")
FT_BODY  = ("Segoe UI", 10)
FT_SMALL = ("Segoe UI",  9)
FT_MONO  = ("Consolas", 9)
FT_NAV   = ("Segoe UI", 10)
FT_STAT  = ("Segoe UI", 26, "bold")

# Background monitoring is deliberately conservative.  Newly arrived
# executable/script-like files are identified using static checks only and
# always await an explicit user action before being scanned.
AUTO_MONITOR_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".msi", ".sys", ".bat", ".cmd",
    ".js", ".vbs", ".ps1", ".hta", ".wsf", ".jar", ".apk",
}

# ─── TOAST NOTIFICATION ──────────────────────────────────────────────────────
class Toast(tk.Toplevel):
    def __init__(self, parent, title, msg, colour=BLU, duration=5000):
        super().__init__(parent)
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(bg=PANEL)
        self.attributes("-alpha", 0.95)

        bar = tk.Frame(self, bg=colour, width=4)
        bar.pack(side="left", fill="y")
        body = tk.Frame(self, bg=PANEL, padx=14, pady=10)
        body.pack(side="left", fill="both", expand=True)
        tk.Label(body, text=title, bg=PANEL, fg=TXT,
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(body, text=msg, bg=PANEL, fg=DIM,
                 font=FT_SMALL, wraplength=260).pack(anchor="w")

        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w  = 300; h = self.winfo_reqheight() + 10
        self.geometry(f"{w}x{h}+{sw-w-16}+{sh-h-60}")
        self.after(duration, self.destroy)

# ─── STAT CARD ───────────────────────────────────────────────────────────────
class StatCard(tk.Frame):
    def __init__(self, parent, label, value, colour, icon):
        super().__init__(parent, bg=CARD, padx=18, pady=14,
                         highlightbackground=BORDER, highlightthickness=1)
        top = tk.Frame(self, bg=CARD)
        top.pack(fill="x")
        tk.Label(top, text=icon, bg=CARD, fg=colour,
                 font=("Segoe UI", 18)).pack(side="left")
        tk.Label(top, text=label, bg=CARD, fg=DIM,
                 font=FT_SMALL).pack(side="right")
        self.val_lbl = tk.Label(self, text=str(value), bg=CARD,
                                fg=colour, font=FT_STAT)
        self.val_lbl.pack(anchor="w", pady=(4, 0))

    def update(self, value):
        self.val_lbl.configure(text=str(value))

# ─── PAGES ───────────────────────────────────────────────────────────────────
class DashboardPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app

        # ── Title ──────────────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="Dashboard", bg=BG, fg=TXT,
                 font=("Segoe UI", 16, "bold")).pack(side="left")
        self.status_dot = tk.Label(hdr, text="● Active", bg=BG,
                                   fg=GRN, font=FT_BODY)
        self.status_dot.pack(side="right")
        tk.Button(hdr, text="🔍 Select & Scan File...", bg="#238636", fg="#ffffff",
                  activebackground="#2ea043", activeforeground="#ffffff",
                  font=FT_SMALL, relief="flat", padx=12, pady=4,
                  cursor="hand2", command=self.app.prompt_scan_file).pack(side="right", padx=(0, 6))

        # ── Stat cards ─────────────────────────────────────────────────
        cards_frame = tk.Frame(self, bg=BG)
        cards_frame.pack(fill="x", padx=24, pady=(10, 0))
        stats = history_store.get_stats()
        self.card_total  = StatCard(cards_frame, "Total Scanned",  stats["total"],     BLU, "📁")
        self.card_threat  = StatCard(cards_frame, "Threats Found",  stats["threats"],   RED, "🛑")
        self.card_ransom  = StatCard(cards_frame, "Ransomware",     stats["ransomware"],RED, "💀")
        self.card_clean   = StatCard(cards_frame, "Clean Files",    stats["clean"],     GRN, "✅")
        for i, card in enumerate([self.card_total, self.card_threat,
                                   self.card_ransom, self.card_clean]):
            card.grid(row=0, column=i, padx=(0, 12), sticky="ew")
        cards_frame.columnconfigure([0,1,2,3], weight=1)

        # ── Watched folders ────────────────────────────────────────────
        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x", padx=24, pady=14)
        folders_hdr = tk.Frame(self, bg=BG)
        folders_hdr.pack(fill="x", padx=24)
        tk.Label(folders_hdr, text="Monitored folders", bg=BG, fg=DIM,
                 font=FT_SMALL).pack(side="left")
        tk.Button(folders_hdr, text="+ Manage folders", bg=PANEL, fg=BLU,
                  activebackground=CARD, activeforeground=BLU,
                  font=FT_SMALL, relief="flat", padx=9, pady=3, cursor="hand2",
                  command=self.app.open_folder_manager).pack(side="right")
        self.folders_frame = tk.Frame(self, bg=BG)
        self.folders_frame.pack(fill="x", padx=24, pady=(4, 0))
        self._reload_folders()

        # ── Recent activity ────────────────────────────────────────────
        sep2 = tk.Frame(self, bg=BORDER, height=1)
        sep2.pack(fill="x", padx=24, pady=14)
        tk.Label(self, text="Recent activity", bg=BG, fg=DIM,
                 font=FT_SMALL).pack(anchor="w", padx=24)

        self.feed = tk.Text(self, bg=PANEL, fg=TXT, font=FT_MONO,
                            height=10, state="disabled", relief="flat",
                            padx=10, pady=8)
        self.feed.pack(fill="both", padx=24, pady=(4, 20), expand=True)
        self._reload_feed()

    def _reload_feed(self):
        entries = history_store.get_all()[:12]
        self.feed.configure(state="normal")
        self.feed.delete("1.0", "end")
        if not entries:
            self.feed.insert("end", "No scans yet. Download a file to begin.")
        for e in entries:
            icon = "🛑" if e["verdict"] == "Ransomware" else \
                   "⚠️" if e["verdict"] == "Suspicious"  else "✅"
            line = f"{icon}  {e['timestamp']}   {e['filename']:<35}  {e['verdict']}\n"
            self.feed.insert("end", line)
        self.feed.configure(state="disabled")

    def _reload_folders(self):
        for child in self.folders_frame.winfo_children():
            child.destroy()
        for folder in WATCH_FOLDERS:
            tk.Label(self.folders_frame, text=f"  📂  {folder}", bg=BG, fg=TXT,
                     font=FT_MONO).pack(anchor="w")

    def refresh(self):
        stats = history_store.get_stats()
        self.card_total.update(stats["total"])
        self.card_threat.update(stats["threats"])
        self.card_ransom.update(stats["ransomware"])
        self.card_clean.update(stats["clean"])
        self._reload_feed()
        self._reload_folders()


class HistoryPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app

        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=24, pady=(20, 10))
        tk.Label(hdr, text="Scan History", bg=BG, fg=TXT,
                 font=("Segoe UI", 16, "bold")).pack(side="left")
        tk.Button(hdr, text="Export CSV", bg=PANEL, fg=BLU,
                  font=FT_SMALL, relief="flat", padx=10, pady=4,
                  cursor="hand2", command=self._export).pack(side="right")
        tk.Button(hdr, text="🔄 Refresh", bg=PANEL, fg=DIM,
                  font=FT_SMALL, relief="flat", padx=10, pady=4,
                  cursor="hand2", command=self.refresh).pack(side="right", padx=(0,6))

        # Table
        cols = ("Time", "File", "Verdict", "Confidence", "Family", "VT Hits", "Entropy")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.Treeview",
                         background=PANEL, foreground=TXT,
                         fieldbackground=PANEL, rowheight=26,
                         font=FT_MONO, borderwidth=0)
        style.configure("Dark.Treeview.Heading",
                         background=CARD, foreground=DIM,
                         font=FT_SMALL, relief="flat")
        style.map("Dark.Treeview", background=[("selected", "#2d333b")])

        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="both", expand=True, padx=24, pady=(0,20))
        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                  style="Dark.Treeview")
        widths = [130, 220, 90, 80, 100, 70, 65]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, minwidth=w)
        sb = ttk.Scrollbar(frame, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.refresh()

    def refresh(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for e in history_store.get_all():
            tag = ("red" if e["verdict"] == "Ransomware" else
                   "ylw" if e["verdict"] == "Suspicious"  else "grn")
            self.tree.insert("", "end", values=(
                e["timestamp"], e["filename"], e["verdict"],
                e["confidence"], e["family"],
                e.get("vt_hits", "-"), e.get("entropy", "-")
            ), tags=(tag,))
        self.tree.tag_configure("red", foreground=RED)
        self.tree.tag_configure("ylw", foreground=YLW)
        self.tree.tag_configure("grn", foreground=GRN)

    def _export(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile="srdc_scan_history.csv")
        if path:
            ok = history_store.export_csv(path)
            if ok:
                messagebox.showinfo("Exported", f"Saved to:\n{path}")
            else:
                messagebox.showwarning("Empty", "No history to export yet.")


class QuarantinePage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app

        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=24, pady=(20, 10))
        tk.Label(hdr, text="Quarantine", bg=BG, fg=TXT,
                 font=("Segoe UI", 16, "bold")).pack(side="left")
        tk.Button(hdr, text="📂 Open Folder", bg=PANEL, fg=DIM,
                  font=FT_SMALL, relief="flat", padx=10, pady=4,
                  cursor="hand2",
                  command=lambda: os.startfile(QUARANTINE_DIR)).pack(side="right")

        info = tk.Label(self,
            text="Files moved here cannot execute. Restore or delete permanently.",
            bg=BG, fg=DIM, font=FT_SMALL)
        info.pack(anchor="w", padx=24, pady=(0, 8))

        # List frame
        cols = ("Quarantined", "Original Name", "Verdict", "Size", "Original Path")
        style = ttk.Style()
        style.configure("Q.Treeview",
                         background=PANEL, foreground=TXT,
                         fieldbackground=PANEL, rowheight=26,
                         font=FT_MONO, borderwidth=0)
        style.configure("Q.Treeview.Heading",
                         background=CARD, foreground=DIM,
                         font=FT_SMALL, relief="flat")
        style.map("Q.Treeview", background=[("selected", "#2d333b")])

        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="both", expand=True, padx=24)
        vsb = ttk.Scrollbar(frame, orient="vertical")
        hsb = ttk.Scrollbar(frame, orient="horizontal")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                  style="Q.Treeview",
                                  yscrollcommand=vsb.set,
                                  xscrollcommand=hsb.set)
        vsb.configure(command=self.tree.yview)
        hsb.configure(command=self.tree.xview)
        widths = [130, 180, 90, 70, 500]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, minwidth=w, stretch=False)
        self.tree.column("Original Path", width=500, minwidth=300, stretch=True)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        # Buttons
        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(fill="x", padx=24, pady=12)
        tk.Button(btn_row, text="♻️  Restore Selected", bg=PANEL, fg=GRN,
                  font=FT_BODY, relief="flat", padx=14, pady=6,
                  cursor="hand2", command=self._restore).pack(side="left", padx=(0,8))
        tk.Button(btn_row, text="🗑️  Delete Permanently", bg=PANEL, fg=RED,
                  font=FT_BODY, relief="flat", padx=14, pady=6,
                  cursor="hand2", command=self._delete).pack(side="left")

        self.refresh()

    def refresh(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for e in qm.get_all():
            self.tree.insert("", "end", iid=e["id"], values=(
                e["timestamp"], e["original_name"], e["verdict"],
                f"{e['size_kb']} KB", e["original_path"]
            ))

    def _restore(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select a file first.", parent=self)
            return
        item_id = sel[0]
        if messagebox.askyesno("Restore",
            "Restore file to original location?", parent=self):
            ok = qm.restore_file(item_id)
            if ok:
                self.refresh()
                Toast(self.app, "Restored", "File moved back to original location.", GRN)
            else:
                messagebox.showerror("Error", "Restore failed.", parent=self)

    def _delete(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select a file first.", parent=self)
            return
        item_id = sel[0]
        name    = self.tree.item(item_id)["values"][1]
        if messagebox.askyesno("Delete",
            f"Permanently delete '{name}'?\nThis CANNOT be undone.", parent=self):
            ok = qm.delete_permanently(item_id)
            if ok:
                self.refresh()
                Toast(self.app, "Deleted", f"{name} permanently removed.", RED)
            else:
                messagebox.showerror("Error", "Delete failed.", parent=self)


class SettingsPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=BG)
        self.app = app

        tk.Label(self, text="Settings", bg=BG, fg=TXT,
                 font=("Segoe UI", 16, "bold")).pack(anchor="w", padx=24, pady=(20,14))

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", padx=24)

        def section(txt):
            tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(14,8))
            tk.Label(body, text=txt, bg=BG, fg=DIM, font=FT_SMALL).pack(anchor="w")

        def row(label, var, placeholder=""):
            r = tk.Frame(body, bg=BG)
            r.pack(fill="x", pady=3)
            tk.Label(r, text=label, bg=BG, fg=TXT, font=FT_BODY,
                     width=18, anchor="w").pack(side="left")
            e = tk.Entry(r, textvariable=var, bg=CARD, fg=TXT,
                         insertbackground=TXT, relief="flat",
                         font=FT_MONO, width=55)
            e.pack(side="left", ipady=5, padx=(6,0))
            return e

        # ── VirusTotal ──────────────────────────────────────────────────
        section("VirusTotal")
        import config as _cfg
        self.vt_key = tk.StringVar(value=_cfg.VT_API_KEY or "")
        vt_entry = row("API Key", self.vt_key, "Paste VT API key here")
        vt_entry.configure(show="*")
        tk.Button(body, text="Show / Hide", bg=PANEL, fg=DIM,
                  font=FT_SMALL, relief="flat", padx=8,
                  command=lambda: vt_entry.configure(
                      show="" if vt_entry.cget("show") == "*" else "*"
                  )).pack(anchor="w", pady=(2,0))

        # ── Watched folders ─────────────────────────────────────────────
        section("Watched Folders")
        self.folders_label = tk.Label(body, bg=BG, fg=TXT, font=FT_MONO,
                                      justify="left")
        self.folders_label.pack(anchor="w")
        tk.Button(body, text="Manage monitored folders", bg=PANEL, fg=BLU,
                  font=FT_SMALL, relief="flat", padx=10, pady=5, cursor="hand2",
                  command=self.app.open_folder_manager).pack(anchor="w", pady=(7,0))
        tk.Label(body,
                 text="Added folders are saved and monitored immediately.",
                 bg=BG, fg=FAINT, font=FT_SMALL).pack(anchor="w", pady=(4,0))
        self.refresh_folders()

        # ── Save ────────────────────────────────────────────────────────
        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(14,12))
        tk.Button(body, text="Save Settings", bg=BLU, fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat",
                  padx=18, pady=8, cursor="hand2",
                  command=self._save).pack(anchor="w")

    def _save(self):
        key = self.vt_key.get().strip()
        try:
            from dotenv import set_key
            env_file = os.path.join(APP_DIR, ".env")
            set_key(env_file, "VT_API_KEY", key, quote_mode="auto")
            import config, static_analysis
            config.VT_API_KEY = key
            static_analysis.VT_API_KEY = key
            Toast(self.app, "Saved",
                  "VirusTotal key saved to .env and applied."
                  if key else "VirusTotal key cleared.", GRN)
        except Exception as exc:
            messagebox.showerror("Error", f"Could not save VT key: {exc}", parent=self)

    def refresh_folders(self):
        self.folders_label.configure(text="  " + "\n  ".join(WATCH_FOLDERS))


class FolderManager(tk.Toplevel):
    """Pick common, currently unmonitored folders or browse for any folder."""
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Manage monitored folders")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.transient(app)
        self.grab_set()

        body = tk.Frame(self, bg=BG, padx=22, pady=18)
        body.pack(fill="both", expand=True)
        tk.Label(body, text="Add a folder to monitoring", bg=BG, fg=TXT,
                 font=FT_HEAD).pack(anchor="w")
        tk.Label(body, text="Choose an unmonitored folder below, or browse for another one.",
                 bg=BG, fg=DIM, font=FT_SMALL).pack(anchor="w", pady=(3, 12))

        list_frame = tk.Frame(body, bg=PANEL, highlightbackground=BORDER,
                              highlightthickness=1)
        list_frame.pack(fill="both", expand=True)
        self.folders = tk.Listbox(list_frame, bg=PANEL, fg=TXT,
                                  selectbackground="#2d333b", selectforeground=TXT,
                                  font=FT_MONO, relief="flat", height=10,
                                  activestyle="none", exportselection=False)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.folders.yview)
        self.folders.configure(yscrollcommand=scrollbar.set)
        self.folders.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        scrollbar.pack(side="right", fill="y", pady=6)

        actions = tk.Frame(body, bg=BG)
        actions.pack(fill="x", pady=(14, 0))
        tk.Button(actions, text="Add selected folder", bg="#238636", fg="white",
                  activebackground="#2ea043", activeforeground="white",
                  font=FT_SMALL, relief="flat", padx=12, pady=6, cursor="hand2",
                  command=self._add_selected).pack(side="left")
        tk.Button(actions, text="Browse…", bg=PANEL, fg=BLU,
                  font=FT_SMALL, relief="flat", padx=12, pady=6, cursor="hand2",
                  command=self._browse).pack(side="left", padx=(8, 0))
        tk.Button(actions, text="Close", bg=PANEL, fg=DIM,
                  font=FT_SMALL, relief="flat", padx=12, pady=6, cursor="hand2",
                  command=self.destroy).pack(side="right")

        self._paths: list[str] = []
        self._reload()
        self.geometry("620x360")

    def _common_folders(self):
        home = Path.home()
        candidates = [
            home / "Downloads", home / "Desktop", home / "Documents",
            home / "Pictures", home / "Videos", home / "Music",
            home / "OneDrive", home / "OneDrive" / "Desktop",
            home / "OneDrive" / "Documents", home / "OneDrive" / "Pictures",
        ]
        monitored = {os.path.normcase(os.path.abspath(p)) for p in WATCH_FOLDERS}
        unique, seen = [], set()
        for candidate in candidates:
            path = os.path.abspath(str(candidate))
            key = os.path.normcase(path)
            if os.path.isdir(path) and key not in monitored and key not in seen:
                unique.append(path)
                seen.add(key)
        return unique

    def _reload(self):
        self._paths = self._common_folders()
        self.folders.delete(0, "end")
        if not self._paths:
            self.folders.insert("end", "All common folders are already monitored.")
            return
        for folder in self._paths:
            self.folders.insert("end", f"📂  {folder}")

    def _add_selected(self):
        selected = self.folders.curselection()
        if not selected or not self._paths:
            messagebox.showinfo("Select a folder", "Select an unmonitored folder first.", parent=self)
            return
        self._add(self._paths[selected[0]])

    def _browse(self):
        folder = filedialog.askdirectory(title="Choose a folder to monitor", parent=self)
        if folder:
            self._add(folder)

    def _add(self, folder):
        try:
            added = self.app.add_watch_folder(folder)
        except Exception as exc:
            messagebox.showerror("Could not monitor folder", str(exc), parent=self)
            return
        if added:
            Toast(self.app, "Folder monitoring enabled", f"Now monitoring: {folder}", GRN)
            self._reload()
        else:
            messagebox.showinfo("Already monitored", "This folder is already being monitored.", parent=self)


# ─── SCAN PROGRESS WINDOW ────────────────────────────────────────────────────
class ScanProgress(tk.Toplevel):
    def __init__(self, parent, fname):
        super().__init__(parent)
        self.title("Scanning…")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.attributes("-topmost", True)
        pad = tk.Frame(self, bg=BG, padx=24, pady=18)
        pad.pack()
        tk.Label(pad, text="🔍  Scanning", bg=BG, fg=BLU,
                 font=FT_HEAD).pack(anchor="w")
        tk.Label(pad, text=fname, bg=BG, fg=TXT,
                 font=FT_MONO, wraplength=400).pack(anchor="w", pady=(2,10))
        self.status = tk.StringVar(value="Initialising…")
        tk.Label(pad, textvariable=self.status, bg=BG,
                 fg=DIM, font=FT_SMALL).pack(anchor="w")
        self._started_at = time.monotonic()
        self._file_size = self._format_size(fname)
        self.elapsed = tk.StringVar(value="Elapsed: 0s")
        tk.Label(pad, textvariable=self.elapsed, bg=BG, fg=FAINT,
                 font=FT_SMALL).pack(anchor="w", pady=(3,0))
        tk.Label(pad,
                 text="Live elapsed time — duration depends on the file being scanned.",
                 bg=BG, fg=FAINT, font=("Segoe UI", 8), wraplength=400,
                 justify="left").pack(anchor="w", pady=(1,0))
        # Smooth animated bar — custom canvas at ~60 FPS. ttk's indeterminate
        # mode jumps in coarse discrete steps, which reads as stuttering.
        self._bar_w, self._bar_h, self._block_w = 420, 8, 72
        self._bar_canvas = tk.Canvas(pad, width=self._bar_w, height=self._bar_h,
                                     bg=CARD, highlightthickness=1,
                                     highlightbackground=BORDER)
        self._bar_canvas.pack(pady=(10, 0))
        self._block = self._bar_canvas.create_rectangle(
            0, 0, self._block_w, self._bar_h, fill=BLU, width=0)
        self._bar_pos = -self._block_w
        self._animate_bar()
        self._center()
        self._tick_elapsed()

    def _animate_bar(self):
        """Slide the highlight continuously at ~120 FPS for fluid motion."""
        if not self.winfo_exists():
            return
        self._bar_pos += 2
        if self._bar_pos > self._bar_w:
            self._bar_pos = -self._block_w
        self._bar_canvas.coords(self._block,
                                self._bar_pos, 0,
                                self._bar_pos + self._block_w, self._bar_h)
        self.after(8, self._animate_bar)

    def _format_size(self, _fname):
        # The source path is not retained in this small window; the timer is
        # deliberately based on observed elapsed work, not an invented ETA.
        return ""

    def _tick_elapsed(self):
        if not self.winfo_exists():
            return
        seconds = int(time.monotonic() - self._started_at)
        minutes, seconds = divmod(seconds, 60)
        elapsed = f"{minutes}m {seconds:02d}s" if minutes else f"{seconds}s"
        self.elapsed.set(f"Elapsed: {elapsed}")
        self.after(1000, self._tick_elapsed)

    def _center(self):
        self.update_idletasks()
        w,h = self.winfo_width(), self.winfo_height()
        sw,sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw-w)//2}+{(sh-h)//2}")

    def set_status(self, msg):
        self.status.set(msg)


# ─── VERDICT POPUP ───────────────────────────────────────────────────────────
class VerdictPopup(tk.Toplevel):
    def __init__(self, parent, filepath, vdict, app):
        super().__init__(parent)
        self.title("Scan Result — SRDC Guardian")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()
        self.attributes("-topmost", True)
        self._app      = app
        self._filepath = filepath
        self._vdict    = vdict

        fname  = Path(filepath).name
        label  = vdict["label"]
        colour = RED if label == "Ransomware" else YLW if label=="Suspicious" else GRN
        icon   = "🛑" if label=="Ransomware" else "⚠️" if label=="Suspicious" else "✅"

        stripe = tk.Frame(self, bg=colour, width=6)
        stripe.pack(side="left", fill="y")

        main = tk.Frame(self, bg=BG, padx=22, pady=18)
        main.pack(side="left", fill="both", expand=True)

        tk.Label(main, text=f"{icon}  {fname}", bg=BG, fg=TXT,
                 font=FT_HEAD, wraplength=460, justify="left").pack(anchor="w")
        tk.Label(main,
                 text=f"Verdict: {vdict['headline']}   [{vdict['confidence']} confidence]",
                 bg=BG, fg=colour,
                 font=("Segoe UI",11,"bold")).pack(anchor="w", pady=(4,10))

        if vdict["reasons"]:
            tk.Label(main, text="Detection signals:", bg=BG, fg=DIM,
                     font=FT_SMALL).pack(anchor="w")
            for r in vdict["reasons"]:
                tk.Label(main, text=f"  {r}", bg=BG, fg=TXT,
                         font=FT_SMALL, wraplength=460,
                         justify="left").pack(anchor="w")

        tk.Frame(main, bg=BORDER, height=1).pack(fill="x", pady=10)
        for line in vdict["detail_lines"]:
            tk.Label(main, text=line, bg=BG, fg=DIM,
                     font=FT_MONO, anchor="w").pack(anchor="w")
        tk.Frame(main, bg=BORDER, height=1).pack(fill="x", pady=10)

        btn = tk.Frame(main, bg=BG)
        btn.pack(fill="x")

        tk.Button(btn, text="🔒  Quarantine File", bg=RED, fg="white",
                  activebackground="#b91c1c", activeforeground="white",
                  font=("Segoe UI",10,"bold"), relief="flat",
                  padx=16, pady=8, cursor="hand2",
                  command=self._quarantine).pack(side="left", padx=(0,8))

        tk.Button(btn, text="▶  Continue anyway", bg=PANEL, fg=DIM,
                  font=FT_BODY, relief="flat", padx=16, pady=8,
                  cursor="hand2", command=self.destroy).pack(side="left", padx=(0,8))

        self._center()

    def _center(self):
        self.update_idletasks()
        w,h = self.winfo_width(), self.winfo_height()
        sw,sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw-w)//2}+{(sh-h)//2}")

    def _quarantine(self):
        entry = qm.quarantine_file(self._filepath, self._vdict["label"])
        if entry:
            Toast(self._app, "Quarantined",
                  f"{Path(self._filepath).name} moved to quarantine.", RED)
            self._app.refresh_pages()
        else:
            messagebox.showerror("Error", "Could not quarantine file.", parent=self)
        self.destroy()


class AnalysisChoicePopup(tk.Toplevel):
    """Require the user to choose how a newly selected/detected file is handled."""
    def __init__(self, app, filepath, source):
        super().__init__(app)
        self.app = app
        self.filepath = filepath
        self.title("Choose analysis type — SRDC Guardian")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.transient(app)
        self.grab_set()
        self.attributes("-topmost", True)

        body = tk.Frame(self, bg=BG, padx=22, pady=18)
        body.pack(fill="both", expand=True)
        tk.Label(body, text=source, bg=BG, fg=DIM, font=FT_SMALL).pack(anchor="w")
        tk.Label(body, text=f"📄  {Path(filepath).name}", bg=BG, fg=TXT,
                 font=FT_HEAD, wraplength=510, justify="left").pack(anchor="w", pady=(3, 8))
        tk.Label(body,
                 text="Choose an action.",
                 bg=BG, fg=DIM, font=FT_SMALL, wraplength=510,
                 justify="left").pack(anchor="w", pady=(0, 14))

        actions = tk.Frame(body, bg=BG)
        actions.pack(fill="x")
        tk.Button(actions, text="🔍  Run Static Analysis", bg=BLU, fg="white",
                  activebackground="#79c0ff", activeforeground="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=14, pady=8,
                  cursor="hand2", command=self._scan).pack(side="left")

        secondary = tk.Frame(body, bg=BG)
        secondary.pack(fill="x", pady=(10, 0))
        tk.Button(secondary, text="▶  Continue / Keep File", bg=PANEL, fg=DIM,
                  font=FT_BODY, relief="flat", padx=12, pady=7, cursor="hand2",
                  command=self.destroy).pack(side="left")
        tk.Button(secondary, text="🔒  Quarantine", bg=RED, fg="white",
                  activebackground="#b91c1c", activeforeground="white",
                  font=FT_BODY, relief="flat", padx=12, pady=7, cursor="hand2",
                  command=self._quarantine).pack(side="left", padx=(8, 0))

        self.update_idletasks()
        self.geometry(f"+{(self.winfo_screenwidth()-self.winfo_width())//2}+{(self.winfo_screenheight()-self.winfo_height())//2}")

    def _scan(self):
        self.destroy()
        self.app.log(f"Static analysis started: {Path(self.filepath).name}")
        threading.Thread(target=run_scan, args=(self.app, self.filepath),
                         daemon=True).start()

    def _quarantine(self):
        entry = qm.quarantine_file(self.filepath, "User quarantined before analysis")
        if entry:
            Toast(self.app, "Quarantined", f"{Path(self.filepath).name} moved to quarantine.", RED)
            self.app.refresh_pages()
            self.destroy()
        else:
            messagebox.showerror("Quarantine failed", "Could not quarantine this file.", parent=self)


# ─── SCAN PIPELINE ───────────────────────────────────────────────────────────
def run_scan(app, filepath):
    def ui(fn): app.after(0, fn)

    prog = [None]
    def open_prog():
        prog[0] = ScanProgress(app, Path(filepath).name)
    ui(open_prog);  time.sleep(0.3)

    def status(msg):
        if prog[0]:
            ui(lambda m=msg: prog[0].set_status(m))

    # Sound alert helper (Windows only)
    def beep_alert():
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass

    status("Running static analysis…")
    static = static_analysis.run_all(filepath)

    status("Computing verdict…")
    vdict = verdict_mod.compute_verdict(static)
    history_store.add_entry(filepath, vdict, static)

    is_threat = vdict["is_malicious"]
    if is_threat:
        ui(beep_alert)

    def show():
        if prog[0]:
            prog[0].destroy()
        colour = RED if vdict["label"]=="Ransomware" else YLW if vdict["label"]=="Suspicious" else GRN
        Toast(app,
              f"{vdict['label']} detected" if is_threat else "File scanned",
              Path(filepath).name, colour)
        VerdictPopup(app, filepath, vdict, app)
        app.refresh_pages()

    ui(show)


# ─── PROCESS VERDICT POPUP ───────────────────────────────────────────────────
class ProcessVerdictPopup(tk.Toplevel):
    """
    Shown when a running .exe is intercepted.
    Process is SUSPENDED until user decides.
    """
    def __init__(self, parent, filepath, pid, vdict, app):
        super().__init__(parent)
        self.title("⚠ Execution Intercepted — SRDC Guardian")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()
        self.attributes("-topmost", True)
        self._pid      = pid
        self._filepath = filepath
        self._vdict    = vdict
        self._app      = app

        fname  = Path(filepath).name
        label  = vdict["label"]
        colour = RED if label=="Ransomware" else YLW if label=="Suspicious" else GRN
        icon   = "🛑" if label=="Ransomware" else "⚠️" if label=="Suspicious" else "✅"

        stripe = tk.Frame(self, bg=colour, width=6)
        stripe.pack(side="left", fill="y")

        main = tk.Frame(self, bg=BG, padx=22, pady=18)
        main.pack(side="left", fill="both", expand=True)

        # Banner
        banner = tk.Frame(main, bg="#1a0a0a" if label=="Ransomware" else "#1a1400", pady=6, padx=10)
        banner.pack(fill="x", pady=(0,10))
        tk.Label(banner,
                 text="⏸  PROCESS SUSPENDED — Waiting for your decision",
                 bg=banner.cget("bg"), fg=RED if label=="Ransomware" else YLW,
                 font=("Segoe UI", 9, "bold")).pack()

        tk.Label(main, text=f"{icon}  {fname}",
                 bg=BG, fg=TXT, font=FT_HEAD,
                 wraplength=460, justify="left").pack(anchor="w")
        tk.Label(main,
                 text=f"Verdict: {vdict['headline']}   [{vdict['confidence']} confidence]",
                 bg=BG, fg=colour,
                 font=("Segoe UI",11,"bold")).pack(anchor="w", pady=(4,10))

        tk.Label(main, text=f"Path: {filepath}",
                 bg=BG, fg=DIM, font=FT_MONO,
                 wraplength=460).pack(anchor="w", pady=(0,8))

        if vdict["reasons"]:
            for r in vdict["reasons"]:
                tk.Label(main, text=f"  {r}", bg=BG, fg=TXT,
                         font=FT_SMALL, wraplength=460,
                         justify="left").pack(anchor="w")

        tk.Frame(main, bg=BORDER, height=1).pack(fill="x", pady=10)
        for line in vdict["detail_lines"]:
            tk.Label(main, text=line, bg=BG, fg=DIM,
                     font=FT_MONO, anchor="w").pack(anchor="w")
        tk.Frame(main, bg=BORDER, height=1).pack(fill="x", pady=10)

        btn = tk.Frame(main, bg=BG)
        btn.pack(fill="x")

        tk.Button(btn, text="🔒  Kill + Quarantine",
                  bg=RED, fg="white",
                  activebackground="#b91c1c", activeforeground="white",
                  font=("Segoe UI",10,"bold"), relief="flat",
                  padx=16, pady=8, cursor="hand2",
                  command=self._kill).pack(side="left", padx=(0,8))

        tk.Button(btn, text="▶  Resume Execution",
                  bg=PANEL, fg=DIM, font=FT_BODY, relief="flat",
                  padx=16, pady=8, cursor="hand2",
                  command=self._resume).pack(side="left")

        tk.Button(btn, text="✅  Trust — Don't Ask Again",
                  bg=PANEL, fg=GRN, font=FT_BODY, relief="flat",
                  padx=16, pady=8, cursor="hand2",
                  command=self._trust).pack(side="left", padx=(8,0))

        # Auto-resume timer (30s)
        self._countdown = 30
        self._timer_lbl = tk.Label(main,
                                    text=f"Auto-resume in {self._countdown}s",
                                    bg=BG, fg=FAINT, font=FT_SMALL)
        self._timer_lbl.pack(anchor="w", pady=(8,0))
        self._tick()
        self._center()

    def _tick(self):
        if not self.winfo_exists():
            return
        if self._countdown <= 0:
            self._resume()
            return
        self._timer_lbl.configure(text=f"Auto-resume in {self._countdown}s")
        self._countdown -= 1
        self.after(1000, self._tick)

    def _kill(self):
        pm.kill_process(self._pid)
        entry = qm.quarantine_file(self._filepath, self._vdict["label"])
        if entry:
            Toast(self._app, "Process Killed", f"{Path(self._filepath).name} quarantined.", RED)
        self._app.refresh_pages()
        self.destroy()

    def _resume(self):
        pm.resume_process(self._pid)
        Toast(self._app, "Resumed", f"{Path(self._filepath).name} allowed to run.", GRN)
        self.destroy()

    def _trust(self):
        pm.trust_file(self._filepath)
        pm.resume_process(self._pid)
        Toast(self._app, "Trusted",
              f"{Path(self._filepath).name} won't be intercepted again.", GRN)
        self.destroy()

    def _center(self):
        self.update_idletasks()
        w,h = self.winfo_width(), self.winfo_height()
        sw,sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{(sw-w)//2}+{(sh-h)//2}")


# ─── PROCESS SCAN PIPELINE (fast static scan while process is suspended) ─────
def run_process_scan(app, filepath, pid):
    def ui(fn): app.after(0, fn)

    def beep():
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass

    # Suspend process immediately
    suspended = pm.suspend_process(pid)
    if not suspended:
        app.after(0, lambda: app.log(f"Could not suspend PID {pid} (may have exited)"))
        return

    # Fast static scan (process is suspended while it runs)
    static = static_analysis.run_all(filepath)

    vdict = verdict_mod.compute_verdict(static)
    history_store.add_entry(filepath, vdict, static)

    is_threat = vdict["is_malicious"]
    if is_threat:
        ui(beep)

    def show():
        colour = RED if vdict["label"]=="Ransomware" else YLW if vdict["label"]=="Suspicious" else GRN
        Toast(app,
              f"Execution intercepted: {vdict['label']}" if is_threat else f"Execution: Clean",
              Path(filepath).name, colour)
        ProcessVerdictPopup(app, filepath, pid, vdict, app)
        app.refresh_pages()

    ui(show)


# ─── FILE WATCHER ────────────────────────────────────────────────────────────
class DownloadHandler(FileSystemEventHandler):
    def __init__(self, app):
        self.app   = app
        self._seen: set[str] = set()
        self._pending: set[str] = set()

    def _trigger(self, path):
        path = os.path.abspath(path)
        suffix = Path(path).suffix.lower()
        if (path.lower().endswith((".crdownload", ".part", ".tmp", ".download")) or
                suffix not in AUTO_MONITOR_EXTENSIONS):
            return
        if path in self._seen or path in self._pending:
            return
        self._pending.add(path)

        def delayed():
            # Do not scan a partial download.  Wait until its size is stable.
            stable = 0
            previous_size = -1
            for _ in range(30):
                time.sleep(2)
                if not os.path.exists(path):
                    self._pending.discard(path)
                    return
                size = os.path.getsize(path)
                stable = stable + 1 if size > 0 and size == previous_size else 0
                previous_size = size
                if stable >= 2:
                    break
            else:
                self._pending.discard(path)
                return
            self._pending.discard(path)
            self._seen.add(path)
            pm.mark_foreign(path)
            self.app.after(0, lambda: self.app.log(f"Detected: {Path(path).name}"))
            self.app.after(0, lambda p=path: self.app.show_analysis_choice(
                p, "New download or file detected"))
        threading.Thread(target=delayed, daemon=True).start()

    def on_created(self, event):
        if not event.is_directory: self._trigger(event.src_path)

    def on_moved(self, event):
        if not event.is_directory: self._trigger(event.dest_path)


# ─── MAIN APP ────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SRDC Guardian")
        self.configure(bg=SIDEBAR)
        self.geometry("960x640")
        self.minsize(860, 560)

        # ttk styles
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TProgressbar", troughcolor=PANEL,
                    background=BLU, bordercolor=BORDER,
                    lightcolor=BLU, darkcolor=BLU)

        self._build_layout()
        self._start_watcher()
        self.log("Guardian started")

        self.deiconify()
        self.lift()
        self.attributes("-topmost", True)
        self.after(500, lambda: self.attributes("-topmost", False))
        self.focus_force()

    # ── Layout ─────────────────────────────────────────────────────────
    def _build_layout(self):
        # Sidebar
        sidebar = tk.Frame(self, bg=SIDEBAR, width=180)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Logo
        logo = tk.Frame(sidebar, bg=SIDEBAR, pady=20)
        logo.pack(fill="x")
        tk.Label(logo, text="🛡", bg=SIDEBAR, fg=BLU,
                 font=("Segoe UI",22)).pack()
        tk.Label(logo, text="SRDC\nGuardian", bg=SIDEBAR, fg=TXT,
                 font=("Segoe UI",11,"bold"), justify="center").pack()
        tk.Label(logo, text="v2.0", bg=SIDEBAR, fg=FAINT,
                 font=FT_SMALL).pack()

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=12, pady=8)

        # Quick Scan Button
        scan_btn = tk.Button(sidebar, text="🔍  Scan File", bg="#238636", fg="#ffffff",
                             activebackground="#2ea043", activeforeground="#ffffff",
                             font=("Segoe UI", 10, "bold"), relief="flat", padx=12, pady=8,
                             cursor="hand2", command=self.prompt_scan_file)
        scan_btn.pack(fill="x", padx=12, pady=(4, 8))

        # Nav buttons
        self._pages: dict[str, tk.Frame] = {}
        self._nav_btns: dict[str, tk.Button] = {}
        self._content = tk.Frame(self, bg=BG)
        self._content.pack(side="left", fill="both", expand=True)

        nav_items = [
            ("Dashboard",  "📊"),
            ("History",    "📋"),
            ("Quarantine", "🔒"),
            ("Settings",   "⚙️"),
        ]
        for name, icon in nav_items:
            b = tk.Button(sidebar, text=f"  {icon}  {name}",
                          bg=SIDEBAR, fg=DIM,
                          activebackground="#1c2128", activeforeground=TXT,
                          font=FT_NAV, relief="flat", anchor="w",
                          padx=16, pady=10, cursor="hand2",
                          command=lambda n=name: self._show_page(n))
            b.pack(fill="x")
            self._nav_btns[name] = b

        # ── Quit button (bottom of sidebar) ─────────────────────────────
        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=12, pady=(6, 8))
        quit_btn = tk.Button(sidebar, text="⏻   Quit Guardian",
                             bg="#3d1418", fg="#ff7b72",
                             activebackground="#63202a", activeforeground="#ffa198",
                             font=("Segoe UI", 10, "bold"), relief="flat",
                             padx=12, pady=9, cursor="hand2",
                             command=self.quit_app)
        quit_btn.pack(fill="x", padx=12, pady=(0, 8))
        quit_btn.bind("<Enter>", lambda e: quit_btn.configure(bg="#63202a"))
        quit_btn.bind("<Leave>", lambda e: quit_btn.configure(bg="#3d1418"))

        # Status dot at bottom of sidebar
        tk.Frame(sidebar, bg=SIDEBAR).pack(fill="y", expand=True)
        self._status_lbl = tk.Label(sidebar, text="● Active",
                                     bg=SIDEBAR, fg=GRN, font=FT_SMALL)
        self._status_lbl.pack(pady=(0,6))
        tk.Label(sidebar, text="Static Edition | KMIT", bg=SIDEBAR,
                 fg=FAINT, font=("Segoe UI",8)).pack(pady=(0,12))

        # Build pages
        self._pages["Dashboard"]  = DashboardPage(self._content, self)
        self._pages["History"]    = HistoryPage(self._content, self)
        self._pages["Quarantine"] = QuarantinePage(self._content, self)
        self._pages["Settings"]   = SettingsPage(self._content, self)

        self._show_page("Dashboard")

    def _show_page(self, name):
        for n, f in self._pages.items():
            f.pack_forget()
            self._nav_btns[n].configure(
                bg=SIDEBAR if n!=name else "#1c2128",
                fg=DIM     if n!=name else TXT)
        self._pages[name].pack(fill="both", expand=True)

    def open_folder_manager(self):
        FolderManager(self)

    def add_watch_folder(self, folder: str) -> bool:
        """Save and begin watching a user-selected folder without a restart."""
        folder = os.path.abspath(os.path.expanduser(folder))
        if not os.path.isdir(folder):
            raise ValueError("The selected folder no longer exists.")
        key = os.path.normcase(folder)
        if any(os.path.normcase(os.path.abspath(item)) == key for item in WATCH_FOLDERS):
            return False

        watch = self._observer.schedule(self._watch_handler, folder, recursive=False)
        try:
            save_watch_folders([*WATCH_FOLDERS, folder])
        except Exception:
            self._observer.unschedule(watch)
            raise
        self._folder_watches[folder] = watch
        self._pages["Dashboard"].refresh()
        self._pages["Settings"].refresh_folders()
        self.log(f"Now monitoring folder: {folder}")
        return True

    def log(self, msg):
        print(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def show_analysis_choice(self, filepath, source):
        if os.path.isfile(filepath):
            AnalysisChoicePopup(self, filepath, source)

    def prompt_scan_file(self):
        filepath = filedialog.askopenfilename(
            title="Select File to Scan",
            filetypes=[
                ("Supported Files", "*.exe;*.dll;*.scr;*.pdf;*.doc;*.docx;*.xls;*.xlsx;*.zip;*.rar;*.js;*.vbs;*.ps1;*.bat;*.cmd;*.jar;*.apk"),
                ("Executables (*.exe, *.dll, *.scr)", "*.exe;*.dll;*.scr;*.com;*.bat;*.cmd"),
                ("Documents (*.pdf, *.docx, *.xlsx)", "*.pdf;*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx"),
                ("Scripts (*.js, *.vbs, *.ps1)", "*.js;*.vbs;*.ps1;*.hta;*.wsf"),
                ("Archives (*.zip, *.rar, *.7z)", "*.zip;*.rar;*.7z;*.tar;*.gz"),
                ("All Files (*.*)", "*.*")
            ]
        )
        if filepath:
            pm.mark_foreign(filepath)
            self.show_analysis_choice(filepath, "File selected by you")

    def refresh_pages(self):
        self._pages["Dashboard"].refresh()
        self._pages["History"].refresh()
        self._pages["Quarantine"].refresh()

    # ── Watcher ────────────────────────────────────────────────────────
    def _start_watcher(self):
        # Folder watcher
        self._watch_handler = DownloadHandler(self)
        observer = Observer()
        self._folder_watches = {}
        for folder in WATCH_FOLDERS:
            self._folder_watches[folder] = observer.schedule(
                self._watch_handler, folder, recursive=False)
        observer.start()
        self._observer = observer

        # Process monitor callbacks use Tkinter's event queue.  Start it only
        # after mainloop() has begun; otherwise its worker can call app.after()
        # too early and raise "main thread is not in main loop".
        self.after(100, lambda: pm.start(self, lambda path, pid: threading.Thread(
            target=run_process_scan,
            args=(self, path, pid),
            daemon=True
        ).start()))

    def on_closing(self):
        self._observer.stop()
        self._observer.join()
        self.destroy()

    def quit_app(self):
        """Full shutdown from the UI: stop watchers, close GUI, kill process."""
        if not messagebox.askyesno(
                "Quit SRDC Guardian",
                "Stop all monitoring and exit SRDC Guardian completely?"):
            return
        self.log("Shutdown requested from UI")
        try:
            self._observer.stop()
            self._observer.join(timeout=2)
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass
        # Hard exit: guarantees the Python process terminates even if a
        # background WMI/COM thread would otherwise keep the console busy.
        os._exit(0)


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
