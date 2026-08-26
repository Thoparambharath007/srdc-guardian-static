# 🛡️ SRDC Guardian — Static Edition

**A transparent, explainable endpoint-security guardian for Windows that watches
every file you download and every program you launch — and shows you *why* it
made every decision.**

SRDC Guardian is a Windows endpoint-security prototype that monitors new files
and process launches in real time, performs layered static malware analysis,
verifies digital signatures, and gives you the final say — all through a clean
dark-themed dashboard with scan history, verdict popups, and quarantine
management. No CAPE sandbox, no VirtualBox, no ML weights needed — the entire
pipeline runs instantly on your machine.

---

## 🤔 Why does this project matter?

Every day users download installers, cracked tools, "free" utilities and files
from messengers. Most people click **Run** without a second thought. SRDC
Guardian puts a checkpoint between the internet and your CPU.

### Where built-in Windows Defender falls short

| Windows Defender | SRDC Guardian |
|---|---|
| Black-box verdicts — it blocks or allows, but **never explains why** | Every verdict shows its full evidence: VirusTotal consensus (70+ engines), digital-signature owner, YARA matches, entropy, magic bytes |
| Opaque cloud decisions you cannot audit | **You decide** — Quarantine, Allow, or permanently Trust a file |
| Treats all processes the same; no focus on file *provenance* | **Foreign-file policy**: intercepts only files that came from outside (Mark-of-the-Web — browsers, WhatsApp, Telegram) or that you explicitly scan. Your system tools and app dependencies are never interrupted |
| No per-engine visibility | Shows the multi-engine VirusTotal consensus for every scan |
| Heavy, always-on cloud telemetry | 100% local analysis — the only network call is an optional hash lookup (your file is **never uploaded**) |
| No scan history you control | Full local scan history with CSV export, quarantine with restore/delete |

> **Honest positioning:** Defender is a strong antivirus — SRDC Guardian is not
> trying to replace it. Guardian is the **transparent, explainable,
> user-in-control layer** that Defender does not give you: it tells you *what a
> file is, where it came from, and who signed it*, then lets *you* decide. It is
> built to demonstrate how real endpoint-security decisions should be made —
> visible, weighted, and explainable.

### Why it is important

- 🎓 **Educational** — every scan is a live lesson in how malware analysis
  actually works (hashes, entropy, signatures, YARA, reputation)
- 🔍 **Explainable security** — no more "trust me" black boxes
- ⚡ **Instant** — pure static analysis: verdicts in seconds, no sandbox needed
- 🧩 **Provenance-aware** — only files "born on the internet" get intercepted;
  your workflow is never disturbed by false alarms on local dependencies
- 🧪 **Real techniques** — Mark-of-the-Web ADS parsing, Authenticode
  verification, WMI process suspension (`NtSuspendProcess`), YARA engines

---

## ⚙️ What It Checks

Every scanned file goes through these instant, no-execution checks:

- **MD5 / SHA-1 / SHA-256** hashing
- **VirusTotal hash lookup** — consensus of 70+ antivirus engines (hash only;
  the file is never uploaded)
- **Authenticode digital-signature verification** — is it signed? by whom? is
  the chain trusted? (the strongest signal when VT has never seen a file)
- **Magic-byte check** — is that `.jpg` secretly an `.exe`?
- **Shannon entropy** — packed/encrypted payloads (type-aware: a `.zip` being
  high-entropy is normal, an `.exe` being high-entropy is suspicious)
- **File-size anomalies**
- **YARA rules** from `yara_rules/`

Signals are combined with a weighted verdict policy — VirusTotal consensus is
the major signal, magic-byte mismatch and signature validity are medium-strong,
YARA/entropy/size are medium-to-weak — producing **Clean / Suspicious /
Ransomware** with an honest confidence level.

## 🚦 Process interception (foreign-file policy)

Newly launched `.exe` files are intercepted via WMI **only when they are
foreign**:

- tagged by Windows as downloaded from the internet (Mark-of-the-Web, written
  by browsers and messenger apps),
- selected by you for scanning, or
- newly arrived in a watched folder (Downloads, Desktop, …).

The process is **suspended** (`NtSuspendProcess`), scanned while frozen, and
you choose: **Kill + Quarantine**, **Resume**, or **Trust — Don't Ask Again**
(persistent whitelist in `trusted_files.json`). A 30-second auto-resume keeps
the system usable. Local app dependencies (helpers, runtimes, installers'
child processes) are logged and allowed to run without interruption.

---

## 🚀 Quick Start (one command)

> **Prerequisite:** [Python 3.10+](https://www.python.org/downloads/) with
> *"Add python.exe to PATH"* ticked during installation.

After cloning the repo, run **`start.bat`** — double-click it, or:

```powershell
git clone https://github.com/<you>/srdc-guardian-static.git
cd srdc-guardian-static
.\start.bat
```

`start.bat` automatically:

1. finds your Python installation,
2. creates an isolated virtual environment (`.venv`),
3. installs all dependencies,
4. creates `.env` from the template,
5. runs the **first-run VirusTotal key wizard** — it offers to open
   [virustotal.com](https://www.virustotal.com) in your browser, waits for you
   to paste your free API key (required for full protection; the key is saved
   locally in `.env` and never uploaded anywhere), and
6. launches **SRDC Guardian** (a UAC admin prompt appears — this is normal; the
   process monitor needs it to suspend executables during scanning).

That's it — one command, and the Guardian is watching.

### Manual setup (alternative)

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python main.py
```

### Command-line scanner

For a full result object without the GUI:

```powershell
python scan_file.py "C:\path\to\file.exe" --json
```

---

## 🖥️ The App

- **Dashboard** — live stats (scanned / threats / ransomware / clean), watched
  folders, recent activity feed
- **History** — every scan with verdict, confidence, VT hits, entropy; CSV
  export
- **Quarantine** — restore or permanently delete intercepted files
- **Settings** — VirusTotal API key (masked with working Show/Hide, saved to
  `.env`), manage monitored folders at runtime
- **⏻ Quit Guardian** — one click shuts down all monitoring and exits cleanly

## 🔐 Privacy & Repository Safety

- Your `.env`, scan history, quarantine contents and trust list are
  **gitignored** — never committed, never uploaded
- Files are analyzed **locally**; VirusTotal receives only the SHA-256 hash
- No telemetry, no accounts, no cloud dependency for the analysis itself

## 📁 Project Structure

```text
├── start.bat                # One-command setup + launch + key wizard
├── main.py                  # Entry point + Tkinter GUI
├── config.py                # Settings (dynamic OS paths)
├── static_analysis.py       # Hashes, VT, signature, magic bytes, entropy, size, YARA
├── verdict.py               # Weighted verdict policy (VT major → weak signals)
├── scan_file.py             # Command-line scanner
├── process_monitor.py       # WMI watcher + foreign-file policy (suspend/resume/kill)
├── history_store.py         # Scan history (JSON + CSV export)
├── quarantine_manager.py    # Quarantine management
├── yara_rules/
│   └── basic_rules.yar      # YARA detection rules
└── quarantine/              # Created at runtime (gitignored)
```

## 📄 Resume Summary

Built **SRDC Guardian**, a Windows endpoint-security prototype that monitors
file and process activity, performs instant static malware analysis with
YARA, VirusTotal consensus and Authenticode signature verification, intercepts
internet-born executables via a Mark-of-the-Web foreign-file policy, and
presents fully explainable verdicts with quarantine and history tracking.

---

*Built as a security-engineering portfolio project — static analysis edition of
the SRDC Guardian family.*
