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
- **YARA rules** from `yara_rules/` (tuned to avoid false positives on clean
  installers — see the false-positive policy below)

Signals are combined with a weighted verdict policy — VirusTotal consensus is
the major signal, magic-byte mismatch and signature validity are medium-strong,
YARA/entropy/size are medium-to-weak — producing **Clean / Suspicious /
Ransomware** with an honest confidence level.

### False-positive policy (built after real-world tuning)

A security tool that screams "malware" at every clean installer teaches users
to ignore it. Four mechanisms keep the verdicts honest:

- **Corroborated YARA rules** — no rule ships with a single loose string as
  its trigger: `wannacry_indicator` and `locky_indicator` need **2 of** their
  strings, `double_extension_exe` requires an MZ header *at offset 0* **and** a
  double extension, and `crypto_ransom_generic` raises its bar by requiring a
  known family name **or** a ransom-note phrase **combined with** a Windows
  crypto API. The base64-blob rule needs a 500+ character run (a 100+ char
  threshold fired on legitimate binaries, embedded certificates and resources).
- **Corroboration rule** — a single weak hit (one YARA match, high entropy) is
  reported as *information*, not a threat. A **Suspicious** verdict requires
  either a strong local indicator (lying extension, invalid signature,
  VirusTotal flag) or a score of 4+, i.e. multiple weaker signals agreeing.
- **Type-aware entropy** — high entropy is normal for `.zip`, `.docx`, `.jpg`
  and `.mp4`, so it is only treated as a signal for formats where packed or
  encrypted bytes are unexpected (`.exe`, `.dll`, `.txt`, …).
- **Trust evidence counts** — a valid Authenticode signature from a trusted
  publisher and a broad clean VirusTotal consensus actively lower the
  suspicion score and raise confidence, so a signed installer with YARA noise
  stays **Clean**.

> **Known limitation (honest disclosure):** the bundled rules are *string*
> matches, so a document that merely *discusses* ransomware — naming
> `WannaCry`/`Ryuk`, or quoting a ransom note next to a WinCrypto API name —
> can still match. That is why no YARA hit alone can produce a Suspicious
> verdict. Replace or extend `yara_rules/` with community rules
> (e.g. YARA-Marketplace) for production-grade detection.

**No VirusTotal key?** Everything still works locally: the verdict engine says
so explicitly ("VirusTotal reputation unavailable — relying on local static
analysis only") and reports **Low confidence** instead of pretending to have
reputation it doesn't have.

## 🚦 Process interception (foreign-file policy)

Newly launched `.exe` files are intercepted via WMI **only when they are
foreign**:

- tagged by Windows as downloaded from the internet (Mark-of-the-Web, written
  by browsers and messenger apps),
- selected by you for scanning, or
- newly arrived in a watched folder (Downloads, Desktop, …).

The process is **suspended** (`NtSuspendProcess`), scanned while frozen, and
you choose: **Kill + Quarantine**, **Resume**, or **Trust — Don't Ask Again**
(persistent whitelist in `trusted_files.json`). A **30-second auto-resume**
keeps the system usable for *Suspicious* and *Clean* verdicts, but a **confirmed
Ransomware is held frozen until you explicitly decide** — the timer never
releases a real threat. Local app dependencies (helpers, runtimes, installers'
child processes) are logged and allowed to run without interruption.

### Known limitation (the trust model)

"Foreign" is inferred **primarily from the Mark-of-the-Web `Zone.Identifier`
stream** — a label a file carries about itself, not a property bound to its
contents. That label is not tamper-proof:

- it can be **stripped** (`type malware.exe > copy.exe`,
  `Remove-Item file.exe:Zone.Identifier`, re-saving through an editor, or
  copying out-and-back over a FAT/exFAT USB drive, which cannot hold ADS), or
- it can **age out** — a file older than the 24-hour freshness window no longer
  counts as a fresh download, and
- some delivery paths never stamp zone 3/4 at all (running from inside an
  archive, or a **network share**, which Windows tags as zone 2 / intranet).

So a file executed from a folder you are **not** watching, with the mark removed
or aged past the window, will run **un-intercepted**. Anything that *lands in a
watched folder* is still caught by the file watcher regardless of the mark.
Closing the remaining gap entirely needs a heavier reputation/behaviour model
rather than provenance inference — deliberately out of scope for a lightweight
static-analysis prototype. This is a **detection-coverage limit, not a code bug**.

---

## 🚀 Quick Start (one command)

> **Prerequisite:** [Python 3.10+](https://www.python.org/downloads/) with
> *"Add python.exe to PATH"* ticked during installation, plus a **free
> [VirusTotal API key](https://www.virustotal.com)** (sign up → click your
> avatar → **API key** → copy the 64-character string). The key powers the
> strongest signal — 70+ engine consensus — but the app still runs without it.

After cloning the repo, run **`start.bat`** — double-click it, or:

```powershell
git clone https://github.com/Thoparambharath007/srdc-guardian-static.git
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

### Tests

The verdict engine and every static check have unit tests:

```powershell
python -m pytest tests/ -v
```

or with no extra dependencies (the files are plain pytest-compatible and also
run standalone):

```powershell
python tests/test_verdict.py
python tests/test_static_analysis.py
```

The suite locks in the false-positive policy: a single generic YARA hit on a
file with no VirusTotal reputation must stay **Clean**, corroborated weak
signals must be **Suspicious**, a lying extension is **Suspicious** on its
own, a trusted signature overrides YARA noise, and broad multi-engine flags
reach **Ransomware**. `tests/test_imports.py` additionally guards against a
regression where importing `main` popped a UAC dialog, and
`tests/test_storage.py` covers history and quarantine persistence.

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
├── .env.example             # Config template (copied to .env on first run)
├── yara_rules/
│   └── basic_rules.yar      # YARA detection rules (false-positive-tuned)
├── tests/
│   ├── test_imports.py      # Import side-effect regression guard
│   ├── test_verdict.py      # Verdict-policy unit tests
│   ├── test_static_analysis.py  # Static-check unit tests
│   └── test_storage.py      # History + quarantine unit tests
├── trusted_files.json       # Trust whitelist (created at runtime, gitignored)
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
