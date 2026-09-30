@echo off
setlocal
cd /d "%~dp0"
title SRDC Guardian - Static Edition

rem ============================================================
rem  SRDC Guardian - one-command setup and launch
rem  Creates the virtualenv, installs dependencies, creates
rem  .env from the template, offers first-run VirusTotal API
rem  key setup, then starts the app.
rem ============================================================

rem --- 1. Find a usable Python 3 installation ---
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [ERROR] Python 3 was not found on this PC.
    echo         Install it from https://www.python.org/downloads/
    echo         and tick "Add python.exe to PATH" during setup,
    echo         then run this file again.
    pause
    exit /b 1
)

rem --- 2. Create the virtual environment on first run ---
if not exist ".venv\Scripts\python.exe" (
    echo [*] Creating virtual environment...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Could not create the virtual environment.
        pause
        exit /b 1
    )
)

call ".venv\Scripts\activate.bat"

rem --- 3. Install dependencies (fast when already installed) ---
echo [*] Installing dependencies...
python -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Dependency installation failed. Check your internet connection.
    pause
    exit /b 1
)

rem --- 4. Create .env from the template on first run ---
if not exist ".env" (
    copy ".env.example" ".env" >nul
)

rem --- 5. First-run VirusTotal API key setup (skipped once a VALID key is saved) ---
rem     A value shorter than 32 chars (e.g. a stray keystroke like "Y") is treated
rem     as "not set", so the wizard re-prompts instead of locking in a broken key.
python -c "import sys;from dotenv import dotenv_values;v=(dotenv_values('.env').get('VT_API_KEY') or '').strip();sys.exit(0 if len(v)>=32 else 1)"
if not errorlevel 1 goto vt_done
echo.
echo  ============================================================
echo    VIRUS TOTAL API KEY   ^(REQUIRED^)
echo  ============================================================
echo    Guardian checks every file against 70+ antivirus
echo    engines before you run it - the API key powers this.
echo    This is the most important step of the setup.
echo.
echo    Create your free key at:  https://www.virustotal.com
echo    ^(Sign up -^> click your avatar -^> API key -^> copy^)
echo.
choice /C YN /N /M "   Open virustotal.com in your browser now? [Y/N]: "
if errorlevel 2 goto vt_ask
start "" https://www.virustotal.com
:vt_ask
set "VTKEY="
set /p "VTKEY=   Paste your API key here: "
python -c "import sys;v=(sys.argv[1] if len(sys.argv)>1 else '').strip();sys.exit(0 if len(v)>=32 else 1)" "%VTKEY%"
if not errorlevel 1 goto vt_save
echo    [!] That doesn't look like a valid key - it must be at least 32 characters.
echo        Get your free 64-char key at https://www.virustotal.com and paste it again.
goto vt_ask
:vt_save
python -c "from dotenv import set_key; set_key('.env', 'VT_API_KEY', '%VTKEY%'.strip(), quote_mode='auto')"
echo    [*] API key saved to .env - you can change it later in Settings.
:vt_done

rem --- 6. Launch the app (a UAC admin prompt is normal) ---
echo [*] Starting SRDC Guardian...
python main.py
if errorlevel 1 pause
