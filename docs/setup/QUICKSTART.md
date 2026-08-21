# Quick Start — Zero to Scanning in 6 Steps

This gets you from a blank laptop to a working scanner with a local SonarQube instance.
If anything goes wrong, see the full [Setup Guide](setup.md).

---

## What you need first

Before running any commands, install these two things manually:

1. **Python 3.11+** → https://www.python.org/downloads/  
   ⚠ On the installer's first screen, tick **"Add Python to PATH"** before clicking Install Now.

2. **Java 17 or newer** → https://adoptium.net/temurin/releases/  
   Download a Windows x64 JDK. On the "Custom Setup" screen, tick **"Add to PATH"** and **"Set JAVA_HOME variable"**.

Open a **new** PowerShell window after both installs. Then continue below.

---

## Step 1 — Get the code

```powershell
git clone https://github.com/DEFRA/lap-pii-screener C:\Github\lap-pii-screener
cd C:\Github\lap-pii-screener
```

---

## Step 2 — Install dependencies

```powershell
pip install uv
uv sync
```

`uv sync` reads `pyproject.toml` and `uv.lock` to install the base dependencies at their exact pinned versions, then registers the `sensitive-scanner` command automatically. Optional document extractors are installed separately with `uv sync --extra docs`.

---

## Step 3 — Run setup (downloads everything automatically)

```powershell
sensitive-scanner setup --all
```

This downloads Gitleaks, installs Semgrep and spaCy, downloads SonarQube (~500 MB), and
starts it. The setup command saves `SONAR_TOKEN` and `SONAR_HOST_URL` to the user
environment when token creation succeeds; open a new terminal before scanning so the
variables are available.

> ⏳ The first run takes 3–5 minutes while SonarQube starts for the first time.

---

## Step 4 — Open a new terminal

Environment variables written in Step 3 only take effect in **new** terminal windows.
Close this PowerShell window and open a fresh one.

---

## Step 5 — Scan something

```powershell
sensitive-scanner scan C:\path\to\your\project
```

Results print to the terminal with colour coding. To save an HTML report instead:

```powershell
sensitive-scanner scan C:\path\to\your\project --format html --output report.html
```

---

## Step 6 — (Optional) Check everything is healthy

```powershell
sensitive-scanner status
```

You should see `Active tier: 2` which means SonarQube is running and being used.

---

## Starting SonarQube after a reboot

SonarQube does not start automatically on login. Run this when you want it:

```powershell
& "$env:USERPROFILE\.sensitive-scanner\sonarqube\bin\windows-x86-64\StartSonar.bat"
```

Wait ~60 seconds, then scans will use it automatically.

---

## Something went wrong?

```powershell
sensitive-scanner setup --check --sonarqube
```

This shows the status of every component without changing anything, so you can see
exactly what is missing. Then check the [full guide](setup.md#troubleshooting) for that specific issue.
