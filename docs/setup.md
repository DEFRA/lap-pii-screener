# Setup Guide

This guide takes you from nothing to a fully configured scanner. Work through it in order — each step builds on the previous one.

**Page contents**
- [What you need](#what-you-need)
- [Step 1 — Install Python](#step-1--install-python)
- [Step 2 — Get the code](#step-2--get-the-code)
- [Step 3 — Install Python packages](#step-3--install-python-packages)
- [Step 4 — Register the `sensitive-scanner` command](#step-4--register-the-sensitive-scanner-command)
- [Step 5 — Run the setup wizard](#step-5--run-the-setup-wizard)
- [Step 6 — Install SonarQube (recommended)](#step-6--install-sonarqube-recommended)
- [Step 7 — Install spaCy NLP model (optional)](#step-7--install-spacy-nlp-model-optional)
- [Verify your full setup](#verify-your-full-setup)
- [Air-gapped environments](#air-gapped-environments)
- [VS Code chat agent setup](#vs-code-chat-agent-setup)
- [Troubleshooting](#troubleshooting)

---

## What you need

| Requirement | Version | Purpose | Where to get it |
|---|---|---|---|
| **Python** | 3.11+ | The tool is written in Python | [python.org/downloads](https://www.python.org/downloads/) |
| **Java** | 17+ | Required for SonarQube (recommended) | [adoptium.net](https://adoptium.net/temurin/releases/) |
| **Git** | Any | Optional — needed for Git history scanning | [git-scm.com](https://git-scm.com/downloads) |
| **Internet access** | — | First-run downloads binaries automatically | — |

---

## Step 1 — Install Python

1. Go to [python.org/downloads](https://www.python.org/downloads/) and download the latest Python 3.x.
2. Run the installer. On the **first screen**, tick **"Add Python to PATH"** before clicking Install Now. If you miss this, commands will not work.
3. Click **Install Now** and wait for it to finish.

**Verify:**

```powershell
python --version
```

Expected output: `Python 3.14.0` (any 3.11+ is fine).

> **Seeing a Microsoft Store window?** Python was not added to PATH. Run this in PowerShell, then open a new terminal:
>
> ```powershell
> [Environment]::SetEnvironmentVariable(
>     "PATH",
>     "$env:LOCALAPPDATA\Python\pythoncore-3.14-64;$env:LOCALAPPDATA\Python\pythoncore-3.14-64\Scripts;" + [Environment]::GetEnvironmentVariable("PATH","User"),
>     "User"
> )
> ```
>
> Replace `3.14` with your installed version number.

---

## Step 2 — Get the code

```powershell
git clone https://github.com/DEFRA/lap-pii-screener C:\Github\lap-pii-screener
```

If you do not have Git, download the ZIP from the repository page, extract it, and place the folder at `C:\Github\lap-pii-screener`.

---

## Step 3 — Install Python packages

```powershell
cd C:\Github\lap-pii-screener
python -m pip install -r requirements.txt
```

You will see a lot of text scroll past — that is normal. Wait until you get a new `PS>` prompt.

---

## Step 4 — Register the `sensitive-scanner` command

This makes `sensitive-scanner` available from any folder, not just the project directory.

```powershell
cd C:\Github\lap-pii-screener
python -m pip install -e .
```

**Verify:**

```powershell
sensitive-scanner --help
```

You should see a list of available commands.

---

## Step 5 — Run the setup wizard

The wizard downloads Gitleaks and checks your environment. This installs everything needed for Tier 1 scanning (Gitleaks + Semgrep + Presidio).

```powershell
sensitive-scanner setup
```

Example output:

```
  Component    Status   Details
  Python       ✅       3.14.5
  Gitleaks     ✅       downloaded → C:\Users\you\.sensitive-scanner\bin\gitleaks.exe
  Semgrep      ✅       installed
  spaCy        –        optional — add --spacy to install
  SonarQube    –        optional — add --sonarqube to auto-download
```

A green tick (✅) means ready. A dash (–) means the component is optional and not installed.

---

## Step 6 — Install SonarQube (recommended)

SonarQube adds inter-procedural data-flow analysis and taint tracking that the pattern-based scanners cannot do. It is the most powerful scanner in the stack.

### 6a — Install Java 21

1. Go to [adoptium.net/temurin/releases](https://adoptium.net/temurin/releases/)
2. Select: **Version 21 (LTS)**, **OS Windows**, **Architecture x64**, **Package Type JDK**
3. Download the `.msi` installer
4. Run it. On the **"Custom Setup"** screen, make sure both **"Add to PATH"** and **"Set JAVA_HOME variable"** are ticked
5. Complete the installation

**Verify in a new terminal:**

```powershell
java -version
```

Expected: a line containing `openjdk version "21.x.x"`. Any version 17+ works.

### 6b — Download and configure SonarQube

```powershell
sensitive-scanner setup --sonarqube
```

This command will:

1. Check that Java is available and at a supported version
2. Download **sonar-scanner-cli** (~50 MB) — the agent that analyses code and sends results to SonarQube
3. Download **SonarQube Community Edition** (~500 MB) — the analysis server
4. Configure SonarQube to run on **port 9100** (not the default 9000, which conflicts with ZScaler on corporate laptops)
5. Start SonarQube and wait for it to become ready (2–3 minutes on first run while it builds its internal index)
6. Generate an API token automatically

When complete, the command prints:

```
SONAR_TOKEN=squ_abc123def456...
SONAR_HOST_URL=http://localhost:9100
```

**Save these two values.** Set them as permanent environment variables so they are available in every new terminal:

```powershell
[Environment]::SetEnvironmentVariable("SONAR_TOKEN", "squ_abc123def456...", "User")
[Environment]::SetEnvironmentVariable("SONAR_HOST_URL", "http://localhost:9100", "User")
```

Replace `squ_abc123def456...` with the actual token shown in the output.

Open a **new** PowerShell window after running these commands — environment variables only take effect in new terminals.

### Starting SonarQube after a reboot

SonarQube does not start automatically on login. Run this whenever you want to use it:

```powershell
& "$env:USERPROFILE\.sensitive-scanner\sonarqube\bin\windows-x86-64\StartSonar.bat"
```

Wait about 60 seconds for it to start, then scans will use it automatically.

### Token generation failed?

This happens if SonarQube's default admin password was already changed from a previous install. Generate a token manually:

1. Open [http://localhost:9100](http://localhost:9100) in a browser
2. Log in (default credentials: `admin` / `admin`, or whatever you changed it to)
3. Go to **Account → Security → Generate Tokens**
4. Give it a name (e.g. `pii-screener`) and click **Generate**
5. Copy the token and set the environment variable as above

---

## Step 7 — Install spaCy NLP model (optional)

spaCy adds named entity recognition: the scanner can detect person names and locations written inside code comments or string values — things no regex can reliably catch.

```powershell
sensitive-scanner setup --spacy
```

This downloads the `en_core_web_sm` English language model (~15 MB).

---

## Verify your full setup

At any time, run:

```powershell
sensitive-scanner status
```

This shows the active tier and the status of each component without changing anything.

```powershell
sensitive-scanner setup --check
```

This checks every component and reports what is ready and what is missing.

---

## Air-gapped environments

If the machine that will do the scanning has no internet access, you can create an installation bundle on a connected machine and transfer it.

### Create the bundle (on a connected machine)

```powershell
sensitive-scanner setup --airgap
```

This downloads all binaries (Gitleaks, sonar-scanner-cli, SonarQube) and the Python package wheels into a single `.zip` bundle in the current directory.

### Deploy the bundle (on the air-gapped machine)

Copy the bundle to the target machine, then:

```powershell
sensitive-scanner setup --airgap-bundle C:\path\to\bundle.zip
```

This installs everything from the local bundle without making any network requests.

### Python packages in air-gapped mode

The `requirements.txt` file lists all dependencies with pinned versions. On a connected machine, run:

```powershell
pip download -r requirements.txt --dest C:\bundle\wheels
```

Transfer the `wheels` folder to the air-gapped machine alongside the code, then:

```powershell
pip install --no-index --find-links C:\bundle\wheels -r requirements.txt
```

---

## VS Code chat agent setup

The MCP server lets you talk to the scanner in plain English inside VS Code Copilot Chat:
*"scan C:\Github\MyProject and show me the critical findings"*

### Find your Python path

```powershell
python -c "import sys; print(sys.executable)"
```

Copy the full path printed — for example `C:\Users\YourName\AppData\Local\Python\pythoncore-3.14-64\python.exe`.

### Register the server in VS Code

1. Open VS Code
2. Go to **File → Preferences → Settings** (or `Ctrl+,`)
3. Search for `mcp` and click **"Edit in settings.json"**
4. Add the following inside your settings JSON (merge into an existing `"mcp"` block if one already exists):

```json
"mcp": {
  "servers": {
    "pii-screener": {
      "command": "C:\\Users\\YourName\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe",
      "args": ["C:\\Github\\lap-pii-screener\\server.py"],
      "env": {
        "SONAR_HOST_URL": "http://localhost:9100",
        "SONAR_TOKEN": "squ_abc123..."
      }
    }
  }
}
```

Replace `command` with your Python path (use double backslashes). Set `SONAR_TOKEN` to your token, or leave it as `""` if you skipped the SonarQube step.

5. Save the file and restart VS Code

### Using the agent

Open Copilot Chat (`Ctrl+Alt+I`), ensure **Agent** mode is selected, and type naturally:

| Example | What happens |
|---|---|
| `scan C:\Github\MyProject` | Full scan, shows summary |
| `show me high and critical findings` | Filters last results |
| `get the report as html` | Returns HTML report |
| `get remediation for finding abc123` | Shows fix steps |
| `check scanner status` | Reports active tier |

---

## Troubleshooting

### `sensitive-scanner` is not recognised as a command

Run `python -m pip install -e .` from the `C:\Github\lap-pii-screener` folder. If that fails, check that `~\AppData\Local\Python\pythoncore-3.x\Scripts` is on your PATH.

### SonarQube does not start

- Check Java is installed: `java -version`
- Check port 9100 is not in use: `netstat -an | findstr 9100`
- Check the SonarQube logs: `~\.sensitive-scanner\sonarqube\logs\sonar.log`

### SonarQube starts but token is invalid

Environment variables are only read in terminals opened *after* they were set. Open a new PowerShell window. If scans still fail, verify the values with:

```powershell
echo $env:SONAR_TOKEN
echo $env:SONAR_HOST_URL
```

### Semgrep is slow

Semgrep downloads rule definitions from the internet on first run. On subsequent runs they are cached. If you are behind a proxy, set the `HTTPS_PROXY` environment variable before running the scan.

### spaCy model is missing

```powershell
python -m spacy download en_core_web_sm
```

### `pip install` fails with SSL error

Your machine may be behind a corporate proxy that intercepts SSL. Try:

```powershell
python -m pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```
