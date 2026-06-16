# Sensitive Code Scanner — Setup & Troubleshooting Guide

> **Reading this for the first time?**  Start at [Before you begin](#before-you-begin) and work
> through each section in order.  Every command is explained before you are asked to run it.
> Nothing is assumed.

---

## What is this tool?

This tool scans a folder of code and tells you if it contains anything sensitive that should not
be there — things like passwords, API keys, and personal data (PII) such as email addresses,
national insurance numbers, or credit card numbers.

It is useful before sharing code with another team, publishing a repository, or as a regular
health check during development.

You can use it in two ways:

- **As a command you type in a terminal** — the "CLI" (Command Line Interface).  Works anywhere,
  no VS Code required.
- **As a chat assistant inside VS Code** — you describe what you want in plain English and the
  agent runs the scan for you.

---

## What does it find?

| What | Examples |
|---|---|
| API keys & tokens | AWS, Azure, GitHub, Stripe, Slack keys, JWT tokens |
| Passwords & credentials | Hardcoded passwords, database connection strings, private keys |
| Personal data (structured) | Email addresses, phone numbers, credit card numbers, NI numbers, passports, dates of birth, SSNs, IBANs |
| Personal data (unstructured) | People's names and locations written inside code comments or strings |
| High-entropy secrets | Random-looking strings that are likely secret tokens |

Every finding includes the file name, line number, a redacted preview of the value, and
step-by-step instructions for fixing it.

---

## How it works (the short version)

The tool runs up to four different "scanners" at the same time and combines their results:

| Scanner | What it does |
|---|---|
| **Gitleaks** | Finds secrets using pattern matching — fast and lightweight |
| **Semgrep** | Reads code like a compiler does — catches things pattern matching misses |
| **PII scanner** | Custom rules for personal data (regex + optional AI model) |
| **SonarQube** | Enterprise-grade analysis — catches the most subtle issues |

You do not need all four to get useful results.  Gitleaks + Semgrep + PII are the default and
work without any extra infrastructure.  SonarQube is optional and adds deeper analysis.

---

## Before you begin

### What you need

| Requirement | Why | Where to get it |
|---|---|---|
| **Windows 10 or 11 (64-bit)** | The tool runs on Windows, macOS, and Linux.  This guide uses Windows. | Already installed |
| **Python 3.11 or newer** | The tool is written in Python | [python.org/downloads](https://www.python.org/downloads/) |
| **Git** (optional) | Only needed if you want to scan old commit history | [git-scm.com](https://git-scm.com/downloads) |
| **Java 17 or newer** (optional) | Only needed for SonarQube — the most powerful scanner | [adoptium.net](https://adoptium.net/temurin/releases/) |
| **Internet connection** | The first-time setup downloads tools automatically | — |

> **Not sure if you have Python?**  Skip ahead to [Step 1](#step-1--install-python) to check.

---

## Installation

Follow these steps in order.  Each step builds on the previous one.

---

### Step 1 — Install Python

**What this does:** Python is the programming language the tool is written in.  Without it,
nothing will run.

1. Open a browser and go to **https://www.python.org/downloads/**
2. Click the big yellow **"Download Python 3.x.x"** button (the exact version number doesn't
   matter as long as it's 3.11 or higher).
3. Run the installer.
4. **Important:** On the first screen of the installer, tick the box that says
   **"Add Python to PATH"** before clicking Install Now.  If you miss this, Python commands
   won't work in the terminal.
5. Click **Install Now** and wait for it to finish.
6. Click **Close**.

**Verify it worked.** Open a new terminal window (search for "PowerShell" in the Start menu),
type the following, and press Enter:

```powershell
python --version
```

You should see something like `Python 3.14.0`.  Any version 3.11 or higher is fine.

> **Seeing a Microsoft Store window instead?** This means Python is not on your PATH yet.
> Run this command in PowerShell (copy and paste the whole thing):
>
> ```powershell
> [Environment]::SetEnvironmentVariable(
>     "PATH",
>     "$env:LOCALAPPDATA\Python\pythoncore-3.14-64;$env:LOCALAPPDATA\Python\pythoncore-3.14-64\Scripts;" + [Environment]::GetEnvironmentVariable("PATH","User"),
>     "User"
> )
> ```
>
> Then **close PowerShell completely** and open a new one.  Try `python --version` again.
> Replace `3.14` in the path above with whatever version you installed if it's different.

---

### Step 2 — Get the code

**What this does:** Downloads the scanner tool to your computer.

Open PowerShell and run:

```powershell
git clone https://github.com/DEFRA/lap-pii-screener C:\Github\lap-pii-screener
```

If you do not have Git installed, you can instead download a ZIP from the repository website
(look for a "Code" or "Download ZIP" button), extract it, and place the folder at
`C:\Github\lap-pii-screener`.

---

### Step 3 — Install Python packages

**What this does:** Downloads the third-party libraries the tool depends on (things like the
library that produces coloured terminal output, the YAML configuration reader, etc.).

In PowerShell, navigate into the project folder and run the install:

```powershell
cd C:\Github\lap-pii-screener
python -m pip install -r requirements.txt
```

You will see a lot of text scroll past — that is normal.  Wait until you get a new `PS>` prompt.

> **What is pip?** `pip` is Python's built-in package manager — like an app store for Python
> libraries.  The `-r requirements.txt` part tells it to install everything listed in
> the `requirements.txt` file.

---

### Step 4 — Register the `sensitive-scanner` command

**What this does:** Makes `sensitive-scanner` available as a command you can type from
any folder, rather than having to be inside the project folder every time.

```powershell
cd C:\Github\lap-pii-screener
python -m pip install -e .
```

The `-e .` means "install this project in editable mode from the current folder (`.`)".

Verify it worked:

```powershell
sensitive-scanner --help
```

You should see a list of available commands.  If you see an error, see the
[Troubleshooting](#troubleshooting) section.

---

### Step 5 — Run the setup wizard

**What this does:** Checks your installation, automatically downloads Gitleaks, installs
Semgrep, and reports what is ready.  This is the fastest way to get the basic scanner working.

```powershell
sensitive-scanner setup
```

You will see a progress spinner for each component, then a summary table like this:

```
  Component    Status   Details
  Python       ✅       3.14.5
  Gitleaks     ✅       downloaded → C:\Users\you\.sensitive-scanner\bin\gitleaks.exe
  Semgrep      ✅       installed
  spaCy        –        optional — add --spacy to install
  SonarQube    –        optional — add --sonarqube to auto-download
```

A green tick (✅) means that component is ready.  A dash (–) means it's optional and not
installed — that is fine for now.

**That's it for the basic setup.**  You can now scan code.  Continue reading for how to
run your first scan, or keep going to set up the optional components.

---

### Step 6 — (Optional) Add SonarQube for deeper analysis

**What this does:** Downloads and configures SonarQube Community Edition — a professional
code analysis server that runs locally on your machine.  It catches a broader range of issues
than the basic scanners.  This step downloads about 550 MB in total.

**You will need Java 17+ installed first** (see below).

#### 6a — Install Java

1. Go to **https://adoptium.net/temurin/releases/**
2. Under "Version", select **21 (LTS)**.  Under "OS", select **Windows**.  Under "Architecture",
   select **x64**.  Under "Package Type", select **JDK**.
3. Download the `.msi` file (the Windows installer).
4. Run it.  On the "Custom Setup" screen, make sure **"Add to PATH"** and **"Set JAVA_HOME
   variable"** are both ticked.
5. Click through to finish.
6. Open a **new** PowerShell window and verify:

```powershell
java -version
```

You should see a line containing `openjdk version "21.x.x"` or similar.  Any version 17 or
higher works.

#### 6b — Auto-download and configure SonarQube

Once Java is installed, run:

```powershell
sensitive-scanner setup --sonarqube
```

This will:
1. Check Java is available.
2. Download **sonar-scanner-cli** (the component that sends code to SonarQube) — ~50 MB.
3. Download **SonarQube Community Edition** (the analysis server) — ~500 MB.
4. Automatically configure it to use **port 9100** (not the default 9000, which conflicts with
   ZScaler on company laptops).
5. Start SonarQube and wait for it to be ready (~2 minutes on first start because it builds an
   internal search index).
6. Attempt to generate an API token automatically.

When finished, if the token was created automatically, you will see something like:

```
SONAR_TOKEN=squ_abc123def456...
SONAR_HOST_URL=http://localhost:9100
```

**Save these two values** — you will need them in Step 7 (MCP setup) and again any time you
restart your computer.

**Set them as permanent environment variables** so every terminal session has them:

```powershell
[Environment]::SetEnvironmentVariable("SONAR_TOKEN", "squ_abc123def456...", "User")
[Environment]::SetEnvironmentVariable("SONAR_HOST_URL", "http://localhost:9100", "User")
```

Replace `squ_abc123def456...` with the actual token shown by the setup command.

> **Didn't get a token automatically?**  This happens when SonarQube's default admin password
> was already changed on a previous install.  See
> [Generating a token manually](#generating-a-sonarqube-token-manually).

---

### Step 7 — (Optional) Add spaCy for unstructured PII detection

**What this does:** Adds a small AI language model that can spot people's names and locations
written inside code comments and string values — things that pattern matching alone would miss.
Downloads about 15 MB.

```powershell
sensitive-scanner setup --spacy
```

This installs the spaCy library and downloads the `en_core_web_sm` English language model.

---

### Check your full setup

At any point you can check what is installed without changing anything:

```powershell
sensitive-scanner setup --check
```

Or for a more detailed view of active scanner tiers:

```powershell
sensitive-scanner status
```

```

---

## Your first scan

Once setup is complete, open a PowerShell window and run:

```powershell
sensitive-scanner scan C:\path\to\your\project
```

Replace `C:\path\to\your\project` with the actual folder you want to scan.  For example:

```powershell
sensitive-scanner scan C:\Github\MyProject
```

You will see a spinner while the scan runs, then a colour-coded table of findings in the terminal.
If nothing sensitive is found, you will see "Scan complete — Total: 0".

### Save the results to a file

```powershell
# HTML report — open in any browser
sensitive-scanner scan C:\Github\MyProject --format html --output report.html

# Markdown — opens in VS Code, Confluence, GitHub
sensitive-scanner scan C:\Github\MyProject --format markdown --output report.md
```

The HTML report is fully self-contained — you can email it or attach it to a ticket.

---

## Understanding the results

Each finding in the report contains:

| Column | What it means |
|---|---|
| **Severity** | How serious the issue is: Critical → High → Medium → Low |
| **Category** | The type of issue, e.g. `pii_email`, `aws_access_key`, `hardcoded_password` |
| **File** | The file path relative to the folder you scanned |
| **Line** | The line number in that file |
| **Match** | A redacted preview — e.g. `john***` — not the full value |
| **Rule** | The rule ID that triggered this finding — useful for suppressing false positives |
| **Scanners** | Which scanner(s) caught this (multiple means higher confidence) |
| **Fix** | Step-by-step remediation instructions |

### Severity levels

| Severity | Meaning | What to do |
|---|---|---|
| **Critical** | Exposed secret or PII that is almost certainly real | Fix immediately |
| **High** | Strong likelihood of a real issue | Fix before sharing the code |
| **Medium** | Could be an issue — review the context | Investigate and fix or suppress |
| **Low** | Weak signal — probably fine but worth a look | Review at your convenience |

### "This is a false positive — how do I stop it appearing?"

A false positive is when the scanner flags something that is not actually sensitive — for
example, a placeholder value like `email@example.com` in a test file.

**One-time suppression** (just for this run):

```powershell
sensitive-scanner scan C:\Github\MyProject --suppress "pii_email"
```

**Permanent suppression** (suppressed on every future scan):

Open the file `C:\Github\lap-pii-screener\config\suppress.txt` in any text editor and add the Rule
ID on a new line:

```
# This is a test fixture — not real PII
pii_email
```

The Rule ID is shown in the "Rule" column of every finding.

**Suppress a single line in your code** by adding a comment:

```python
test_email = "user@example.com"  # noscan
```

Or to suppress a specific rule only:

```python
test_email = "user@example.com"  # noscan: pii_email
```

---

## Setting up the VS Code chat agent

This lets you talk to the scanner in plain English inside VS Code Copilot Chat — for example:
*"scan the code at C:\Github\MyProject and show me the critical findings"*.

### Step 1 — Find your Python path

In PowerShell:

```powershell
python -c "import sys; print(sys.executable)"
```

This prints the full path to your Python executable, for example:
`C:\Users\YourName\AppData\Local\Python\pythoncore-3.14-64\python.exe`

Copy this value — you will need it in the next step.

### Step 2 — Register the server in VS Code

1. Open VS Code.
2. Go to **File → Preferences → Settings** (or press `Ctrl+,`).
3. In the search box at the top, type `mcp`.
4. Click **"Edit in settings.json"**.
5. You will see a file open.  Find the closing `}` at the very end of the file.
   Before it, add the following block.  If there is already an `"mcp"` key, merge the
   `"servers"` section into it instead of adding a second `"mcp"` block.

```json
"mcp": {
  "servers": {
    "pii-screener": {
      "command": "C:\\Users\\YourName\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe",
      "args": ["C:\\Github\\lap-pii-screener\\server.py"],
      "env": {
        "SONAR_HOST_URL": "http://localhost:9100",
        "SONAR_TOKEN": ""
      }
    }
  }
}
```

Replace the `command` value with the Python path from Step 1 (use double backslashes `\\`).
Replace `SONAR_TOKEN` with your token from the SonarQube setup — leave it blank (`""`) if you
skipped the SonarQube step.

6. Save the file (`Ctrl+S`).
7. Restart VS Code.

### Step 3 — Use the agent

1. Open the Copilot Chat panel (the speech-bubble icon in the left sidebar, or `Ctrl+Alt+I`).
2. Make sure **Agent** mode is selected at the top of the chat panel (not "Ask" or "Edit").
3. Type your request, for example:

```
scan C:\Github\MyProject and show me any critical findings
```

The agent will run the scan and display a formatted summary in the chat.

### What can you ask the agent?

| Example prompt | What happens |
|---|---|
| `scan C:\Github\MyProject` | Runs a full scan and shows a summary |
| `list all high and critical findings` | Filters the last scan without re-scanning |
| `show findings in the auth folder` | Filters by file path |
| `get the report as html` | Returns the last scan report as HTML |
| `get remediation for finding abc123` | Shows the fix steps for a specific finding |
| `check scanner status` | Reports which scanners are active |

---

## CLI reference

### `setup` — install and configure dependencies

```powershell
sensitive-scanner setup                  # installs Gitleaks + Semgrep
sensitive-scanner setup --spacy          # also installs spaCy NLP model
sensitive-scanner setup --sonarqube      # also downloads SonarQube CE (~550 MB)
sensitive-scanner setup --all            # installs everything
sensitive-scanner setup --check          # reports status without installing anything
```

---

### `scan` — scan a directory

```powershell
sensitive-scanner scan <path> [options]
```

**Examples**

```powershell
# Default colour-coded console output
sensitive-scanner scan C:\Github\MyProject

# Give the project a name (used in the report header)
sensitive-scanner scan C:\Github\MyProject --project "My Project"

# Save a self-contained HTML report
sensitive-scanner scan C:\Github\MyProject --format html --output report.html

# Save a Markdown report
sensitive-scanner scan C:\Github\MyProject --format markdown --output report.md

# Save a JSON file for automated processing
sensitive-scanner scan C:\Github\MyProject --format json --output findings.json

# Run only specific scanners (faster)
sensitive-scanner scan C:\Github\MyProject --scanners gitleaks,pii

# Include git history — catches secrets in old commits
sensitive-scanner scan C:\Github\MyProject --history

# Exclude additional folders from the scan
sensitive-scanner scan C:\Github\MyProject --exclude "test-fixtures,docs"

# Stop with an error code if critical issues are found (useful in CI pipelines)
sensitive-scanner scan C:\Github\MyProject --fail-on critical
```

**All options**

| Option | Short | Default | Description |
|---|---|---|---|
| `--format` | `-f` | `console` | Output format: `console`, `markdown`, `html`, `json` |
| `--output` | `-o` | terminal | File to write the report to |
| `--project` | `-p` | folder name | Project name shown in the report |
| `--scanners` | `-s` | all | Comma-separated: `gitleaks`, `semgrep`, `pii`, `sonarqube` |
| `--history` | | off | Scan git commit history as well as working files |
| `--show-secrets` | | off | Show full matched values instead of redacting them |
| `--exclude` | `-e` | | Extra folder names to skip |
| `--suppress` | | | Comma-separated rule IDs to hide from results for this run |
| `--fail-on` | | none | Exit with code 2 if a finding at or above this severity exists |
| `--config` | `-c` | auto-detect | Path to a YAML config file |
| `--per-file` | | off | Write one report file per scanned source file |
| `--output-dir` | | `scan-reports/` | Directory for per-file reports (implies `--per-file`) |

**Folders the scanner skips automatically**

These are never scanned regardless of what you pass in:

`.git` · `.vs` · `.vscode` · `.idea` · `node_modules` · `__pycache__` · `.pytest_cache` ·
`venv` · `.venv` · `env` · `dist` · `build` · `target` · `out` · `bin` · `obj` · `.gradle`

---

### `status` — check what is installed

```powershell
sensitive-scanner status
```

Shows which scanners are available, whether Java and SonarQube are detected, and the active
tier (1, 2, or 3).

---

### `report` — re-export the last scan without re-scanning

```powershell
sensitive-scanner report --format html --output report.html
sensitive-scanner report --format markdown
```

---

## Generating a SonarQube token manually

If `sensitive-scanner setup --sonarqube` could not create a token automatically (because the
default admin password was already changed), do this:

1. Make sure SonarQube is running.  If it is not, start it:

```powershell
& "C:\Users\YourName\.sensitive-scanner\sonarqube\bin\windows-x86-64\StartSonar.bat"
```

Wait about 2 minutes.  A CMD window will appear — leave it open.

2. Open a browser and go to **http://localhost:9100**
3. Log in with your admin username and password.
4. Click your account icon (top right) → **My Account**.
5. Click the **Security** tab.
6. Under "Generate Tokens", enter a name (e.g. `scanner`), leave the type as **User Token**,
   and click **Generate**.
7. A token string appears (starts with `squ_`).  **Copy it immediately** — it will not be
   shown again.
8. Save it permanently:

```powershell
[Environment]::SetEnvironmentVariable("SONAR_TOKEN", "squ_your_token_here", "User")
[Environment]::SetEnvironmentVariable("SONAR_HOST_URL", "http://localhost:9100", "User")
```

Replace `squ_your_token_here` with the actual token.

9. Also paste the token into the `settings.json` `"SONAR_TOKEN"` field if you set up the
   VS Code agent.

---

## Starting SonarQube after a restart

SonarQube does not start automatically when you reboot your computer.  Whenever you want to
use SonarQube-level scanning, start it first:

```powershell
& "C:\Users\YourName\.sensitive-scanner\sonarqube\bin\windows-x86-64\StartSonar.bat"
```

Wait about 60–90 seconds.  You will know it is ready when you can open
**http://localhost:9100** in a browser and see the login page (or the dashboard if you are
already logged in).

> **Tip:** If you find yourself starting SonarQube often, you can create a desktop shortcut to
> `StartSonar.bat`.

---

## Troubleshooting

### The `sensitive-scanner` command is not found

**Symptom:** Typing `sensitive-scanner` gives "The term 'sensitive-scanner' is not recognized".

**Fix:**

```powershell
cd C:\Github\lap-pii-screener
python -m pip install -e .
```

If that still does not work, the Python `Scripts` folder is probably not on your PATH.  Run:

```powershell
python -c "import sys; print(sys.executable)"
```

Note the folder shown (e.g. `C:\Users\YourName\AppData\Local\Python\pythoncore-3.14-64\`).
The `Scripts` subfolder of that path needs to be on your PATH.  You can run the fix command
from [Step 1](#step-1--install-python) above, substituting your actual Python version.

Close and reopen PowerShell after running the fix.

---

### `python` opens the Microsoft Store

**Symptom:** Typing `python` opens the Microsoft Store app.

**Fix:** Python is not on your PATH.  Run the PATH fix command from
[Step 1](#step-1--install-python), replacing `3.14` with your installed version.  Then
close and reopen PowerShell.

---

### `pip install` fails with a permissions error

**Symptom:** Error message contains "Access is denied" or "Permission denied".

**Fix:** Run PowerShell as Administrator, or add `--user` to the pip command:

```powershell
python -m pip install --user -r requirements.txt
python -m pip install --user -e .
```

---

### `mcp` library is outdated after installing semgrep

**Symptom:** The VS Code agent gives an error about `mcp` version, or `server.py` crashes on
import.

**Cause:** The `semgrep` package has older dependencies that sometimes downgrade `mcp`.

**Fix:**

```powershell
python -m pip install "mcp[cli]>=1.9.0" --upgrade
```

---

### SonarQube download fails or stalls

**Symptom:** `sensitive-scanner setup --sonarqube` hangs for more than 10 minutes or fails
with a connection error.

**Fixes to try in order:**

1. Check your internet connection.
2. If you are on a VPN or proxy, try disconnecting temporarily.
3. The file is ~500 MB — allow at least 5–10 minutes on a slow connection.
4. If the download completes but extraction fails, delete the partial folder and retry:

```powershell
Remove-Item -Recurse -Force "$env:USERPROFILE\.sensitive-scanner\sonarqube"
sensitive-scanner setup --sonarqube
```

---

### SonarQube does not start or stays "not ready"

**Symptom:** `setup --sonarqube` says "SonarQube did not become UP within 3 min", or the
browser shows "site can't be reached" at http://localhost:9100.

**Checks:**

1. **Is Java installed?**

```powershell
java -version
```

If this gives an error, go back to [Step 6a](#6a--install-java).

2. **Did the port get patched?**

Open `C:\Users\YourName\.sensitive-scanner\sonarqube\conf\sonar.properties` in Notepad.
Look for a line that says `sonar.web.port=9100`.  If it's not there, the patch did not apply.
Add the line manually, then try starting SonarQube again.

3. **Is something else already on port 9100?**

```powershell
netstat -ano | findstr :9100
```

If a process is listed, either stop that process or change `sonar.web.port` in
`sonar.properties` to something else (e.g. `9200`) and update `SONAR_HOST_URL` accordingly.

4. **Check the SonarQube log files:**

```powershell
Get-Content "$env:USERPROFILE\.sensitive-scanner\sonarqube\logs\sonar.log" -Tail 30
Get-Content "$env:USERPROFILE\.sensitive-scanner\sonarqube\logs\es.log" -Tail 30
```

Common errors and fixes:

| Log message | Fix |
|---|---|
| `max virtual memory areas vm.max_map_count [65530] is too low` | Windows Subsystem for Linux (WSL) setting — not normally an issue on native Windows |
| `Native controller process has stopped` | Java version issue — ensure Java 17+ is installed and on PATH |
| `bootstrap.system_call_filter` error | Remove any `bootstrap.system_call_filter` line from `sonar.properties` — this setting was removed in newer versions |
| `Address already in use: 9100` | Something else is using port 9100 — see step 3 above |

5. **Not enough memory:** SonarQube needs at least 3 GB of free RAM.  Close other applications
   and try again.

---

### SonarQube starts but the scan does not use it

**Symptom:** `sensitive-scanner status` shows "Active tier: 1" even though SonarQube is running.

**Checks:**

1. Is `SONAR_TOKEN` set?

```powershell
echo $env:SONAR_TOKEN
```

If this is blank, set it (see [Generating a token manually](#generating-a-sonarqube-token-manually)).
After setting it, open a **new** PowerShell window (environment variables are read at startup).

2. Is `SONAR_HOST_URL` correct?

```powershell
echo $env:SONAR_HOST_URL
```

It should be `http://localhost:9100`.  If it is missing or wrong:

```powershell
[Environment]::SetEnvironmentVariable("SONAR_HOST_URL", "http://localhost:9100", "User")
```

Then open a new PowerShell window.

---

### VS Code does not see the MCP server / agent tools are missing

**Symptom:** The Copilot Chat agent does not respond to scan requests, or you see no scanner
tools listed in Agent mode.

**Checks:**

1. Did you restart VS Code after editing `settings.json`?  VS Code reads MCP configuration
   at startup — a full restart (not just reloading the window) is required.

2. Is the Python path in `settings.json` correct?  It must be the **full absolute path**,
   not just `python`.  Find yours with:

```powershell
python -c "import sys; print(sys.executable)"
```

3. Is the `args` path in `settings.json` pointing to the correct `server.py`?  Use the
   full absolute path to `C:\Github\lap-pii-screener\server.py` (or wherever you cloned the
   repo).

4. Check the VS Code Output panel: press `Ctrl+Shift+U`, then in the dropdown at the top
   right of the output pane, select **MCP**.  Any connection errors will appear there.

5. If you see a Python import error in the MCP output, the packages are probably not
   installed in the Python environment VS Code is using.  Run:

```powershell
"C:\path\to\your\python.exe" -m pip install -r C:\Github\lap-pii-screener\requirements.txt
```

Using the exact Python path from step 2 above.

---

### Gitleaks exits unexpectedly with no results

**Symptom:** Gitleaks runs but returns no findings and exits with a non-zero code, or you
see a "panic" message.

**Fix:** This usually means `config/gitleaks.toml` contains a regex the Gitleaks engine
cannot handle (it uses the RE2 engine which does not support lookahead/lookbehind assertions
like `(?!...)` or `(?=...)`).  Edit `config/gitleaks.toml` and remove any such patterns.

---

### A finding says "noscan" but is still appearing

**Symptom:** You added `# noscan` to a line but the finding still shows up.

**Fix:** The comment must be on the **same line** as the value, not on the line above or
below.  Example:

```python
# This does NOT suppress the next line:
# noscan
password = "abc123"

# This DOES suppress it:
password = "abc123"  # noscan
```

---

### "No cached report found" when running `report`

**Symptom:** Running `sensitive-scanner report` gives "No cached report found."

**Fix:** The `report` command re-exports the results from the last `scan` run.  You must run
`sensitive-scanner scan ...` at least once first.  The cache is stored per-session, so if you
opened a new terminal it will be empty.

---

## Configuration file reference

You can place a `sensitive-scanner.yaml` file in the folder you are scanning to set default
options for that project.  CLI flags always override the config file.

```yaml
# sensitive-scanner.yaml
# All settings are optional — comment out or remove what you don't need.

# Which scanners to run (default: all available)
# scanners: [gitleaks, semgrep, pii, sonarqube]

# Default output format (default: console)
# format: console

# Default output file (default: print to terminal)
# output: report.html

# Project name used in report headers and SonarQube project key
# project_name: My Project

# Scan git history as well as working files (default: false)
# include_git_history: false

# Fail with exit code 2 if any finding at or above this severity is found
# fail_on: high

# Rule IDs to suppress globally for this project
# suppress:
#   - pii_email
#   - CWE-798

# Per-scanner suppression
# suppress_by_scanner:
#   sonarqube:
#     - secrets:S6706
#   pii:
#     - pii_phone_us

# Folders and files to exclude
# exclude:
#   directories:
#     - test-fixtures
#     - generated
#   patterns:
#     - "**/*.min.js"
#     - "src/vendor/**"
#   files:
#     - src/config/test_data.py
```

You can also create a `.scannerignore` file in the scanned folder — it works like `.gitignore`
and accepts folder names and glob patterns, one per line.

Add the following block (merge into the top-level JSON object):

```json
"mcp": {
  "servers": {
    "pii-screener": {
      "command": "C:\\Users\\<you>\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe",
      "args": ["C:\\Github\\lap-pii-screener\\server.py"],
      "env": {
        "SONAR_HOST_URL": "http://localhost:9100",
        "SONAR_TOKEN": ""
      }
    }
  }
}
```

Replace `<you>` with your Windows username.

> Use the **full Python path** rather than just `python` — VS Code's process may not inherit
> your user PATH update until it is restarted.

Save the file. VS Code will automatically connect to the MCP server.
