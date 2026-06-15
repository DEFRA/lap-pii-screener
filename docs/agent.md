# Sensitive Code Scanner — Copilot Agent

The file `.github/agents/sensitive-code-scanner.agent.md` defines a custom GitHub Copilot agent that can be used in **any** VS Code workspace to run a PII and secrets scan against a codebase.

---

## Prerequisites

### 1. Clone this repository

Clone to any location you prefer — the agent discovers the CLI automatically:

```
git clone https://github.com/<your-org>/PII-Screener
```

The agent finds the CLI by checking in this order:

1. `sensitive-scanner` on your system PATH (available automatically after `pip install -e .`)
2. Any `cli.py` under `%USERPROFILE%` whose path contains `PII-Screener` or `sensitive-scanner`
3. A `cli.py` in the current workspace root (if you opened the PII-Screener repo itself)
4. Prompting you to provide the path if none of the above succeed

### 2. Python 3.11+

```
python --version   # must be 3.11 or higher
```

### 3. Install Python dependencies

```
cd C:\Github\PII-Screener
pip install -r requirements.txt
```

### 4. Optional — spaCy NLP model (names, addresses)

Without spaCy, the scanner still detects structured PII (SSNs, credit cards, emails, etc.) via regex. spaCy adds unstructured entity detection (person names, locations).

```
pip install spacy
python -m spacy download en_core_web_sm
```

### 5. Optional — Gitleaks binary (secrets scanner)

If Gitleaks is not already on your PATH, the scanner auto-downloads a pinned binary to `~\.sensitive-scanner\bin\` on first run. No manual install needed unless you are in an air-gapped environment.

### 6. Optional — Semgrep

```
pip install semgrep
```

### 7. Optional — SonarQube

Requires Java 17+ and the `sonar-scanner` CLI, or Docker Desktop. See [scanners.md](scanners.md) for full details.

---

## Making the agent available in another workspace

Copy (or symlink) the agent file into the target project:

```
# Option A — copy
copy C:\Github\PII-Screener\.github\agents\sensitive-code-scanner.agent.md <target-project>\.github\agents\sensitive-code-scanner.agent.md

# Option B — user-profile (available in ALL workspaces automatically)
copy C:\Github\PII-Screener\.github\agents\sensitive-code-scanner.agent.md "%APPDATA%\Code\User\prompts\agents\sensitive-code-scanner.agent.md"
```

After copying, reload VS Code. The **Sensitive Code Scanner** agent will appear in the Copilot Chat agent picker.

---

## How to invoke

Open Copilot Chat in any workspace and either:

- Select **Sensitive Code Scanner** from the `@` agent picker, or
- Type a natural-language request — the agent's description matches phrases such as:
  - *scan for PII*
  - *check for secrets*
  - *run pii scan*
  - *sensitive data scan*
  - *security scan codebase*

### Examples

```
@Sensitive Code Scanner scan the current project
@Sensitive Code Scanner scan ./src --format markdown --output pii-report.md
@Sensitive Code Scanner scan C:\Projects\MyApp --scanners presidio,gitleaks
```

---

## What the agent does

1. **Locates the CLI** — checks for `sensitive-scanner` on PATH, searches `%USERPROFILE%` for a matching `cli.py`, checks the current workspace, then asks you if nothing is found.
2. **Determines the target path** — uses the path you supply, or defaults to the current workspace root.
3. **Runs the scan** — calls the CLI with the appropriate flags.
4. **Presents findings** — total count, severity breakdown (critical / high / medium / low), and per-finding details (file, line, category). Secret values longer than 8 characters are redacted.
5. **Suggests remediation** — for each critical or high finding, states the recommended action (e.g. rotate secret, move to environment variable, remove from git history).

---

## Scan options

| Flag | Values | Default | Purpose |
|------|--------|---------|---------|
| `--scanners` | `presidio`, `gitleaks`, `semgrep`, `sonarqube` | `presidio,gitleaks` | Scanners to run |
| `--format` | `console`, `markdown`, `html`, `json` | `console` | Output format |
| `--output` | file path | *(print to chat)* | Save report to file |

---

## What is scanned

The built-in PII scanner covers:

| Category | Examples |
|----------|---------|
| Email addresses | `user@example.com` |
| Phone numbers | US (+1) and international E.164 |
| US Social Security Numbers | `123-45-6789` |
| Credit card numbers | Visa, Mastercard, Amex, Discover (Luhn-validated) |
| IBAN / bank account numbers | `GB29NWBK60161331926819` |
| UK National Insurance numbers | `AB123456C` |
| Passport numbers | Generic 7–9 character alphanumeric |
| Dates of birth | `YYYY-MM-DD`, `DD/MM/YYYY`, `MM/DD/YYYY` |
| PEM private keys | `-----BEGIN RSA PRIVATE KEY-----` |
| Database connection strings | Embedded credentials in URIs |
| Hardcoded passwords | `password = "..."` style assignments |
| JWT tokens | `eyJ...` header.payload.signature |
| IPv4 addresses | Inside string literals |
| Named entities (spaCy) | Person names, locations *(requires spaCy)* |

Gitleaks extends coverage with hundreds of additional patterns for cloud provider keys, tokens, and service credentials.
