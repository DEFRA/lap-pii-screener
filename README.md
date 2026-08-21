# PII Screener

A multi-scanner static analysis tool that finds secrets, API keys, and personally identifiable information (PII) in source code repositories. It combines four independent scanning engines into a single CLI, merges and deduplicates their results, maps every finding to a remediation guide and applicable regulation, and can optionally redact sensitive values directly in your source files.

---

## What problem does this solve?

Organisations routinely store sensitive data in the wrong places — configuration files, test fixtures, comments, migration scripts, seed data. This creates two categories of risk:

- **Secrets exposure** — API keys, passwords, and tokens that grant access to systems. If committed to source control they are permanently in Git history even after deletion.
- **PII in code** — Real email addresses, phone numbers, names, and financial data committed as test data or hardcoded values. This creates GDPR Article 5 compliance obligations and potential Article 83 penalties.

This tool scans a codebase in minutes and gives you a prioritised, actionable list of both problem types, along with step-by-step fixes for each finding.

---

## What it finds

| Category                 | Examples                                                                                                                                    |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| API keys & tokens        | AWS, Azure, GitHub, Stripe, Slack, JWT tokens                                                                                               |
| Passwords & credentials  | Hardcoded passwords, database connection strings, private keys                                                                              |
| Structured PII           | Email addresses, phone numbers, credit card numbers, NI numbers, NHS numbers, passports, dates of birth, SSNs, IBANs, sort codes, postcodes |
| Unstructured PII         | Person names and addresses in comments or string literals (requires spaCy)                                                                  |
| Security vulnerabilities | SQL injection, XSS, broken auth, OWASP Top 10 (via Semgrep + SonarQube)                                                                     |

---

## How it works

Four scanning engines run in parallel against the target directory. Their results are merged, triplicate findings from multiple scanners are deduplicated, and every finding is enriched with:

- A confidence score based on how specific the detection was
- The applicable regulation (UK GDPR, PCI DSS, PSR 2017)
- Step-by-step remediation instructions
- Cross-references to CWE and OWASP identifiers

| Scanner         | What it contributes                                                                              |
| --------------- | ------------------------------------------------------------------------------------------------ |
| **Gitleaks**    | Secret pattern matching — fast, purpose-built, 150+ service-specific rules                       |
| **Semgrep**     | Code-structure-aware analysis — catches patterns that span multiple tokens                       |
| **PII scanner** | Custom PII detection — structured regex plus optional Presidio or spaCy named-entity recognition |
| **SonarQube**   | Enterprise deep analysis — data-flow tracking, taint propagation, inter-procedural reasoning     |

The CLI requests all four scanners by default and skips backends that are not available. Gitleaks, Semgrep, and the built-in PII scanner form the baseline; SonarQube is an optional deeper-analysis backend that needs Java and a local SonarQube instance (or a container runtime).

---

## Prerequisites

| Requirement     | Version | Notes                                      |
| --------------- | ------- | ------------------------------------------ |
| Python          | 3.11+   | Must be on PATH                            |
| uv              | Latest  | Package manager — `pip install uv`         |
| Java            | 17+     | Only needed for SonarQube                  |
| Git             | Any     | Only needed if scanning commit history     |
| Docker Desktop  | Any     | Alternative to native Java SonarQube       |
| Internet access | —       | Required on first run to download binaries |

> Alternatively, you can run the tool within a docker container using the [steps below](#run-with-docker)

The setup wizard (`sensitive-scanner setup`) handles all binary downloads automatically.

---

## Quick start

```powershell
git clone https://github.com/DEFRA/lap-pii-screener C:\Github\lap-pii-screener
cd C:\Github\lap-pii-screener
pip install uv
uv sync
sensitive-scanner setup
sensitive-scanner scan C:\path\to\your-project
```

The default `setup` command installs the Gitleaks binary and Semgrep. Add `--spacy` for
name and location detection, or `--sonarqube` for SonarQube analysis. Document ingestion
extras such as Excel, PDF, and Word support are installed separately with
`uv sync --extra docs`.

For a detailed walkthrough including SonarQube setup and air-gapped environments, see the [Setup Guide](docs/setup/setup.md).

### Run with Docker

To run the scanner without installing Python or Java locally, start the container with the source directory you want to scan:

```powershell
./scripts/init-docker.ps1 -SourceDir C:\path\to\your-project
./scripts/init-full
./scripts/screener scan /source
```

Use `scripts\init-docker.cmd` from Windows Command Prompt or `./scripts/init-docker` from Bash/WSL. See the [Docker Setup guide](docs/setup/docker.md) for all supported shells and options.

---

## Documentation

**Setup**

| Document                                | What it covers                                                           |
| --------------------------------------- | ------------------------------------------------------------------------ |
| [Quick Start](docs/setup/QUICKSTART.md) | Zero to scanning in 6 steps                                              |
| [Setup Guide](docs/setup/setup.md)      | Full installation, SonarQube configuration, air-gapped environments      |
| [Docker Setup](docs/setup/docker.md)    | Run the scanner in a container without local Python or Java installation |

**Guides**

| Document                                   | What it covers                                                  |
| ------------------------------------------ | --------------------------------------------------------------- |
| [Scanning](docs/guides/scanning.md)        | All scan options, exclusions, suppressions, CI integration      |
| [Obfuscation](docs/guides/obfuscation.md)  | Interactive PII review, dry-run, apply, rollback, session files |
| [Faker replacements](FAKER_INTEGRATION.md) | Optional realistic replacements during obfuscation              |
| [Reports](docs/guides/reports.md)          | Report formats, what each contains, when to use each            |
| [Agent (MCP)](docs/guides/agent.md)        | Using the scanner from VS Code Copilot Chat                     |

**CLI commands**

| Command     | Purpose                                               |
| ----------- | ----------------------------------------------------- |
| `scan`      | Scan a directory and optionally write a report        |
| `status`    | Show available backends and the active tier           |
| `setup`     | Install scanner dependencies and optional backends    |
| `report`    | Export the most recent cached scan without rescanning |
| `obfuscate` | Review and optionally replace sensitive values        |
| `rollback`  | Restore files from an obfuscation backup              |
| `edit`      | Change an item in an obfuscation session              |

**Reference**

| Document                                                                       | What it covers                                           |
| ------------------------------------------------------------------------------ | -------------------------------------------------------- |
| [Scanners](docs/reference/scanners.md)                                         | How each scanner works, regex rules, why each was chosen |
| [Ingestion support matrix](docs/reference/ingestion-requirements-support.html) | Supported file formats for PII ingestion                 |

**Design**

| Document                                              | What it covers                                      |
| ----------------------------------------------------- | --------------------------------------------------- |
| [High-Level Design](docs/design/HIGH-LEVEL-DESIGN.md) | Architecture, data flow, component responsibilities |
| [Low-Level Design](docs/design/LOW-LEVEL-DESIGN.md)   | Class models, sequences, and lifecycle diagrams     |

---

## Licence

Internal use.
