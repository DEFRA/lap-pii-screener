# Reports

PII Screener can produce output in four formats. Each suits a different audience and purpose. This page explains what each format contains, when to use it, and the options available.

**Page contents**
- [Console](#console)
- [HTML](#html)
- [Markdown](#markdown)
- [JSON](#json)
- [The `report` command](#the-report-command)
- [Choosing a format](#choosing-a-format)

---

## Console

**Flag:** `--format console` (default)  
**Extension:** printed to stdout

The default format. Results print directly to the terminal with colour-coded severity levels and a summary line at the end.

```powershell
sensitive-scanner scan C:\Github\MyProject
```

Example output:

```
┌─────────────────────────────────────────────────────────────────┐
│  CRITICAL  │  aws_access_key  │  src/config.py:14  │  AKIA****  │
│  HIGH      │  pii_email       │  tests/seed.py:47  │  alice**** │
│  MEDIUM    │  hardcoded_pass  │  src/db.py:8       │  passw**** │
└─────────────────────────────────────────────────────────────────┘
Scan complete — Total: 3  Critical: 1  High: 1  Medium: 1  Low: 0
```

**Best for:**
- Interactive use during development
- Quick checks before committing or sharing code
- Piping to other tools

**Drawbacks:**
- Not archivable — colour codes are stripped if redirected to a file
- No remediation text shown inline
- No hyperlinks to files

---

## HTML

**Flag:** `--format html --output report.html`  
**Extension:** `.html`

A fully self-contained HTML file with embedded CSS and JavaScript. No internet connection is required to open it. It can be emailed, attached to a ticket, or dropped into SharePoint as a single file.

```powershell
sensitive-scanner scan C:\Github\MyProject --format html --output report.html
```

### What the HTML report contains

- A header with the project name, scan date, and active scanners
- A summary card row showing counts by severity (Critical / High / Medium / Low) and by scanner
- A full findings table with: Severity, Category, File, Line, Match (redacted by default), Rule ID, Scanners, Fix steps, Regulations
- Colour-coded severity badges (red, orange, yellow, blue)
- Expandable fix steps per finding
- If an obfuscation session was attached, an **Obfuscation** column showing the decision for each finding

### Confidence column

To add a confidence percentage column:

```powershell
sensitive-scanner scan C:\Github\MyProject --format html --output report.html --show-confidence
```

The column is colour-coded:
- Green badge (≥85%): strong detection
- Amber badge (65–84%): moderate detection
- Red badge (<65%): weak signal

A summary card counting findings below 65% is also added.

### Showing full matched values

```powershell
sensitive-scanner scan C:\Github\MyProject --format html --output report.html --show-secrets
```

> **Warning:** This includes actual sensitive values in the report file. Do not share or commit reports generated with `--show-secrets`.

### Attaching an obfuscation session

Add an **Obfuscation** column showing the review decision for each finding:

```powershell
sensitive-scanner scan C:\Github\MyProject --format html --output report.html \
  --session C:\Github\MyProject\pii-review-session.json
```

The column values are: `approved`, `skipped`, `manual`, or `pending`.

**Best for:**
- Management and compliance reporting
- Sharing findings with stakeholders who are not on the terminal
- Archiving scan results
- Attaching to Jira/Azure DevOps tickets

**Drawbacks:**
- Not easily diffed or version-controlled
- Cannot be post-processed by scripts without parsing HTML

---

## Markdown

**Flag:** `--format markdown --output report.md`  
**Extension:** `.md`

A plain Markdown file using GitHub-flavoured Markdown (GFM) tables. Renders correctly in VS Code, GitHub, GitLab, Confluence (with Markdown support), and any Markdown preview tool.

```powershell
sensitive-scanner scan C:\Github\MyProject --format markdown --output report.md
```

### What the Markdown report contains

- Project and scan metadata header
- Summary table by severity
- Full findings table with the same columns as the HTML report
- Fix steps listed as numbered lists under each finding

**Best for:**
- Committing to a repository alongside the code (for team visibility)
- Rendering in Confluence or GitHub wikis
- Review in VS Code (`Ctrl+Shift+V` to preview)
- Copy-pasting into tickets and documentation

**Drawbacks:**
- No interactivity (no expandable sections)
- Tables become hard to read in raw form for large result sets
- No colour coding

---

## JSON

**Flag:** `--format json --output report.json`  
**Extension:** `.json`

A structured JSON file suitable for automated processing, storage in artefact repositories, or feeding into dashboards.

```powershell
sensitive-scanner scan C:\Github\MyProject --format json --output report.json
```

### JSON structure

```json
{
  "scan_id": "abc123",
  "scan_date": "2026-06-09T14:30:22",
  "project_name": "MyProject",
  "scan_root": "C:/Github/MyProject",
  "summary": {
    "total": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "files_scanned": 47,
    "lines_scanned": 3821
  },
  "findings": [
    {
      "id": "abc123",
      "scanners": ["gitleaks", "semgrep"],
      "category": "aws_access_key",
      "severity": "critical",
      "confidence": 0.90,
      "file": "src/config.py",
      "line": 14,
      "match": "AKIA****",
      "rule_id": "aws-access-key",
      "message": "AWS Access Key found",
      "remediation_description": "Remove the key from source code...",
      "fix_steps": ["Revoke the key in the AWS console", "..."],
      "references": ["CWE-798", "OWASP:A07:2021"],
      "regulations": ["GDPR Article 5", "PCI DSS Requirement 3"]
    }
  ]
}
```

**Best for:**
- CI pipelines that process findings programmatically
- Storing results in a database or artefact store
- Building dashboards or trend reports over time
- Filtering, sorting, and aggregating with `jq` or scripts
- Comparing results between scans

**Drawbacks:**
- Not human-readable without processing
- Requires tooling to view usefully

### Useful jq queries

```bash
# Count by severity
jq '.summary | {critical, high, medium, low}' report.json

# List critical findings
jq '[.findings[] | select(.severity == "critical") | {file, line, category}]' report.json

# List findings from a specific scanner
jq '[.findings[] | select(.scanners | contains(["sonarqube"]))]' report.json

# Files with the most findings
jq '[.findings[].file] | group_by(.) | map({file: .[0], count: length}) | sort_by(-.count)' report.json
```

---

## The `report` command

To export the results from the **most recent scan** without running the scan again:

```powershell
sensitive-scanner report --format html --output report.html
sensitive-scanner report --format markdown --output report.md
sensitive-scanner report --format json --output report.json
```

The last scan's results are cached between runs. `report` reads that cache. This is useful when you want the same scan data in multiple formats without waiting for another scan.

```powershell
# Get the confidence report without re-scanning
sensitive-scanner report --format html --output report-with-confidence.html --show-confidence
```

---

## Choosing a format

| I want to... | Use |
|---|---|
| See results immediately while working | Console (default) |
| Share results with my team or manager | HTML |
| Attach to a Jira / ADO ticket | HTML |
| Commit findings to the repository | Markdown |
| Process findings in a CI pipeline | JSON |
| Review in VS Code or Confluence | Markdown |
| Build a dashboard or trend report | JSON |
| Archive scan history | JSON or HTML |
| Show obfuscation decisions | HTML with `--session` |
